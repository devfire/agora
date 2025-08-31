use std::{collections::HashMap, fs, hash::Hash, path::Path};

use anyhow::{Context, Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ssh_key::PrivateKey;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::SenderKey;
#[derive(Clone)]
pub struct PeerIdentity {
    pub peer_x25519_keys: HashMap<String, X25519PublicKey>,
    pub peer_verifying_keys: HashMap<String, VerifyingKey>,
    pub peer_sender_keys: HashMap<String, HashMap<u32, ChaCha20Poly1305>>,
}

impl PeerIdentity {
    pub fn new() -> Self {
        Self {
            peer_x25519_keys: HashMap::new(),
            peer_verifying_keys: HashMap::new(),
            peer_sender_keys: HashMap::new(),
        }
    }

    pub fn add_peer_keys(
        &mut self,
        peer_id: String,
        x25519_public_bytes: &[u8],
        ed25519_public_bytes: &[u8],
    ) -> Result<()> {
        if x25519_public_bytes.len() != 32 {
            return Err(anyhow!("Invalid X25519 public key length"));
        }
        if ed25519_public_bytes.len() != 32 {
            return Err(anyhow!("Invalid Ed25519 public key length"));
        }

        let mut x25519_array = [0u8; 32];
        x25519_array.copy_from_slice(x25519_public_bytes);
        let x25519_public = X25519PublicKey::from(x25519_array);

        let mut ed25519_array = [0u8; 32];
        ed25519_array.copy_from_slice(ed25519_public_bytes);
        let verifying_key = VerifyingKey::from_bytes(&ed25519_array)?;

        self.peer_x25519_keys.insert(peer_id.clone(), x25519_public);
        self.peer_verifying_keys.insert(peer_id, verifying_key);
        Ok(())
    }

    pub fn get_peer_x25519_key(&self, peer_id: &str) -> Option<&X25519PublicKey> {
        self.peer_x25519_keys.get(peer_id)
    }

    pub fn list_known_peers(&self) -> Vec<&String> {
        self.peer_x25519_keys.keys().collect()
    }
}

/// SecureIdentity manages our cryptographic identity using an Ed25519 SSH key for signing
/// and a derived X25519 key for encryption.
/// It handles loading the SSH key, decrypting if necessary, and converting to X25519
#[derive(Clone)]
pub struct MyIdentity {
    // Our Ed25519 identity (for signatures/verification from the SSH key)
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,

    // Encryption (separate, generated key)
    pub x25519_secret_key: StaticSecret,
    pub x25519_public_key: X25519PublicKey,
    pub my_sender_id: String,

    // Symmetric sender keys (what actually encrypts messages)
    // SenderKey is a type alias for (ChaCha20Poly1305, [u8; 32]);
    // There's one of these per *session*, not per peer!
    my_sender_keys: HashMap<u32, SenderKey>, // cipher + raw key bytes
    pub current_key_id: u32,
}

impl MyIdentity {
    /// Load an Ed25519 SSH private key from the specified path
    fn load_ssh_ed25519_key(path: &Path) -> Result<(SigningKey, VerifyingKey)> {
        // Read the SSH private key file
        let key_data = fs::read_to_string(path)?;

        // Parse it
        let ssh_private_key = PrivateKey::from_openssh(&key_data)?;

        // Ensure the key is not encrypted
        let ssh_private_key_decrypted = if ssh_private_key.is_encrypted() {
            eprint!("SSH key is encrypted; please provide the password:");
            let passphrase =
                rpassword::read_password().context("Failed to read passphrase from terminal")?;

            // This line creates a secure wrapper around sensitive data (a passphrase)
            // that automatically wipes the memory when it goes out of scope.
            // The code is decrypting an encrypted SSH private key,
            // so the passphrase contains sensitive cryptographic material that must not be left in memory after use.
            //
            // What it does:
            //  1. Takes the passphrase string read from terminal input
            //  2. Wraps it in a Zeroizing<String> type from the zeroize crate
            //  3. When pass_z is dropped (goes out of scope), the memory containing the passphrase is automatically overwritten with zeros
            let pass_z = Zeroizing::new(passphrase);

            ssh_private_key
                .decrypt(&pass_z)
                .context("Failed to decrypt SSH private key (wrong passphrase?)")?
        } else {
            ssh_private_key
        };
        // Extract the raw Ed25519 key bytes
        let key_bytes = ssh_private_key_decrypted
            .key_data()
            .ed25519()
            .context("SSH key is not Ed25519")?;

        let signing_key = SigningKey::from_bytes(&key_bytes.private.to_bytes());

        // This is the same as PublicKey::from(&signing_key);
        // VerifyingKey is the public key counterpart to SigningKey.
        let verifying_key = signing_key.verifying_key();

        Ok((signing_key, verifying_key))
    }

    /// Create a new SecureIdentity from the given SSH key path
    pub fn new(ssh_key_path: &Path, user_id: &str) -> Result<Self> {
        let expanded_path = shellexpand::tilde(
            ssh_key_path
                .to_str()
                .expect("Expected to find the key file"),
        )
        .to_string();
        let path = Path::new(&expanded_path);
        // Load SSH Ed25519 key
        let (signing_key, verifying_key) =
            Self::load_ssh_ed25519_key(path).context("Failed to load SSH Ed25519 key")?;

        // Generate initial sender key (inline for constructor)
        let mut key_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut key_bytes);

        let key = chacha20poly1305::Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        
        let current_key_id = 0; // Start with key ID 0
        let my_sender_keys = (cipher, key_bytes);

        // Convert Ed25519 secret key to X25519 for ECDH
        // This is a standard conversion using the same key material
        let ed25519_secret_bytes = signing_key.to_bytes();
        let x25519_secret_key = StaticSecret::from(ed25519_secret_bytes);
        let x25519_public_key = X25519PublicKey::from(&x25519_secret_key);

        Ok(MyIdentity {
            signing_key,
            verifying_key,
            x25519_secret_key,
            x25519_public_key,
            my_sender_keys: HashMap::from([(current_key_id, my_sender_keys)]),
            current_key_id,
            my_sender_id: user_id.to_string(),
        })
    }

    /// Generate a new sender key for the current session
    /// This is NOT per peer, this is per session.
    pub fn generate_new_sender_key(&mut self) -> (u32, SenderKey) {
        let mut key_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut key_bytes);

        let key = chacha20poly1305::Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        self.current_key_id += 1;
        // self.my_sender_keys.insert(self.current_key_id, (cipher, key_bytes));
        (self.current_key_id, (cipher, key_bytes))
    }

    /// Return a SenderKey for the current session. Again, this is NOT per peer, this is per session.
    pub fn get_sender_key(&self) -> Option<&SenderKey> {
      
        tracing::debug!("Getting sender key for key ID {}", self.current_key_id);
      
        if let Some(sender_key) = self.my_sender_keys.get(&self.current_key_id) {
            tracing::debug!(
                "Found existing sender key for key ID {}",
                self.current_key_id
            );
            Some(sender_key)
        } else {
            tracing::debug!("No sender key found for key ID {}", self.current_key_id);
            None
        }
    }
}
