use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ssh_key::PrivateKey;
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroizing;

pub(crate) struct SecureIdentity {
    // Identity/Authentication (from SSH key)
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,

    // Encryption (separate, generated key)
    pub x25519_private: [u8; 32],
    pub x25519_public: X25519PublicKey,
}

impl SecureIdentity {
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

            // Use zeroizing string for security
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
        let verifying_key = signing_key.verifying_key();

        Ok((signing_key, verifying_key))
    }
    pub fn new(ssh_key_path: &Path) -> Result<Self> {
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

        // Generate X25519 key pair for encryption
        let x25519_private: [u8; 32] = rand::random();
        let x25519_public = X25519PublicKey::from(x25519_private);

        Ok(SecureIdentity {
            signing_key,
            verifying_key,
            x25519_private,
            x25519_public,
        })
    }
}
