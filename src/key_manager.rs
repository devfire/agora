use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ssh_key::PrivateKey;
use x25519_dalek::{PublicKey as X25519PublicKey};

struct P2PIdentity {
    // Identity/Authentication (from SSH key)
    signing_key: SigningKey,
    verifying_key: VerifyingKey,

    // Encryption (separate, generated key)
    x25519_private: [u8; 32],
    x25519_public: X25519PublicKey,
}

impl P2PIdentity {
    fn load_ssh_ed25519_key(path: &Path) -> Result<(SigningKey, VerifyingKey)> {
        // Read the SSH private key file
        let key_data = std::fs::read_to_string(path)?;

        // Parse it
        let ssh_private_key = PrivateKey::from_openssh(&key_data)?;

        // Extract the raw Ed25519 key bytes
        let key_bytes = ssh_private_key
            .key_data()
            .ed25519()
            .context("SSH key is not Ed25519")?;

        let signing_key = SigningKey::from_bytes(&key_bytes.private.to_bytes());
        let verifying_key = signing_key.verifying_key();

        Ok((signing_key, verifying_key))
    }
    pub fn new(ssh_key_path: &Path) -> Result<Self> {
        // Load SSH Ed25519 key
        let (signing_key, verifying_key) =
            Self::load_ssh_ed25519_key(ssh_key_path).context("Failed to load SSH Ed25519 key")?;

        // Generate X25519 key pair for encryption
        let x25519_private: [u8; 32] = rand::random();
        let x25519_public = X25519PublicKey::from(x25519_private);

        Ok(P2PIdentity {
            signing_key,
            verifying_key,
            x25519_private,
            x25519_public,
        })
    }
}
