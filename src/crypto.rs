
use prost::Message;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, Nonce};
use rand::{rngs::OsRng, RngCore};
use anyhow::{Result, anyhow};

use crate::{chat_message::PlaintextPayload, identity::MyIdentity};

pub fn encrypt_message(sender_id: &str, content: &str,identity: &MyIdentity) -> Result<(Vec<u8>, Vec<u8>)> {
    let payload = PlaintextPayload {
        sender_id: sender_id.to_string(),
        content: content.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    };

    let payload_bytes = payload.encode_to_vec();
    let (cipher, _) = 
        identity.
        .get(&self.current_key_id)
        .ok_or_else(|| anyhow!("No current sender key"))?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted_payload = cipher.encrypt(&nonce, payload_bytes.as_ref())?;

    Ok((encrypted_payload, nonce.to_vec()))
}
