use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305,
    aead::{Aead, OsRng as ChaChaOsRng},
};
use prost::Message;

use anyhow::{Result, anyhow};

use crate::{
    chat_message::PlaintextPayload,
    identity::{MyIdentity, PeerIdentity},
};

pub fn encrypt_message(content: &str, identity: &MyIdentity) -> Result<(Vec<u8>, Vec<u8>)> {
    let payload = PlaintextPayload {
        sender_id: identity.my_sender_id.to_string(),
        content: content.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    };

    let payload_bytes = payload.encode_to_vec();
    let (cipher, _) = identity
        .get_sender_key()
        .ok_or_else(|| anyhow!("No current sender key"))?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng); // 96-bits; unique per message
    let encrypted_payload = cipher
        .encrypt(&nonce, payload_bytes.as_ref())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok((encrypted_payload, nonce.to_vec()))
}

pub fn decrypt_message(
    sender_id: &str,
    key_id: u32,
    encrypted_payload: &[u8],
    nonce_bytes: &[u8],
    peer_identity: &PeerIdentity,
) -> Result<String> {
    let sender_keys = peer_identity
        .peer_sender_keys
        .get(sender_id)
        .ok_or_else(|| anyhow!("Unknown sender: {}", sender_id))?;

    let cipher = sender_keys
        .get(&key_id)
        .ok_or_else(|| anyhow!("Unknown key ID {} for sender {}", key_id, sender_id))?;

    if nonce_bytes.len() != 12 {
        return Err(anyhow!("Invalid nonce length"));
    }

    let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
    let decrypted_bytes = cipher.decrypt(nonce, encrypted_payload)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    let payload = PlaintextPayload::decode(decrypted_bytes.as_slice())?;
    Ok(payload.content)
}
