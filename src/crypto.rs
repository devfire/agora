use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305,
    aead::{Aead, OsRng as ChaChaOsRng},
};
use prost::Message;

use anyhow::{Result, anyhow};
use tracing_subscriber::field::debug;

use crate::{
    chat_message::{ChatPacket, PlaintextPayload, PublicKeyAnnouncement, chat_packet::PacketType},
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
) -> Result<PlaintextPayload> {
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
    let decrypted_bytes = cipher
        .decrypt(nonce, encrypted_payload)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    let payload = PlaintextPayload::decode(decrypted_bytes.as_slice())?;
    Ok(payload)
}

// Announce our public key to the group
pub async fn create_public_key_announcement(my_identity: &MyIdentity) -> ChatPacket {
    let announcement = PublicKeyAnnouncement {
        user_id: my_identity.my_sender_id.to_string(),
        x25519_public_key: my_identity.x25519_public_key.as_bytes().to_vec(),
        ed25519_public_key: my_identity.verifying_key.as_bytes().to_vec(),
    };

    tracing::debug!("Creating public key announcement: {:?}", announcement);
    ChatPacket {
        packet_type: Some(PacketType::PublicKey(announcement)),
    }
}

pub fn create_encrypted_chat_packet(content: &str, my_identity: &MyIdentity) -> Result<ChatPacket> {
    let (encrypted_payload, nonce) = encrypt_message(content, my_identity)?;

    let encrypted_msg = crate::chat_message::EncryptedMessage {
        sender_id: my_identity.my_sender_id.to_string(),
        key_id: my_identity.current_key_id,
        encrypted_payload,
        nonce,
    };

    Ok(ChatPacket {
        packet_type: Some(PacketType::EncryptedMsg(encrypted_msg)),
    })
}