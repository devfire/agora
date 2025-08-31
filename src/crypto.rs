use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, Key, KeyInit,
    aead::{Aead, OsRng as ChaChaOsRng},
};
use prost::Message;

use anyhow::{Result, anyhow, bail};
use tracing::debug;

/// We can get either a ChatPacket or a decrypted PlaintextPayload
/// This enum helps distinguish between the two types of received messages
/// ChatPacket is for control messages (e.g., PublicKeyAnnouncement)
/// PlaintextPayload is for regular chat messages which are outside the ChatPacket wrapper
/// This allows the network.receive_message() to handle them appropriately
///
/// This is needed because network.rs doesn't own peer_identity to update it directly but processor.rs does.
/// So network.rs can pass the raw ChatPacket up to processor.rs which can then handle it properly.
/// Otherwise if network.rs only ever returns ChatPacket, it cannot return decrypted PlaintextPayload messages. And others.
pub enum ReceivedMessage {
    ChatPacket(ChatPacket),
    PlaintextPayload(PlaintextPayload),
    PeerSenderKey(PeerSenderKey),
}

pub struct PeerSenderKey {
    pub sender_key: String,
    pub key_id: u32,
    pub sender_cipher: ChaCha20Poly1305,
}
use crate::{
    chat_message::{
        self, ChatPacket, PlaintextPayload, PublicKeyAnnouncement, chat_packet::PacketType,
    },
    identity::{MyIdentity, PeerIdentity},
};

pub fn encrypt_message(content: &str, identity: &MyIdentity) -> Result<(Vec<u8>, Vec<u8>)> {
    tracing::debug!("Encrypting message content: {}", content);
    // Create plaintext payload
    let payload = PlaintextPayload {
        sender_id: identity.my_sender_id.to_string(),
        content: content.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    };

    tracing::debug!("Plaintext payload: {:?}", payload);
    let payload_bytes = payload.encode_to_vec();
    tracing::debug!(
        "Encoded payload to {} bytes: {:?}",
        payload_bytes.len(),
        payload_bytes
    );

    // Remember, SenderKey is a type alias for (ChaCha20Poly1305, [u8; 32]), i.e. a tuple
    let sender_key_tuple = identity
        .get_sender_key()
        .ok_or_else(|| anyhow!("No current sender key"))?;

    // Get the ChaCha20Poly1305 cipher from the tuple
    let (cypher, _) = sender_key_tuple;

    tracing::debug!("Using sender key ID {}", identity.current_key_id);

    let nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng); // 96-bits; unique per message

    tracing::debug!("Generated nonce: {:?}", nonce);

    // Encrypt the payload
    let encrypted_payload = cypher
        .encrypt(&nonce, payload_bytes.as_ref())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    tracing::debug!(
        "Encrypted payload {:?} ({} bytes)",
        encrypted_payload,
        encrypted_payload.len()
    );
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
        bail!("Invalid nonce length");
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

    tracing::info!("Creating public key announcement: {:?}", announcement);
    ChatPacket {
        packet_type: Some(PacketType::PublicKey(announcement)),
    }
}

pub fn create_encrypted_chat_packet(content: &str, my_identity: &MyIdentity) -> Result<ChatPacket> {
    tracing::debug!("Creating encrypted chat packet with content: {}", content);
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

// Create encrypted sender key for a specific recipient
pub fn create_key_distribution(
    my_identity: &MyIdentity,
    peer_identity: &PeerIdentity,
    recipient_id: &str,
) -> Result<ChatPacket> {
    let recipient_x25519_public = peer_identity
        .peer_x25519_keys
        .get(recipient_id)
        .ok_or_else(|| anyhow!("Unknown recipient: {}", recipient_id))?;

    // Perform ECDH to get shared secret
    let shared_secret = my_identity
        .x25519_secret_key
        .diffie_hellman(recipient_x25519_public);

    // Use shared secret as encryption key
    let key = Key::from_slice(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);

    let (_, sender_key_bytes) = my_identity
        .get_sender_key()
        .ok_or_else(|| anyhow!("No current sender key"))?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng);
    let encrypted_key = cipher
        .encrypt(&nonce, sender_key_bytes.as_ref())
        .map_err(|e| anyhow!("Creating key distribution failed: {}", e))?;

    let key_dist = chat_message::KeyDistribution {
        sender_id: my_identity.my_sender_id.to_string(),
        key_id: my_identity.current_key_id,
        encrypted_sender_key: encrypted_key,
        recipient_id: recipient_id.to_string(),
    };
    Ok(ChatPacket {
        packet_type: Some(PacketType::KeyDist(key_dist)),
    })

    // Prepend nonce to encrypted key
    // let mut result = nonce.to_vec();
    // result.extend_from_slice(&encrypted_key);
    // Ok(result)
}

// /// Create a key distribution packet to share a new sender key with a peer
// pub async fn distribute_sender_key(
//     my_identity: &MyIdentity,
//     peer_identity: &PeerIdentity,
// ) -> Result<()> {
//     for peer_id in peer_identity.list_known_peers() {
//         match create_key_distribution(peer_id) {
//             Ok(encrypted_key) => {
//                 let key_dist = KeyDistribution {
//                     sender_id: self.crypto.our_user_id().to_string(),
//                     key_id: self.crypto.current_key_id(),
//                     encrypted_sender_key: encrypted_key,
//                     recipient_id: peer_id.clone(),
//                 };

//                 let packet = ChatPacket {
//                     packet_type: Some(chat_packet::PacketType::KeyDist(key_dist)),
//                 };

//                 let packet_bytes = packet.encode_to_vec();
//                 self.socket
//                     .send_to(&packet_bytes, self.multicast_addr)
//                     .await?;
//             }
//             Err(e) => {
//                 eprintln!("Failed to create key distribution for {}: {}", peer_id, e);
//             }
//         }
//     }

//     if !self.crypto.list_known_peers().is_empty() {
//         println!(
//             "Distributed sender key to {} peers",
//             self.crypto.list_known_peers().len()
//         );
//     }
//     Ok(())
// }
