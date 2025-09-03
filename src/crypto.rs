use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, Key, KeyInit,
    aead::{Aead, OsRng as ChaChaOsRng},
};
use prost::Message;

use anyhow::{Result, anyhow, bail};
use tracing::{debug, info};

use sha2::Digest;

use ed25519_dalek::Signer;

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
    // PeerSenderKey(PeerSenderKey),
}

// pub struct PeerSenderKey {
//     // pub sender_key: String,
//     pub key_id: u32,
//     pub sender_cipher: ChaCha20Poly1305,
// }
use crate::{
    chat_message::{
        self, ChatPacket, EncryptedMessage, KeyDistribution, PlaintextPayload,
        PublicKeyAnnouncement, chat_packet::PacketType,
    },
    identity::{MyIdentity, PeerIdentity},
};

pub fn encrypt_message(content: &str, identity: &MyIdentity) -> Result<(Vec<u8>, Vec<u8>)> {
    tracing::debug!("Encrypting message content: {}", content);
    // Create plaintext payload
    let payload = PlaintextPayload {
        display_name: identity.display_name.to_string(),
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
    sender_public_key_hash_hex: &str,
    key_id: u32,
    encrypted_payload: &[u8],
    nonce_bytes: &[u8],
    peer_identity: &PeerIdentity,
) -> Result<PlaintextPayload> {
    let sender_keys = peer_identity
        .peer_sender_keys
        .get(sender_public_key_hash_hex)
        .ok_or_else(|| {
            anyhow!(
                "From decrypt_message(): Unknown sender: {}",
                sender_public_key_hash_hex
            )
        })?;

    let cipher = sender_keys.get(&key_id).ok_or_else(|| {
        anyhow!(
            "Unknown key ID {} for sender {}",
            key_id,
            sender_public_key_hash_hex
        )
    })?;

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
        display_name: my_identity.display_name.to_string(),
        x25519_public_key: my_identity.x25519_public_key.as_bytes().to_vec(),
        ed25519_public_key: my_identity.verifying_key.as_bytes().to_vec(),
    };

    debug!("Creating public key announcement: {:?}", announcement);
    ChatPacket {
        packet_type: Some(PacketType::PublicKey(announcement)),
    }
}

pub fn create_encrypted_chat_packet(content: &str, my_identity: &MyIdentity) -> Result<ChatPacket> {
    tracing::debug!("Creating encrypted chat packet with content: {}", content);
    let (encrypted_payload, nonce) = encrypt_message(content, my_identity)?;

    // Create the Sha256 hash of the sender's public key
    // This is used to identify the sender in messages
    // let mut hasher = sha2::Sha256::default();
    // hasher.update(my_identity.verifying_key.as_bytes());
    // let sender_public_key_hash = hasher.finalize().to_vec();

    // Log the public key hash in hex format for easier reading
    info!(
        "Sender public key hash (SHA256) in hex: {}",
        hex::encode(my_identity.get_my_verifying_key_sha256hash_as_bytes())
    );
    // Create the EncryptedMessage without the signature first
    let mut encrypted_msg = crate::chat_message::EncryptedMessage {
        sender_public_key_hash: my_identity.get_my_verifying_key_sha256hash_as_bytes(),
        key_id: my_identity.current_key_id,
        encrypted_payload,
        nonce,
        signature: Vec::new(), // Signature will be added later during the signing process
    };

    // Sign the message
    let signature = sign_message(&encrypted_msg, my_identity)?;

    // Now replace the Vec::new placeholder with the correct signature we just created
    encrypted_msg.signature = signature;

    Ok(ChatPacket {
        packet_type: Some(PacketType::EncryptedMsg(encrypted_msg)),
    })
}

/// Creates the canonical byte representation for signing.
/// This must be deterministic and match verification.
/// Basically we mash everything together in a specific order.
/// Exclude the signature field itself.
/// A hasher masher! :)
fn create_signable_encrypted_message(msg: &EncryptedMessage) -> Vec<u8> {
    let mut hasher = sha2::Sha256::default();

    // Hash all fields in a specific order (excluding signature)
    hasher.update(&msg.key_id.to_le_bytes());
    hasher.update(&msg.encrypted_payload);
    hasher.update(&msg.nonce);

    hasher.finalize().to_vec()
}

/// Signs an EncryptedMessage and returns the signature
pub fn sign_message(msg: &EncryptedMessage, my_identity: &MyIdentity) -> Result<Vec<u8>> {
    // Create the data to sign by concatenating all fields
    let data_to_sign = create_signable_encrypted_message(msg);

    // Sign the data
    let signature = my_identity.signing_key.sign(&data_to_sign);

    Ok(signature.to_bytes().to_vec())
}

/// Generate a SHA256 hash as a hex string of the verifying (public) key.
/// This is used to identify the sender in messages.
pub fn get_public_key_hash_as_hex_string(public_key_as_bytes: &[u8]) -> String {
    // NOTE: it's not safe to directly convert the raw hash bytes (Vec<u8>) to a String.
    // This is because a Rust String is required to be valid UTF-8,
    // but the raw bytes of a SHA-256 hash are arbitrary binary data and have no guarantee of forming a valid UTF-8 sequence.
    // Attempting a direct conversion will either fail or corrupt the data.
    //
    // But hex is totes awesome for this purpose. :)
    hex::encode(&public_key_as_bytes)
}

// Create encrypted sender key for a specific recipient
pub fn create_key_distribution(
    my_identity: &MyIdentity,
    peer_identity: &PeerIdentity,
    recipient_id: &str, // recipient's public key hash in hex string format
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
        sender_public_key_hash: my_identity.verifying_key.as_bytes().to_vec(),
        key_id: my_identity.current_key_id,
        encrypted_sender_key: encrypted_key,
        recipient_public_key_hash: recipient_x25519_public.as_bytes().to_vec(),
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
pub async fn distribute_sender_key(
    my_identity: &MyIdentity,
    peer_identity: &PeerIdentity,
) -> Result<Vec<ChatPacket>> {
    let mut packets_to_send = Vec::new();
    for recipient_public_key_hash in peer_identity.list_known_peers() {
        match create_key_distribution(my_identity, peer_identity, recipient_public_key_hash) {
            Ok(kd_packet) => {
                // Add this packet to the list to send
                debug!(
                    "Created key distribution for recipient {}",
                    recipient_public_key_hash
                );
                packets_to_send.push(kd_packet);
            }
            Err(e) => {
                eprintln!(
                    "Failed to create key distribution for {}: {}",
                    recipient_public_key_hash, e
                );
            }
        }
    }

    Ok(packets_to_send)
}
