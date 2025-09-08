use crate::{
    chat_message::{
        EncryptedMessage, PlaintextPayload, PublicKeyAnnouncement, chat_packet::PacketType,
    },
    crypto::{
        CryptoError, create_encrypted_chat_packet, create_public_key_announcement,
        create_public_key_request, create_sender_key_distribution, create_sha256, decrypt_message,
        get_public_key_hash_as_hex_string,
    },
    identity::{MyIdentity, PeerIdentity},
    network,
};

use anyhow::{Result, anyhow};

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::Aead};
// use anyhow::{anyhow};
use rustyline::{DefaultEditor, error::ReadlineError};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use subtle::ConstantTimeEq;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

type EncryptedMessagesPendingDecryptionHashMap = HashMap<String, Vec<EncryptedMessage>>;
type RequestedKeysHashSet = HashSet<String>;

/// Responsible for all message processing. Messages with missing public keys get inserted into the pending_messages HashMap.
/// Once a public key arrives, we check if there are any in this HashMap waiting to be decrypted.
/// If yes, decrypt and display. If not, move on.
/// NOTE: requested_keys keep track of requests to avoid being DOSed with bad messages.
pub struct Processor {
    pub network_manager: Arc<network::NetworkManager>,
    pub my_identity: MyIdentity,
    peer_identity: PeerIdentity,
}

impl Processor {
    pub fn new(
        network_manager: Arc<network::NetworkManager>,
        my_identity: MyIdentity,
        peer_identity: PeerIdentity,
    ) -> Self {
        Self {
            network_manager,
            my_identity,
            peer_identity,
        }
    }

    /// Display task for printing messages to console. This task is READ ONLY and does not send messages.
    pub fn spawn_message_display_task(
        &self,
        mut receiver: tokio::sync::mpsc::Receiver<PlaintextPayload>,
        chat_id: &str,
    ) -> tokio::task::JoinHandle<()> {
        // let message_handler = Arc::clone(&self.message_handler);
        let chat_id = chat_id.to_string();

        tokio::spawn(async move {
            debug!("Starting chat processing task for agent '{}'", chat_id);
            while let Some(message) = receiver.recv().await {
                // Filter messages sent by self
                if message.display_name != chat_id {
                    debug!(
                        "Chat processing received message from '{}' with content: '{}'",
                        message.display_name,
                        message.content // message.content.chars().take(50).collect::<String>()
                    );

                    // Clear the current prompt line and print the message, then re-display prompt
                    eprint!("\r\x1b[K"); // Carriage return and clear line
                    eprintln!(
                        "{} {}: {}",
                        message.timestamp, message.display_name, message.content
                    );
                    eprint!("{} > ", chat_id); // Re-display the prompt
                } else {
                    debug!("Ignoring self-sent message from '{}'", message.display_name);
                }
            }
            info!("Message display task ending.");
        })
    }

    /// Spawn UDP message intake task for continuous message reception.
    /// This task receives messages from multicast and sends them to MPSC channel.
    /// spawn_message_display_task() will handle the receiving end of the MPSC channel and forward messages back to channel.
    /// Then, receive_message() will trigger the spawn_message_display_task() to print messages to console.
    pub fn spawn_udp_intake_task(
        &self,
        message_sender: mpsc::Sender<PlaintextPayload>,
        chat_id: &str,
    ) -> tokio::task::JoinHandle<()> {
        let network_manager = Arc::clone(&self.network_manager);

        let chat_id = chat_id.to_string(); // Clone chat_id to move into the task
        let mut peer_identity = self.peer_identity.clone();
        let my_identity = self.my_identity.clone();

        tokio::spawn(async move {
            debug!("Starting UDP message intake task for agent '{}'", chat_id);

            let mut pending_messages: EncryptedMessagesPendingDecryptionHashMap = HashMap::new();
            let mut requested_keys: RequestedKeysHashSet = HashSet::new();

            loop {
                match network_manager.receive_message().await {
                    Ok(packet) => {
                        debug!("Received ChatPacket: {:?}", packet);
                        match packet.packet_type {
                            Some(PacketType::PublicKey(announcement)) => {
                                info!(
                                    "Received PublicKeyAnnouncement from '{}'",
                                    announcement.display_name
                                );

                                // NOTE: Loopback is disabled at the socket level, so we should not receive our own announcements.
                                // However, as a safety measure, we will still check if the announcement is from ourselves
                                // Also this is mega cool.
                                //
                                // The best way to compare two x25519_public_key values is with a constant-time comparison to prevent timing attacks.
                                // Since we are comparing cryptographic key material, it's crucial to avoid any timing discrepancies that could leak information about the key.
                                // A standard equality check (==) is not safe for this purpose because it "short-circuits" (lol) it returns false as soon as it finds a mismatch.
                                // An attacker could potentially measure the tiny differences in comparison time to guess the key's value byte by byte.
                                //
                                // The correct and secure method is to use a crate like subtle that provides constant-time cryptographic functions.
                                let this_is_me = my_identity.x25519_public_key.as_bytes().len()
                                    == announcement.x25519_public_key.len()
                                    && my_identity
                                        .x25519_public_key
                                        .as_bytes()
                                        .ct_eq(&announcement.x25519_public_key)
                                        .into();

                                // check to see if I am the sender
                                if this_is_me {
                                    debug!("But I am '{}', ignoring.", announcement.display_name);
                                    continue; // We gon baaaaail...
                                }
                                // Add peer keys to peer identity
                                // TODO: Filter out self-sent announcements
                                info!("Adding peer keys for '{}'", announcement.display_name);
                                peer_identity
                                    .add_peer_keys(
                                        // NOTE: internally, this uses the hex-encoded SHA256 hash of the Ed25519 public key as the identifier
                                        &announcement.x25519_public_key,
                                        &announcement.ed25519_public_key,
                                    )
                                    .expect("Failed to add peer keys");

                                info!("Current peers: {:?}", peer_identity.peer_x25519_keys.keys());

                                // Let's see if this is a new peer coming online

                                // Send the sender key only when we receive a PublicKeyAnnouncement from a new peer.
                                let kd_packet = create_sender_key_distribution(
                                    &announcement,
                                    &my_identity,
                                    // &peer_identity,
                                )
                                .expect("Failed to distribute sender key");

                                // We have the key distribution, send it.
                                network_manager
                                    .send_message(kd_packet)
                                    .await
                                    .expect("Failed to send KeyDistribution packet");

                                // Now, let's create a PlaintextPayload to announce the new user
                                let payload = PlaintextPayload {
                                    display_name: announcement.display_name.clone(),
                                    content: format!(
                                        "{} has joined the chat.",
                                        &announcement.display_name
                                    ),
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .expect("Getting time failed")
                                        .as_secs(),
                                };
                                // Forward the announcement to the message display task
                                // TODO: this needs to be removed because we already filtered out self-sent announcements above
                                if payload.display_name != chat_id {
                                    debug!(
                                        "Forwarding announcement from '{}'",
                                        payload.display_name
                                    );
                                    message_sender
                                        .send(payload)
                                        .await
                                        .expect("Failed to send message");
                                } else {
                                    debug!(
                                        "Ignoring self-sent announcement from '{}'",
                                        payload.display_name
                                    );
                                }
                            }
                            Some(PacketType::KeyDist(key_dist)) => {
                                // This is who it came from
                                // First, let's convert the sender_ed25519_public_key to hex string for lookup
                                let sender_key_hash_hex_string = get_public_key_hash_as_hex_string(
                                    &crate::crypto::create_sha256(
                                        &key_dist.sender_ed25519_public_key,
                                    ),
                                );

                                // This is who this was meant for
                                let recipient_key_hash_hex_string =
                                    get_public_key_hash_as_hex_string(
                                        &key_dist.recipient_public_key_hash,
                                    );

                                let my_ed25519_key_hash_hex_string =
                                    get_public_key_hash_as_hex_string(
                                        &my_identity.get_my_verifying_key_sha256hash_as_bytes(),
                                    );
                                if recipient_key_hash_hex_string != my_ed25519_key_hash_hex_string {
                                    info!(
                                        "KeyDistribution packet not intended for me. Intended for: {}, I am: {}",
                                        recipient_key_hash_hex_string, my_ed25519_key_hash_hex_string
                                    );
                                    continue;
                                } else {
                                    info!(
                                        "Received KeyDistribution packet from: {} to: {}",
                                        sender_key_hash_hex_string, recipient_key_hash_hex_string
                                    );
                                    debug!("Recipient verification - Packet intended for: {}", recipient_key_hash_hex_string);
                                    debug!("Recipient verification - My public key hash: {}", my_ed25519_key_hash_hex_string);
                                    debug!("Recipient verification - Am I the intended recipient? {}", recipient_key_hash_hex_string == my_ed25519_key_hash_hex_string);
                                }

                                // match peer_identity
                                //     .peer_x25519_keys
                                //     .get(&sender_key_hash_hex_string)
                                // {
                                //     Some(sender_x25519_public) => {

                                // OK now we convert the key to a 32 byte fixed array
                                let x25519_public_key_bytes: [u8; 32] =
                                    key_dist.sender_x25519_public_key.clone().try_into().map_err(
                                        |_| anyhow!("Failed to convert Vec<u8> to [u8; 32]"),
                                    ).expect("Should have been able to convert public key bytes to a 32 byte fixed array");

                                // Extract nonce and encrypted key
                                let (nonce_bytes, encrypted_key) =
                                    key_dist.encrypted_sender_key.split_at(12);
                                let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

                                // Perform ECDH to get shared secret
                                let shared_secret = my_identity.x25519_secret_key.diffie_hellman(
                                    &x25519_dalek::PublicKey::from(x25519_public_key_bytes),
                                );

                                // Use shared secret as decryption key
                                let key =
                                    chacha20poly1305::Key::from_slice(shared_secret.as_bytes());
                                let cipher = ChaCha20Poly1305::new(key);

                                debug!("Decryption - My secret key (first 8 bytes): {:?}", &my_identity.x25519_secret_key.as_bytes()[..8]);
                                debug!("Decryption - Sender public key (first 8 bytes): {:?}", &x25519_public_key_bytes[..8]);
                                debug!("Decryption - Shared secret (first 8 bytes): {:?}", &shared_secret.as_bytes()[..8]);
                                debug!("Decryption - Nonce: {:?}", nonce_bytes);
                                debug!("Decryption - Encrypted data length: {}", encrypted_key.len());
                                let decrypted_key = cipher
                                    .decrypt(nonce, encrypted_key)
                                    .map_err(|e| error!("Creating the decrypted_key failed: {}", e))
                                    .expect("Failed to decrypt the sender key.");

                                if decrypted_key.len() != 32 {
                                    error!("Invalid sender key length");
                                }

                                let sender_key = Key::from_slice(&decrypted_key);
                                let sender_cipher = ChaCha20Poly1305::new(sender_key);

                                // Add the key to peer_identity
                                peer_identity
                                    .peer_sender_keys
                                    .entry(sender_key_hash_hex_string.clone())
                                    .or_insert_with(std::collections::HashMap::new)
                                    .insert(key_dist.key_id, sender_cipher);
                                // }
                                // None => {
                                //     warn!(
                                //         "Missing ed25519 public key hash string to look for the peer's x25519 public key."
                                //     );
                                //     // Request key (only once)
                                //     // If this fails, that means we already asked, so let's not ask again.
                                //     if requested_keys.insert(sender_key_hash_hex_string) {
                                //         // ask for the public key of the mystery sender
                                //         let public_key_request = create_public_key_request(
                                //             &key_dist.sender_ed25519_public_key,
                                //             &my_identity
                                //                 .get_my_verifying_key_sha256hash_as_bytes(),
                                //         )
                                //         .await;

                                //         info!(
                                //             "Asking {recipient_key_hash_hex_string} for their public key."
                                //         );

                                //         // Send it off, asking for the public key
                                //         network_manager
                                //             .send_message(public_key_request)
                                //             .await
                                //             .expect(
                                //                 "Failed to send PublicKeyRequest packet",
                                //             );
                                //     }
                                //     // Clear the current prompt line and print the message, then re-display prompt
                                //     eprint!("\r\x1b[K"); // Carriage return and clear line

                                //     eprint!("{} > ", chat_id); // Re-display the prompt
                                // }
                            }

                            // if key_dist.encrypted_sender_key.len() < 12 {
                            //     error!("Encrypted data too short");
                            //     continue;
                            // }
                            // }
                            // }

                            // Let's handle the EncryptedMsg case to extract and forward the PlaintextPayload
                            Some(PacketType::EncryptedMsg(encrypted_msg)) => {
                                info!(
                                    "Received EncryptedMessage from '{:?}', key_id {}",
                                    encrypted_msg.sender_public_key_hash, encrypted_msg.key_id
                                );
                                // Decrypt the message
                                // Convert the sender public key hash to hex string for lookup
                                let peer_sender_public_key_as_hex_string =
                                    get_public_key_hash_as_hex_string(
                                        &encrypted_msg.sender_public_key_hash,
                                    );

                                // see if it's from me
                                let my_public_key_as_hex_string = get_public_key_hash_as_hex_string(
                                    &my_identity.get_my_verifying_key_sha256hash_as_bytes(),
                                );

                                if peer_sender_public_key_as_hex_string
                                    == my_public_key_as_hex_string
                                {
                                    warn!("Talking to myself again, ignoring.");

                                    eprint!("\r\x1b[K"); // Carriage return and clear line

                                    eprint!("{} > ", chat_id); // Re-display the prompt
                                    continue;
                                }
                                // info!(
                                //     "Received encrypted message from sender_public_key_hash: {}",
                                //     peer_sender_public_key_as_hex_string
                                // );

                                // Handle encrypted message
                                let plaintext_payload_result = decrypt_message(
                                    &peer_sender_public_key_as_hex_string,
                                    encrypted_msg.key_id,
                                    &encrypted_msg.encrypted_payload,
                                    &encrypted_msg.nonce,
                                    &peer_identity,
                                );

                                match plaintext_payload_result {
                                    Ok(plaintext_payload) => {
                                        debug!(
                                            "Forwarding message from '{}'",
                                            plaintext_payload.display_name
                                        );
                                        message_sender
                                            .send(plaintext_payload.clone())
                                            .await
                                            .expect("Failed to send message");
                                    }
                                    Err(CryptoError::UnknownSender {
                                        sender_hash: sender_hash_as_string,
                                    }) => {
                                        warn!(
                                            "Wait, who is {sender_hash_as_string}? Let's send this msg to the naughty house for processing."
                                        );

                                        // Append this message to the naughty msg HashMap
                                        pending_messages
                                            .entry(sender_hash_as_string.to_string())
                                            .or_default()
                                            .push(encrypted_msg.clone());

                                        let my_public_key_hash_as_string =
                                            get_public_key_hash_as_hex_string(
                                                &my_identity
                                                    .get_my_verifying_key_sha256hash_as_bytes(),
                                            );

                                        // Request key (only once)
                                        // If this fails, that means we already asked, so let's not ask again.
                                        // if requested_keys.insert(sender_hash_as_string.to_string())
                                        // {
                                        // ask for the public key of the mystery sender
                                        let public_key_request = create_public_key_request(
                                            &encrypted_msg.sender_public_key_hash.clone(),
                                            &my_identity.get_my_verifying_key_sha256hash_as_bytes(),
                                        )
                                        .await;

                                        info!(
                                            "Asking {sender_hash_as_string} from {my_public_key_hash_as_string} for their public key."
                                        );

                                        // Send it off, asking for the public key
                                        network_manager
                                            .send_message(public_key_request)
                                            .await
                                            .expect("Failed to send PublicKeyRequest packet");
                                        // }
                                        // Clear the current prompt line and print the message, then re-display prompt
                                        eprint!("\r\x1b[K"); // Carriage return and clear line

                                        eprint!("{} > ", chat_id); // Re-display the prompt
                                    }
                                    Err(_) => {
                                        // all other errors will handle later
                                        todo!()
                                    }
                                }
                            }
                            Some(PacketType::PublicKeyRequest(request)) => {
                                let sender_public_ed25519_key_string =
                                    get_public_key_hash_as_hex_string(
                                        &request.requester_public_key_hash,
                                    );

                                let my_public_key_hash_as_string =
                                    get_public_key_hash_as_hex_string(
                                        &my_identity.get_my_verifying_key_sha256hash_as_bytes(),
                                    );

                                if sender_public_ed25519_key_string == my_public_key_hash_as_string
                                {
                                    info!(
                                        "Public key request from {sender_public_ed25519_key_string} to {my_public_key_hash_as_string}"
                                    );
                                    continue;
                                }
                                info!(
                                    "Received PublicKeyRequest from {}",
                                    sender_public_ed25519_key_string
                                );
                                // TODO: handle the public key request if necessary

                                let announcement =
                                    create_public_key_announcement(&my_identity).await;

                                let pk_announcement_packet = create_sender_key_distribution(
                                    &announcement,
                                    &my_identity,
                                    // &peer_identity,
                                )
                                .expect("Failed to create sender key");

                                // We have the public key request, send it.
                                network_manager
                                    .send_message(pk_announcement_packet)
                                    .await
                                    .expect("Failed to announce my public keys");

                                // let's send the sender key distribution as well and send it
                                let sender_key_packet =
                                    create_sender_key_distribution(&announcement, &my_identity)
                                        .expect("Sender key packet should include all details.");

                                network_manager
                                    .send_message(sender_key_packet)
                                    .await
                                    .expect("Should have sent the sender key");
                            }

                            None => todo!(),
                        }
                    }
                    Err(e) => {
                        error!("Malformed packet received: {}", e);
                    }
                }
            }
        })
    }

    /// Deal with messages we cannot decrypt
    // async fn handle_missing_public_key(
    //     &mut self,
    //     sender_hash_as_string: &str,
    //     my_identity: &MyIdentity,
    //     encrypted_msg: &EncryptedMessage,
    // ) {

    // }
    /// Spawn a task to handle user input from stdin.
    /// This task reads lines from stdin and sends them as messages to the network manager for multicasting out.
    pub fn spawn_stdin_input_task(&self, chat_id: &str) -> tokio::task::JoinHandle<()> {
        let network_manager = Arc::clone(&self.network_manager);

        let chat_id = chat_id.to_string(); // Clone chat_id to move into the task
        let my_identity = self.my_identity.clone();
        debug!("Starting stdin input task for agent '{}'", chat_id);
        tokio::spawn(async move {
            // Initialize rustyline editor for input with history support
            let mut rustyline_editor = DefaultEditor::new().expect("Editor initialization failed");

            // Message to send when user exits
            let mic_drop = "User has left the chat.".to_string();
            loop {
                // Print prompt to stderr (unbuffered)
                // eprint!("{} > ", chat_id);
                let readline = rustyline_editor.readline(&format!("{} > ", chat_id));

                match readline {
                    Ok(line) => {
                        if line.is_empty() {
                            continue; // Ignore empty lines
                        }
                        rustyline_editor
                            .add_history_entry(line.as_str())
                            .expect("Adding to history failed");

                        // Create and send the chat message
                        debug!("Stdin input read line: {}", line);

                        let encrypted_packet = create_encrypted_chat_packet(&line, &my_identity)
                            .expect("Creating encrypted packet failed");
                        network_manager
                            .send_message(encrypted_packet)
                            .await
                            .expect("Sending message failed");
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        let encrypted_packet_bye_bye =
                            create_encrypted_chat_packet(&mic_drop, &my_identity)
                                .expect("Creating encrypted packet failed");
                        network_manager
                            .send_message(encrypted_packet_bye_bye)
                            .await
                            .expect("msg send failed");
                        std::process::exit(0);
                    }

                    Err(err) => {
                        error!("Error: {:?}", err);
                        break;
                    }
                }
            }
        })
    }
}
