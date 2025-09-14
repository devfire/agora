use crate::{
    chat_message::{ChatPacket, PlaintextPayload, PublicKeyAnnouncement, chat_packet::PacketType},
    crypto::{CryptoError, SecurityLayer, create_sha256, get_public_key_hash_as_hex_string},
    identity::{MyIdentity, PeerIdentity},
    message_buffer::MessageBuffer,
    network,
};

use anyhow::anyhow;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::Aead};
use rustyline::{DefaultEditor, error::ReadlineError};
use std::{collections::HashSet, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tracing::{debug, error};

/// Handles processing of different packet types within the UDP intake loop
struct PacketHandler<S: SecurityLayer> {
    security_module: Arc<S>,
    my_identity: MyIdentity,
    network_manager: Arc<network::NetworkManager>,
    chat_id: String,
}

impl<S: SecurityLayer + Send + Sync + 'static> PacketHandler<S> {
    fn new(
        security_module: Arc<S>,
        my_identity: MyIdentity,
        network_manager: Arc<network::NetworkManager>,
        chat_id: String,
    ) -> Self {
        Self {
            security_module,
            my_identity,
            network_manager,
            chat_id,
        }
    }

    async fn handle_public_key_announcement(
        &self,
        announcement: PublicKeyAnnouncement,
        peer_identity: &mut PeerIdentity,
        message_sender: &mpsc::Sender<PlaintextPayload>,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        debug!("Received PublicKeyAnnouncement from '{}'", announcement.display_name);

        // Check if this announcement is from ourselves (constant-time comparison)
        let this_is_me = self.my_identity.x25519_public_key.as_bytes().len()
            == announcement.x25519_public_key.len()
            && self.my_identity
                .x25519_public_key
                .as_bytes()
                .ct_eq(&announcement.x25519_public_key)
                .into();

        if this_is_me {
            debug!("But I am '{}', ignoring.", announcement.display_name);
            return Ok(());
        }

        debug!("Adding peer keys for '{}'", announcement.display_name);

        // Calculate peer hash for tracking management
        let peer_public_key_hash = create_sha256(&announcement.ed25519_public_key);
        let peer_hash_hex = get_public_key_hash_as_hex_string(&peer_public_key_hash);

        // If this is a rejoining peer, clear tracking to allow fresh key requests
        if peer_identity.peer_x25519_keys.contains_key(&peer_hash_hex) {
            if requested_peer_keys.remove(&peer_hash_hex) {
                debug!("Cleared PublicKeyRequest tracking for rejoining peer '{}'", peer_hash_hex);
            }
        }

        peer_identity.add_peer_keys(
            &announcement.x25519_public_key,
            &announcement.ed25519_public_key,
        )?;

        debug!("Current peers: {:?}", peer_identity.peer_x25519_keys.keys());

        // Send sender key distribution for new peer
        let kd_packet = self.security_module.create_sender_key_distribution(
            &announcement,
            &self.my_identity,
        )?;

        self.network_manager.send_message(kd_packet).await?;

        debug!(
            "Sent KeyDistribution packet intended for '{}' (hash: {})",
            announcement.display_name,
            get_public_key_hash_as_hex_string(&create_sha256(&announcement.ed25519_public_key))
        );

        // Create join announcement for display
        let payload = PlaintextPayload {
            display_name: announcement.display_name.clone(),
            content: format!("{} has joined the chat.", &announcement.display_name),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        if payload.display_name != self.chat_id {
            debug!("Forwarding announcement from '{}'", payload.display_name);
            message_sender.send(payload).await?;
        } else {
            debug!("Ignoring self-sent announcement from '{}'", payload.display_name);
        }

        Ok(())
    }

    async fn handle_key_distribution(
        &self,
        key_dist: crate::chat_message::KeyDistribution,
        peer_identity: &mut PeerIdentity,
        message_buffer: &mut MessageBuffer,
        message_sender: &mpsc::Sender<PlaintextPayload>,
    ) -> anyhow::Result<()> {
        let sender_key_hash_hex_string = get_public_key_hash_as_hex_string(
            &create_sha256(&key_dist.sender_ed25519_public_key),
        );

        let recipient_key_hash_hex_string = get_public_key_hash_as_hex_string(
            &key_dist.recipient_public_key_hash,
        );

        let my_ed25519_key_hash_hex_string = get_public_key_hash_as_hex_string(
            &self.my_identity.get_my_verifying_key_sha256hash_as_bytes(),
        );

        if recipient_key_hash_hex_string != my_ed25519_key_hash_hex_string {
            debug!(
                "KeyDistribution packet not intended for me. Intended for: {}, I am: {}",
                recipient_key_hash_hex_string, my_ed25519_key_hash_hex_string
            );
            return Ok(());
        }

        debug!(
            "Received KeyDistribution packet from: {} to: {}",
            sender_key_hash_hex_string, recipient_key_hash_hex_string
        );

        // Decrypt the sender key
        let sender_cipher = self.decrypt_sender_key(&key_dist)?;

        // Add the key to peer_identity
        let old_key_existed = peer_identity
            .peer_sender_keys
            .entry(sender_key_hash_hex_string.clone())
            .or_insert_with(std::collections::HashMap::new)
            .insert(key_dist.key_id, sender_cipher)
            .is_some();

        if old_key_existed {
            debug!(
                "Replaced existing sender key for peer '{}' key_id {}",
                sender_key_hash_hex_string, key_dist.key_id
            );
        } else {
            debug!(
                "Added new sender key for peer '{}' key_id {}",
                sender_key_hash_hex_string, key_dist.key_id
            );
        }

        // Process any buffered messages for this sender
        self.process_buffered_messages(
            &sender_key_hash_hex_string,
            message_buffer,
            peer_identity,
            message_sender,
        ).await?;

        Ok(())
    }

    fn decrypt_sender_key(&self, key_dist: &crate::chat_message::KeyDistribution) -> anyhow::Result<ChaCha20Poly1305> {
        let x25519_public_key_bytes: [u8; 32] = key_dist
            .sender_x25519_public_key
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Failed to convert Vec<u8> to [u8; 32]"))?;

        let (nonce_bytes, encrypted_key) = key_dist.encrypted_sender_key.split_at(12);
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

        let shared_secret = self.my_identity.x25519_secret_key.diffie_hellman(
            &x25519_dalek::PublicKey::from(x25519_public_key_bytes),
        );

        let key = chacha20poly1305::Key::from_slice(shared_secret.as_bytes());
        let cipher = ChaCha20Poly1305::new(key);

        let decrypted_key = cipher
            .decrypt(nonce, encrypted_key)
            .map_err(|e| anyhow!("Failed to decrypt sender key: {}", e))?;

        if decrypted_key.len() != 32 {
            return Err(anyhow!("Invalid sender key length"));
        }

        let sender_key = Key::from_slice(&decrypted_key);
        Ok(ChaCha20Poly1305::new(sender_key))
    }

    async fn process_buffered_messages(
        &self,
        sender_key_hash: &str,
        message_buffer: &mut MessageBuffer,
        peer_identity: &PeerIdentity,
        message_sender: &mpsc::Sender<PlaintextPayload>,
    ) -> anyhow::Result<()> {
        let buffered = message_buffer.take_sender_messages(sender_key_hash);
        for msg in buffered {
            let plaintext_result = self.security_module.decrypt_message(
                sender_key_hash,
                msg.key_id,
                &msg.encrypted_payload,
                &msg.nonce,
                peer_identity,
            );

            match plaintext_result {
                Ok(plaintext_payload) => {
                    debug!("Forwarding buffered message from '{}'", plaintext_payload.display_name);
                    message_sender.send(plaintext_payload).await?;
                }
                Err(e) => {
                    error!("Permanent failure to decrypt buffered message: {e}");
                }
            }
        }
        Ok(())
    }

    async fn handle_encrypted_message(
        &self,
        encrypted_msg: crate::chat_message::EncryptedMessage,
        peer_identity: &PeerIdentity,
        message_buffer: &mut MessageBuffer,
        message_sender: &mpsc::Sender<PlaintextPayload>,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let peer_sender_public_key_as_hex_string = get_public_key_hash_as_hex_string(
            &encrypted_msg.sender_public_key_hash,
        );

        // Check if message is from ourselves
        let my_public_key_as_hex_string = get_public_key_hash_as_hex_string(
            &self.my_identity.get_my_verifying_key_sha256hash_as_bytes(),
        );

        if peer_sender_public_key_as_hex_string == my_public_key_as_hex_string {
            debug!("Talking to myself again, ignoring.");
            eprint!("\r\x1b[K{} > ", self.chat_id);
            return Ok(());
        }

        let plaintext_payload_result = self.security_module.decrypt_message(
            &peer_sender_public_key_as_hex_string,
            encrypted_msg.key_id,
            &encrypted_msg.encrypted_payload,
            &encrypted_msg.nonce,
            peer_identity,
        );

        match plaintext_payload_result {
            Ok(plaintext_payload) => {
                debug!("Forwarding message from '{}'", plaintext_payload.display_name);
                message_sender.send(plaintext_payload).await?;
            }
            Err(crypto_error) => {
                self.handle_decryption_error(
                    crypto_error,
                    &encrypted_msg,
                    message_buffer,
                    requested_peer_keys,
                ).await?;
            }
        }

        Ok(())
    }

    async fn handle_decryption_error(
        &self,
        error: CryptoError,
        encrypted_msg: &crate::chat_message::EncryptedMessage,
        message_buffer: &mut MessageBuffer,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        match error {
            CryptoError::UnknownSender { sender_hash: sender_hash_as_string } => {
                self.handle_unknown_sender(
                    sender_hash_as_string,
                    encrypted_msg,
                    message_buffer,
                    requested_peer_keys,
                ).await
            }
            CryptoError::UnknownKeyId { key_id, sender_public_key_hash_hex } => {
                self.handle_unknown_key_id(
                    key_id,
                    sender_public_key_hash_hex,
                    encrypted_msg,
                    message_buffer,
                    requested_peer_keys,
                ).await
            }
            CryptoError::InvalidFormat => {
                self.handle_invalid_format(
                    encrypted_msg,
                    message_buffer,
                    requested_peer_keys,
                ).await
            }
            e => {
                error!("Error handling encrypted message: {}", e);
                Ok(())
            }
        }
    }

    async fn handle_unknown_sender(
        &self,
        sender_hash_as_string: String,
        encrypted_msg: &crate::chat_message::EncryptedMessage,
        message_buffer: &mut MessageBuffer,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        debug!("Wait, who is {}? Let's send this msg to the naughty house for processing.", sender_hash_as_string);

        if message_buffer.add_message(
            get_public_key_hash_as_hex_string(&encrypted_msg.sender_public_key_hash),
            encrypted_msg,
        ) {
            debug!("Buffered message from {} for future decryption", sender_hash_as_string);
        }

        self.request_public_key_if_needed(
            &sender_hash_as_string,
            &encrypted_msg.sender_public_key_hash,
            requested_peer_keys,
        ).await?;

        eprint!("\r\x1b[K{} > ", self.chat_id);
        Ok(())
    }

    async fn handle_unknown_key_id(
        &self,
        key_id: u32,
        sender_public_key_hash_hex: String,
        encrypted_msg: &crate::chat_message::EncryptedMessage,
        message_buffer: &mut MessageBuffer,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        debug!("Unknown key ID {} for sender '{}'. Requesting fresh keys.", key_id, sender_public_key_hash_hex);

        if message_buffer.add_message(sender_public_key_hash_hex.clone(), encrypted_msg) {
            debug!("Buffered UnknownKeyId message from {} for future decryption", sender_public_key_hash_hex);
        }

        self.request_public_key_if_needed(
            &sender_public_key_hash_hex,
            &encrypted_msg.sender_public_key_hash,
            requested_peer_keys,
        ).await
    }

    async fn handle_invalid_format(
        &self,
        encrypted_msg: &crate::chat_message::EncryptedMessage,
        message_buffer: &mut MessageBuffer,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let sender_hash_hex = get_public_key_hash_as_hex_string(&encrypted_msg.sender_public_key_hash);

        debug!("Invalid message format from peer '{}'. Could be stale keys, requesting fresh ones.", sender_hash_hex);

        if message_buffer.add_message(sender_hash_hex.clone(), encrypted_msg) {
            debug!("Buffered InvalidFormat message from {} for future decryption", sender_hash_hex);
        }

        self.request_public_key_if_needed(
            &sender_hash_hex,
            &encrypted_msg.sender_public_key_hash,
            requested_peer_keys,
        ).await?;

        error!("Error handling encrypted message: Invalid message format");
        Ok(())
    }

    async fn request_public_key_if_needed(
        &self,
        sender_hash: &str,
        sender_public_key_hash: &[u8],
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        if !requested_peer_keys.contains(sender_hash) {
            let public_key_request = self.security_module.create_public_key_request(
                sender_public_key_hash,
                &self.my_identity.get_my_verifying_key_sha256hash_as_bytes(),
            ).await;

            self.network_manager.send_message(public_key_request).await?;
            requested_peer_keys.insert(sender_hash.to_string());

            debug!("Sent reactive PublicKeyRequest for {}", sender_hash);
        } else {
            debug!("Already sent PublicKeyRequest for {}, skipping", sender_hash);
        }
        Ok(())
    }

    async fn handle_public_key_request(
        &self,
        request: crate::chat_message::PublicKeyRequest,
        peer_identity: &PeerIdentity,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let sender_public_ed25519_key_string = get_public_key_hash_as_hex_string(
            &request.requester_public_key_hash,
        );

        let my_public_key_hash_as_string = get_public_key_hash_as_hex_string(
            &self.my_identity.get_my_verifying_key_sha256hash_as_bytes(),
        );

        // Ignore requests from ourselves
        if sender_public_ed25519_key_string == my_public_key_hash_as_string {
            debug!("Ignoring public key request from myself");
            return Ok(());
        }

        // Send our public key announcement
        let announcement = self.security_module.create_public_key_announcement(&self.my_identity);
        let pk_announcement_packet = ChatPacket {
            packet_type: Some(PacketType::PublicKey(announcement.clone())),
        };

        self.network_manager.send_message(pk_announcement_packet).await?;
        debug!("Sent PublicKeyAnnouncement in response to request");

        // Try to send KeyDistribution if we have their x25519 key
        self.send_key_distribution_if_possible(&request, peer_identity, requested_peer_keys).await
    }

    async fn send_key_distribution_if_possible(
        &self,
        request: &crate::chat_message::PublicKeyRequest,
        peer_identity: &PeerIdentity,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let requester_hex_string = get_public_key_hash_as_hex_string(&request.requester_public_key_hash);

        if let Some(requester_x25519_key) = peer_identity.peer_x25519_keys.get(&requester_hex_string) {
            debug!("Creating KeyDistribution for requester using their x25519 key");

            let requester_announcement = PublicKeyAnnouncement {
                display_name: self.my_identity.display_name.clone(),
                x25519_public_key: requester_x25519_key.as_bytes().to_vec(),
                ed25519_public_key: request.requester_public_key_hash.clone(),
            };

            let sender_key_packet = self.security_module.create_sender_key_distribution(
                &requester_announcement,
                &self.my_identity,
            )?;

            self.network_manager.send_message(sender_key_packet).await?;
            debug!("Sent KeyDistribution packet intended for requester");
        } else {
            debug!("Don't have requester's x25519 key yet, cannot create KeyDistribution");
            self.send_reciprocal_request(request, requested_peer_keys).await?;
        }
        Ok(())
    }

    async fn send_reciprocal_request(
        &self,
        request: &crate::chat_message::PublicKeyRequest,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let requester_hash_hex = get_public_key_hash_as_hex_string(&request.requester_public_key_hash);

        if !requested_peer_keys.contains(&requester_hash_hex) {
            debug!("Requesting requester's PublicKeyAnnouncement to complete key exchange");

            let reciprocal_request = self.security_module.create_public_key_request(
                &request.requester_public_key_hash,
                &self.my_identity.get_my_verifying_key_sha256hash_as_bytes(),
            ).await;

            self.network_manager.send_message(reciprocal_request).await?;
            requested_peer_keys.insert(requester_hash_hex.clone());

            debug!("Sent reciprocal PublicKeyRequest to complete bidirectional key exchange");
        } else {
            debug!("Already sent PublicKeyRequest to requester '{}', skipping duplicate request", requester_hash_hex);
        }
        Ok(())
    }
}

/// Responsible for all message processing. Messages with missing public keys get inserted into the pending_messages HashMap.
/// Once a public key arrives, we check if there are any in this HashMap waiting to be decrypted.
/// If yes, decrypt and display. If not, move on.
/// NOTE: requested_keys keep track of requests to avoid being DOSed with bad messages.
pub struct Processor<S: SecurityLayer> {
    pub network_manager: Arc<network::NetworkManager>,
    pub my_identity: MyIdentity,
    peer_identity: PeerIdentity,
    pub security_module: Arc<S>,
}

impl<S: SecurityLayer + Send + Sync + 'static> Processor<S> {
    pub fn new(
        network_manager: Arc<network::NetworkManager>,
        my_identity: MyIdentity,
        peer_identity: PeerIdentity,
        security_module: S,
    ) -> Self {
        Self {
            network_manager,
            my_identity,
            peer_identity,
            security_module: Arc::new(security_module),
        }
    }

    /// Display task for printing messages to console. This task is READ ONLY and does not send messages.
    pub fn spawn_message_display_task(
        &self,
        mut receiver: tokio::sync::mpsc::Receiver<PlaintextPayload>,
        chat_id: &str,
    ) -> tokio::task::JoinHandle<()> {
        let chat_id = chat_id.to_string();

        tokio::spawn(async move {
            debug!("Starting chat processing task for agent '{}'", chat_id);
            while let Some(message) = receiver.recv().await {
                if message.display_name != chat_id {
                    debug!(
                        "Chat processing received message from '{}' with content: '{}'",
                        message.display_name, message.content
                    );

                    eprint!("\r\x1b[K");
                    eprintln!("{} {}: {}", message.timestamp, message.display_name, message.content);
                    eprint!("{} > ", chat_id);
                } else {
                    debug!("Ignoring self-sent message from '{}'", message.display_name);
                }
            }
            debug!("Message display task ending.");
        })
    }

    /// Spawn UDP message intake task for continuous message reception.
    pub fn spawn_udp_intake_task(
        &self,
        message_sender: mpsc::Sender<PlaintextPayload>,
        chat_id: &str,
    ) -> tokio::task::JoinHandle<()> {
        let network_manager = Arc::clone(&self.network_manager);
        let security_module = Arc::clone(&self.security_module);
        let chat_id = chat_id.to_string();
        let mut peer_identity = self.peer_identity.clone();
        let my_identity = self.my_identity.clone();

        tokio::spawn(async move {
            debug!("Starting UDP message intake task for agent '{}'", chat_id);

            let packet_handler = PacketHandler::new(
                Arc::clone(&security_module),
                my_identity.clone(),
                Arc::clone(&network_manager),
                chat_id.clone(),
            );

            let mut requested_peer_keys: HashSet<String> = HashSet::new();
            let mut message_buffer = MessageBuffer::new();

            loop {
                match network_manager.receive_message().await {
                    Ok(packet) => {
                        if let Err(e) = Self::handle_packet(
                            packet,
                            &packet_handler,
                            &mut peer_identity,
                            &mut message_buffer,
                            &message_sender,
                            &mut requested_peer_keys,
                        ).await {
                            error!("Error handling packet: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Malformed packet received: {}", e);
                    }
                }
            }
        })
    }

    async fn handle_packet(
        packet: ChatPacket,
        handler: &PacketHandler<S>,
        peer_identity: &mut PeerIdentity,
        message_buffer: &mut MessageBuffer,
        message_sender: &mpsc::Sender<PlaintextPayload>,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        match packet.packet_type {
            Some(PacketType::PublicKey(announcement)) => {
                handler.handle_public_key_announcement(
                    announcement,
                    peer_identity,
                    message_sender,
                    requested_peer_keys,
                ).await
            }
            Some(PacketType::KeyDist(key_dist)) => {
                handler.handle_key_distribution(
                    key_dist,
                    peer_identity,
                    message_buffer,
                    message_sender,
                ).await
            }
            Some(PacketType::EncryptedMsg(encrypted_msg)) => {
                handler.handle_encrypted_message(
                    encrypted_msg,
                    peer_identity,
                    message_buffer,
                    message_sender,
                    requested_peer_keys,
                ).await
            }
            Some(PacketType::PublicKeyRequest(request)) => {
                handler.handle_public_key_request(
                    request,
                    peer_identity,
                    requested_peer_keys,
                ).await
            }
            None => {
                debug!("Received packet with no packet type");
                Ok(())
            }
        }
    }

    /// Spawn a task to handle user input from stdin.
    pub fn spawn_stdin_input_task(&self, chat_id: &str) -> tokio::task::JoinHandle<()> {
        let network_manager = Arc::clone(&self.network_manager);
        let security_module = Arc::clone(&self.security_module);
        let chat_id = chat_id.to_string();
        let my_identity = self.my_identity.clone();

        tokio::spawn(async move {
            debug!("Starting stdin input task for agent '{}'", chat_id);
            let mut rustyline_editor = DefaultEditor::new().expect("Editor initialization failed");
            let mic_drop = "User has left the chat.".to_string();

            loop {
                let readline = rustyline_editor.readline(&format!("{} > ", chat_id));

                match readline {
                    Ok(line) => {
                        if line.is_empty() {
                            continue;
                        }
                        rustyline_editor.add_history_entry(line.as_str()).expect("Adding to history failed");

                        debug!("Stdin input read line: {}", line);

                        let encrypted_packet = security_module
                            .create_encrypted_chat_packet(&line, &my_identity)
                            .expect("Creating encrypted packet failed");
                        network_manager.send_message(encrypted_packet).await.expect("Sending message failed");
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        let encrypted_packet_bye_bye = security_module
                            .create_encrypted_chat_packet(&mic_drop, &my_identity)
                            .expect("Creating encrypted packet failed");
                        network_manager.send_message(encrypted_packet_bye_bye).await.expect("msg send failed");
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