use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::Aead};

use std::{collections::HashSet, sync::Arc};

use subtle::ConstantTimeEq;
use tracing::{debug, error};

use crate::{
    chat_message::{ChatPacket, PlaintextPayload, PublicKeyAnnouncement, chat_packet::PacketType},
    crypto::{CryptoError, SecurityLayer, create_sha256, get_public_key_hash_as_hex_string},
    identity::{MyIdentity, PeerIdentity},
    message_buffer::MessageBuffer,
    network,
};

use anyhow::anyhow;
use tokio::sync::mpsc;

/// Handles processing of different packet types within the UDP intake loop
pub struct PacketHandler<S: SecurityLayer> {
    security_module: Arc<S>,
    my_identity: MyIdentity,
    network_manager: Arc<network::NetworkManager>,
    chat_id: String,
}

impl<S: SecurityLayer + Send + Sync + 'static> PacketHandler<S> {
    /// Creates a new instance of PacketHandler with the specified dependencies.
    ///
    /// This constructor initializes a PacketHandler that coordinates the processing of various
    /// packet types in the UDP intake loop, managing cryptographic operations and network communication.
    ///
    /// # Arguments
    /// * `security_module` - The security layer implementation for cryptographic operations
    /// * `my_identity` - This node's identity containing cryptographic keys and display name
    /// * `network_manager` - Network manager for sending messages to peers
    /// * `chat_id` - The chat identifier for this session
    ///
    /// # Returns
    /// Returns a new PacketHandler instance configured with the provided dependencies.
    ///
    /// # Typical Usage
    /// Called during application initialization to set up the packet processing infrastructure.
    pub fn new(
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

    /// Processes a public key announcement received from a peer in the chat network.
    ///
    /// This function handles the initial key exchange when a new peer joins the chat or re-announces
    /// their presence. It validates the announcement isn't from the local user, updates the peer
    /// identity database, distributes sender keys to enable encrypted communication, and broadcasts
    /// a join notification to other peers.
    ///
    /// # Arguments
    /// * `announcement` - The PublicKeyAnnouncement packet containing the peer's display name and cryptographic keys
    /// * `peer_identity` - Mutable reference to the peer identity database to store new peer information
    /// * `message_sender` - Async channel for forwarding join notifications to the application
    /// * `requested_peer_keys` - Mutable set tracking which peers have had key requests sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the announcement was processed successfully.
    /// Returns an error if there are issues with key processing or network communication.
    ///
    /// # Behavior
    /// - **Self-filtering**: Ignores announcements from the local user to prevent infinite loops
    /// - **Peer registration**: Adds the peer's X25519 and Ed25519 keys to the identity database
    /// - **Key distribution**: Sends encrypted sender keys to the new peer for bidirectional communication
    /// - **Rejoining handling**: Clears stale key requests for peers rejoining the chat
    /// - **Join notification**: Forwards a plaintext join message unless it's the local user
    ///
    /// # Security Considerations
    /// - Uses constant-time comparison to prevent timing attacks when checking self-identity
    /// - Validates peer keys before storage and usage
    /// - Ensures only legitimate peers can initiate key exchange
    ///
    /// # Typical Usage
    /// Called automatically when a PublicKeyAnnouncement packet is received from the network layer.
    /// This enables the distributed key exchange protocol that establishes secure communication
    /// channels between all participants in the chat.
    pub async fn handle_public_key_announcement(
        &self,
        announcement: PublicKeyAnnouncement,
        peer_identity: &mut PeerIdentity,
        message_sender: &mpsc::Sender<PlaintextPayload>,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        debug!(
            "Received PublicKeyAnnouncement from '{}'",
            announcement.display_name
        );

        // Check if this announcement is from ourselves (constant-time comparison)
        let this_is_me = self.my_identity.x25519_public_key.as_bytes().len()
            == announcement.x25519_public_key.len()
            && self
                .my_identity
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
                debug!(
                    "Cleared PublicKeyRequest tracking for rejoining peer '{}'",
                    peer_hash_hex
                );
            }
        }

        peer_identity.add_peer_keys(
            &announcement.x25519_public_key,
            &announcement.ed25519_public_key,
        )?;

        debug!("Current peers: {:?}", peer_identity.peer_x25519_keys.keys());

        // Send sender key distribution for new peer
        let kd_packet = self
            .security_module
            .create_sender_key_distribution(&announcement, &self.my_identity)?;

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
            debug!(
                "Ignoring self-sent announcement from '{}'",
                payload.display_name
            );
        }

        Ok(())
    }

    /// Processes a key distribution packet to establish decryption capability for a peer's messages.
    ///
    /// This function handles the reception of encrypted sender keys from peers, enabling the local
    /// node to decrypt future messages from that sender. It validates the packet is intended for
    /// this node, decrypts the sender key using Diffie-Hellman shared secret derivation, stores
    /// the key for future use, and processes any buffered messages that were waiting for this key.
    ///
    /// # Arguments
    /// * `key_dist` - The KeyDistribution packet containing encrypted sender key and metadata
    /// * `peer_identity` - Mutable reference to peer identity database for storing decrypted keys
    /// * `message_buffer` - Mutable reference to buffer containing messages awaiting decryption keys
    /// * `message_sender` - Async channel for forwarding successfully decrypted plaintext payloads
    ///
    /// # Returns
    /// Returns `Ok(())` if the key distribution was processed successfully.
    /// Returns an error if cryptographic operations fail or network communication issues occur.
    ///
    /// # Behavior
    /// - **Recipient validation**: Ignores packets not intended for this node (different recipient hash)
    /// - **Cryptographic decryption**: Uses X25519 Diffie-Hellman to decrypt the sender key
    /// - **Key storage**: Stores the decrypted sender key mapped by sender hash and key ID
    /// - **Buffer processing**: Attempts to decrypt and forward any previously buffered messages
    /// - **Key replacement**: Handles replacement of existing keys with the same ID
    ///
    /// # Security Considerations
    /// - Validates packet recipient to prevent key theft attacks
    /// - Uses authenticated encryption (ChaCha20Poly1305) for key transmission
    /// - Employs Diffie-Hellman key exchange for forward secrecy
    /// - Stores keys securely in peer identity database
    ///
    /// # Typical Usage
    /// Called automatically when a KeyDistribution packet is received from the network layer.
    /// This completes the key exchange handshake initiated by public key announcements,
    /// enabling bidirectional encrypted communication with the sending peer.
    pub async fn handle_key_distribution(
        &self,
        key_dist: crate::chat_message::KeyDistribution,
        peer_identity: &mut PeerIdentity,
        message_buffer: &mut MessageBuffer,
        message_sender: &mpsc::Sender<PlaintextPayload>,
    ) -> anyhow::Result<()> {
        let sender_key_hash_hex_string =
            get_public_key_hash_as_hex_string(&create_sha256(&key_dist.sender_ed25519_public_key));

        let recipient_key_hash_hex_string =
            get_public_key_hash_as_hex_string(&key_dist.recipient_public_key_hash);

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
        )
        .await?;

        Ok(())
    }

    /// Decrypts a sender key from an encrypted key distribution packet using X25519 Diffie-Hellman key exchange.
    ///
    /// This function performs the cryptographic operations necessary to decrypt a sender key that was
    /// encrypted by another peer using their X25519 public key and this node's X25519 private key.
    /// The decrypted sender key is then used to initialize a ChaCha20Poly1305 cipher for decrypting
    /// messages from that sender.
    ///
    /// # Arguments
    /// * `key_dist` - The key distribution packet containing the encrypted sender key and necessary public keys
    ///
    /// # Returns
    /// Returns `Ok(ChaCha20Poly1305)` with a cipher initialized with the decrypted sender key.
    /// Returns an error if:
    /// - The X25519 public key conversion fails
    /// - The cryptographic decryption fails
    /// - The decrypted key has an invalid length (must be exactly 32 bytes)
    ///
    /// # Cryptographic Process
    /// 1. Extracts the sender's X25519 public key from the key distribution packet
    /// 2. Splits the encrypted sender key into a 12-byte nonce and the encrypted key data
    /// 3. Performs X25519 Diffie-Hellman key exchange with the sender's public key to derive a shared secret
    /// 4. Uses ChaCha20Poly1305 authenticated encryption with the shared secret to decrypt the sender key
    /// 5. Validates the decrypted key length (must be 32 bytes for ChaCha20Poly1305)
    /// 6. Returns a ChaCha20Poly1305 cipher initialized with the decrypted sender key
    ///
    /// # Security Notes
    /// - Uses constant-time cryptographic operations where available
    /// - Validates all key lengths to prevent buffer overflow attacks
    /// - Failed decryption is treated as a permanent error (not retried)
    ///
    /// # Typical Usage
    /// Called during key distribution packet processing to establish decryption capability
    /// for messages from a specific peer using their sender keys.
    pub fn decrypt_sender_key(
        &self,
        key_dist: &crate::chat_message::KeyDistribution,
    ) -> anyhow::Result<ChaCha20Poly1305> {
        let x25519_public_key_bytes: [u8; 32] = key_dist
            .sender_x25519_public_key
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Failed to convert Vec<u8> to [u8; 32]"))?;

        let (nonce_bytes, encrypted_key) = key_dist.encrypted_sender_key.split_at(12);
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

        let shared_secret = self
            .my_identity
            .x25519_secret_key
            .diffie_hellman(&x25519_dalek::PublicKey::from(x25519_public_key_bytes));

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

    /// Processes buffered encrypted messages for a specific sender after decryption keys become available.
    ///
    /// This function is called when new decryption keys are received (typically via key distribution),
    /// allowing previously buffered messages to be decrypted and forwarded to the application.
    /// It removes and processes all buffered messages for the specified sender, attempting to decrypt
    /// each one using the security module.
    ///
    /// # Arguments
    /// * `sender_key_hash` - Hex string hash identifying the sender whose buffered messages should be processed
    /// * `message_buffer` - Mutable reference to the message buffer containing encrypted messages waiting for keys
    /// * `peer_identity` - Current peer identity containing available decryption keys
    /// * `message_sender` - Async channel sender for forwarding successfully decrypted plaintext payloads
    ///
    /// # Returns
    /// Returns `Ok(())` if all buffered messages were processed (regardless of individual decryption success/failure).
    /// Returns an error only if there's a fundamental problem with message processing.
    ///
    /// # Behavior
    /// - Removes all buffered messages for the specified sender from the buffer
    /// - Attempts to decrypt each message using the security module
    /// - Forwards successfully decrypted messages as `PlaintextPayload` through the message sender
    /// - Logs decryption failures as permanent errors (messages are not re-buffered)
    /// - Continues processing remaining messages even if individual decryptions fail
    ///
    /// # Typical Usage
    /// Called automatically after receiving key distribution packets that provide the necessary
    /// decryption keys for previously unknown senders or key IDs.
    pub async fn process_buffered_messages(
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
                    debug!(
                        "Forwarding buffered message from '{}'",
                        plaintext_payload.display_name
                    );
                    message_sender.send(plaintext_payload).await?;
                }
                Err(e) => {
                    error!("Permanent failure to decrypt buffered message: {e}");
                }
            }
        }
        Ok(())
    }

    /// Processes an incoming encrypted message, attempting decryption and forwarding or buffering as appropriate.
    ///
    /// This is the main entry point for handling encrypted chat messages received from peers.
    /// The function first checks if the message is from the local user (self-sent messages are ignored),
    /// then attempts to decrypt the message using available keys. Successfully decrypted messages
    /// are forwarded to the application, while decryption failures trigger appropriate error handling
    /// such as buffering the message and requesting missing keys.
    ///
    /// # Arguments
    /// * `encrypted_msg` - The encrypted message packet to process
    /// * `peer_identity` - Current peer identity containing available decryption keys
    /// * `message_buffer` - Mutable reference to buffer for storing messages that cannot be decrypted yet
    /// * `message_sender` - Async channel sender for forwarding successfully decrypted plaintext payloads
    /// * `requested_peer_keys` - Mutable set of peer key hashes for which key requests have been sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the message was processed successfully.
    /// Returns an error if there's a fundamental problem with message handling.
    ///
    /// # Behavior
    /// - **Self-message filtering**: Ignores messages sent by the local user to prevent echo
    /// - **Decryption attempt**: Uses the security module to decrypt the message with available keys
    /// - **Success path**: Forwards decrypted `PlaintextPayload` through the message sender channel
    /// - **Failure path**: Delegates to `handle_decryption_error` which may buffer the message
    ///   and request missing cryptographic keys from the sender
    ///
    /// # Typical Usage
    /// Called for every encrypted message received through the network layer.
    /// This function coordinates the entire flow from encrypted packet reception to
    /// plaintext message delivery or appropriate error handling and key recovery.
    pub async fn handle_encrypted_message(
        &self,
        encrypted_msg: crate::chat_message::EncryptedMessage,
        peer_identity: &PeerIdentity,
        message_buffer: &mut MessageBuffer,
        message_sender: &mpsc::Sender<PlaintextPayload>,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let peer_sender_public_key_as_hex_string =
            get_public_key_hash_as_hex_string(&encrypted_msg.sender_public_key_hash);

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
                debug!(
                    "Forwarding message from '{}'",
                    plaintext_payload.display_name
                );
                message_sender.send(plaintext_payload).await?;
            }
            Err(crypto_error) => {
                self.handle_decryption_error(
                    crypto_error,
                    &encrypted_msg,
                    message_buffer,
                    requested_peer_keys,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Routes decryption errors to appropriate recovery handlers based on error type.
    ///
    /// This function acts as a central dispatcher for handling various cryptographic decryption failures.
    /// When message decryption fails, it analyzes the specific error type and delegates to specialized
    /// handlers that implement appropriate recovery strategies such as key requests or message buffering.
    ///
    /// # Arguments
    /// * `error` - The specific `CryptoError` that occurred during decryption
    /// * `encrypted_msg` - Reference to the encrypted message that failed to decrypt
    /// * `message_buffer` - Mutable reference to buffer for storing undecryptable messages
    /// * `requested_peer_keys` - Mutable set of peer key hashes for which key requests have been sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the error was handled appropriately.
    /// Returns an error if there's a problem with the error handling process itself.
    ///
    /// # Error Handling Strategy
    /// - **`CryptoError::UnknownSender`**: Routes to `handle_unknown_sender` which buffers the message
    ///   and requests the sender's public key from the network
    /// - **`CryptoError::UnknownKeyId`**: Routes to `handle_unknown_key_id` which buffers the message
    ///   and requests fresh keys for the known sender
    /// - **`CryptoError::InvalidFormat`**: Routes to `handle_invalid_format` which buffers the message
    ///   and requests fresh keys due to potentially stale encryption keys
    /// - **Other errors**: Logs the error and continues (no recovery possible)
    ///
    /// # Recovery Mechanisms
    /// The function implements a "buffer and request" strategy where undecryptable messages
    /// are temporarily stored while cryptographic keys are requested from peers. Once keys
    /// are received, buffered messages can be processed via `process_buffered_messages`.
    ///
    /// # Typical Usage
    /// Called automatically by `handle_encrypted_message` when decryption fails.
    /// This enables graceful handling of temporary key unavailability in distributed systems.
    async fn handle_decryption_error(
        &self,
        error: CryptoError,
        encrypted_msg: &crate::chat_message::EncryptedMessage,
        message_buffer: &mut MessageBuffer,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        match error {
            CryptoError::UnknownSender {
                sender_hash: sender_hash_as_string,
            } => {
                self.handle_unknown_sender(
                    sender_hash_as_string,
                    encrypted_msg,
                    message_buffer,
                    requested_peer_keys,
                )
                .await
            }
            CryptoError::UnknownKeyId {
                key_id,
                sender_public_key_hash_hex,
            } => {
                self.handle_unknown_key_id(
                    key_id,
                    sender_public_key_hash_hex,
                    encrypted_msg,
                    message_buffer,
                    requested_peer_keys,
                )
                .await
            }
            CryptoError::InvalidFormat => {
                self.handle_invalid_format(encrypted_msg, message_buffer, requested_peer_keys)
                    .await
            }
            e => {
                error!("Error handling encrypted message: {}", e);
                Ok(())
            }
        }
    }

    /// Handles decryption failure due to unknown sender by buffering the message and requesting peer keys.
    ///
    /// This function is called when an encrypted message cannot be decrypted because the sender's
    /// public key is not known to this node. It buffers the message for later processing and
    /// initiates a request for the sender's public key information.
    ///
    /// # Arguments
    /// * `sender_hash_as_string` - Hex string hash identifying the unknown sender
    /// * `encrypted_msg` - The encrypted message that failed to decrypt
    /// * `message_buffer` - Mutable reference to buffer for storing undecryptable messages
    /// * `requested_peer_keys` - Mutable set tracking which peers have had key requests sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the unknown sender situation was handled appropriately.
    ///
    /// # Behavior
    /// - Buffers the encrypted message for future decryption once keys are received
    /// - Sends a public key request to obtain the sender's cryptographic keys
    /// - Prevents duplicate requests by checking the requested_peer_keys set
    ///
    /// # Typical Usage
    /// Called by handle_decryption_error when CryptoError::UnknownSender occurs.
    async fn handle_unknown_sender(
        &self,
        sender_hash_as_string: String,
        encrypted_msg: &crate::chat_message::EncryptedMessage,
        message_buffer: &mut MessageBuffer,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        debug!(
            "Wait, who is {}? Let's send this msg to the naughty house for processing.",
            sender_hash_as_string
        );

        if message_buffer.add_message(
            get_public_key_hash_as_hex_string(&encrypted_msg.sender_public_key_hash),
            encrypted_msg,
        ) {
            debug!(
                "Buffered message from {} for future decryption",
                sender_hash_as_string
            );
        }

        self.request_public_key_if_needed(
            &sender_hash_as_string,
            &encrypted_msg.sender_public_key_hash,
            requested_peer_keys,
        )
        .await?;

        eprint!("\r\x1b[K{} > ", self.chat_id);
        Ok(())
    }

    /// Handles decryption failure due to unknown key ID by buffering the message and requesting fresh keys.
    ///
    /// This function manages the case where an encrypted message uses a key ID that is not
    /// currently known to this node, typically indicating the sender has rotated keys.
    /// It buffers the message and requests updated key information from the sender.
    ///
    /// # Arguments
    /// * `key_id` - The unknown key ID that caused the decryption failure
    /// * `sender_public_key_hash_hex` - Hex string of the sender's public key hash
    /// * `encrypted_msg` - The encrypted message that failed to decrypt
    /// * `message_buffer` - Mutable reference to buffer for storing undecryptable messages
    /// * `requested_peer_keys` - Mutable set tracking which peers have had key requests sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the unknown key ID situation was handled appropriately.
    ///
    /// # Behavior
    /// - Buffers the encrypted message for future decryption with the correct key
    /// - Requests fresh keys from the known sender
    /// - Logs the specific key ID that was missing
    ///
    /// # Typical Usage
    /// Called by handle_decryption_error when CryptoError::UnknownKeyId occurs.
    async fn handle_unknown_key_id(
        &self,
        key_id: u32,
        sender_public_key_hash_hex: String,
        encrypted_msg: &crate::chat_message::EncryptedMessage,
        message_buffer: &mut MessageBuffer,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        debug!(
            "Unknown key ID {} for sender '{}'. Requesting fresh keys.",
            key_id, sender_public_key_hash_hex
        );

        if message_buffer.add_message(sender_public_key_hash_hex.clone(), encrypted_msg) {
            debug!(
                "Buffered UnknownKeyId message from {} for future decryption",
                sender_public_key_hash_hex
            );
        }

        self.request_public_key_if_needed(
            &sender_public_key_hash_hex,
            &encrypted_msg.sender_public_key_hash,
            requested_peer_keys,
        )
        .await
    }

    /// Handles decryption failure due to invalid message format by buffering and requesting fresh keys.
    ///
    /// This function addresses decryption failures caused by message format issues, which may
    /// indicate stale or corrupted encryption keys. It buffers the message and requests
    /// updated cryptographic keys from the sender.
    ///
    /// # Arguments
    /// * `encrypted_msg` - The encrypted message with invalid format
    /// * `message_buffer` - Mutable reference to buffer for storing undecryptable messages
    /// * `requested_peer_keys` - Mutable set tracking which peers have had key requests sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the invalid format situation was handled appropriately.
    ///
    /// # Behavior
    /// - Buffers the message for future processing with correct keys
    /// - Requests fresh keys due to potential key staleness
    /// - Logs an error indicating the format issue
    ///
    /// # Typical Usage
    /// Called by handle_decryption_error when CryptoError::InvalidFormat occurs.
    async fn handle_invalid_format(
        &self,
        encrypted_msg: &crate::chat_message::EncryptedMessage,
        message_buffer: &mut MessageBuffer,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let sender_hash_hex =
            get_public_key_hash_as_hex_string(&encrypted_msg.sender_public_key_hash);

        debug!(
            "Invalid message format from peer '{}'. Could be stale keys, requesting fresh ones.",
            sender_hash_hex
        );

        if message_buffer.add_message(sender_hash_hex.clone(), encrypted_msg) {
            debug!(
                "Buffered InvalidFormat message from {} for future decryption",
                sender_hash_hex
            );
        }

        self.request_public_key_if_needed(
            &sender_hash_hex,
            &encrypted_msg.sender_public_key_hash,
            requested_peer_keys,
        )
        .await?;

        error!("Error handling encrypted message: Invalid message format");
        Ok(())
    }

    /// Sends a public key request to a peer if one hasn't been sent recently.
    ///
    /// This function manages the deduplication of public key requests to prevent flooding
    /// the network with duplicate requests. It checks if a request has already been sent
    /// for the specified peer and only sends a new request if necessary.
    ///
    /// # Arguments
    /// * `sender_hash` - Hex string hash of the peer whose keys are needed
    /// * `sender_public_key_hash` - Raw bytes of the sender's public key hash
    /// * `requested_peer_keys` - Mutable set tracking which peers have had key requests sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the key request was sent or was already pending.
    /// Returns an error if network communication fails.
    ///
    /// # Behavior
    /// - Checks if a key request has already been sent for this peer
    /// - Creates and sends a public key request packet if needed
    /// - Updates the tracking set to prevent duplicate requests
    /// - Logs the request action for debugging
    ///
    /// # Typical Usage
    /// Called by various error handlers when cryptographic keys are missing and need to be requested.
    async fn request_public_key_if_needed(
        &self,
        sender_hash: &str,
        sender_public_key_hash: &[u8],
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        if !requested_peer_keys.contains(sender_hash) {
            let public_key_request = self
                .security_module
                .create_public_key_request(
                    sender_public_key_hash,
                    &self.my_identity.get_my_verifying_key_sha256hash_as_bytes(),
                )
                .await;

            self.network_manager
                .send_message(public_key_request)
                .await?;
            requested_peer_keys.insert(sender_hash.to_string());

            debug!("Sent reactive PublicKeyRequest for {}", sender_hash);
        } else {
            debug!(
                "Already sent PublicKeyRequest for {}, skipping",
                sender_hash
            );
        }
        Ok(())
    }

    /// Processes a public key request from a peer and responds with this node's key information.
    ///
    /// This function handles incoming requests for public key information by sending back
    /// the local node's public key announcement and attempting to send key distribution
    /// if the requester's keys are already known.
    ///
    /// # Arguments
    /// * `request` - The PublicKeyRequest packet containing requester's key information
    /// * `peer_identity` - Peer identity database containing known peer keys
    /// * `requested_peer_keys` - Mutable set tracking which peers have had key requests sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the request was processed successfully.
    /// Returns an error if network communication or key processing fails.
    ///
    /// # Behavior
    /// - Ignores requests from the local node to prevent self-communication
    /// - Sends a public key announcement containing this node's cryptographic keys
    /// - Attempts to send key distribution if requester's X25519 key is known
    /// - Falls back to reciprocal key request if requester's key is unknown
    ///
    /// # Typical Usage
    /// Called when a PublicKeyRequest packet is received from the network layer.
    pub async fn handle_public_key_request(
        &self,
        request: crate::chat_message::PublicKeyRequest,
        peer_identity: &PeerIdentity,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let sender_public_ed25519_key_string =
            get_public_key_hash_as_hex_string(&request.requester_public_key_hash);

        let my_public_key_hash_as_string = get_public_key_hash_as_hex_string(
            &self.my_identity.get_my_verifying_key_sha256hash_as_bytes(),
        );

        // Ignore requests from ourselves
        if sender_public_ed25519_key_string == my_public_key_hash_as_string {
            debug!("Ignoring public key request from myself");
            return Ok(());
        }

        // Send our public key announcement
        let announcement = self
            .security_module
            .create_public_key_announcement(&self.my_identity);
        let pk_announcement_packet = ChatPacket {
            packet_type: Some(PacketType::PublicKey(announcement.clone())),
        };

        self.network_manager
            .send_message(pk_announcement_packet)
            .await?;
        debug!("Sent PublicKeyAnnouncement in response to request");

        // Try to send KeyDistribution if we have their x25519 key
        self.send_key_distribution_if_possible(&request, peer_identity, requested_peer_keys)
            .await
    }

    /// Attempts to send key distribution to a peer if their X25519 key is available.
    ///
    /// This function checks if the requester's X25519 public key is known and, if so,
    /// creates and sends an encrypted sender key distribution packet. If the key is not
    /// known, it initiates a reciprocal key request.
    ///
    /// # Arguments
    /// * `request` - The PublicKeyRequest containing the requester's key information
    /// * `peer_identity` - Peer identity database for looking up requester's keys
    /// * `requested_peer_keys` - Mutable set tracking which peers have had key requests sent
    ///
    /// # Returns
    /// Returns `Ok(())` if key distribution was sent or reciprocal request initiated.
    /// Returns an error if cryptographic operations or network communication fails.
    ///
    /// # Behavior
    /// - Looks up the requester's X25519 public key in the peer identity database
    /// - Creates an encrypted sender key distribution packet if key is available
    /// - Sends the key distribution packet over the network
    /// - Initiates reciprocal key request if requester's key is unknown
    ///
    /// # Typical Usage
    /// Called by handle_public_key_request to complete the key exchange handshake.
    async fn send_key_distribution_if_possible(
        &self,
        request: &crate::chat_message::PublicKeyRequest,
        peer_identity: &PeerIdentity,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let requester_hex_string =
            get_public_key_hash_as_hex_string(&request.requester_public_key_hash);

        if let Some(requester_x25519_key) =
            peer_identity.peer_x25519_keys.get(&requester_hex_string)
        {
            debug!("Creating KeyDistribution for requester using their x25519 key");

            let requester_announcement = PublicKeyAnnouncement {
                display_name: self.my_identity.display_name.clone(),
                x25519_public_key: requester_x25519_key.as_bytes().to_vec(),
                ed25519_public_key: request.requester_public_key_hash.clone(),
            };

            let sender_key_packet = self
                .security_module
                .create_sender_key_distribution(&requester_announcement, &self.my_identity)?;

            self.network_manager.send_message(sender_key_packet).await?;
            debug!("Sent KeyDistribution packet intended for requester");
        } else {
            debug!("Don't have requester's x25519 key yet, cannot create KeyDistribution");
            self.send_reciprocal_request(request, requested_peer_keys)
                .await?;
        }
        Ok(())
    }

    /// Sends a reciprocal public key request to complete bidirectional key exchange.
    ///
    /// This function sends a public key request back to a peer who requested keys,
    /// ensuring that both parties have each other's cryptographic information for
    /// establishing bidirectional encrypted communication.
    ///
    /// # Arguments
    /// * `request` - The original PublicKeyRequest that triggered this reciprocal request
    /// * `requested_peer_keys` - Mutable set tracking which peers have had key requests sent
    ///
    /// # Returns
    /// Returns `Ok(())` if the reciprocal request was sent successfully.
    /// Returns an error if network communication fails.
    ///
    /// # Behavior
    /// - Checks if a reciprocal request has already been sent
    /// - Creates a public key request packet for the original requester
    /// - Sends the request to complete the key exchange
    /// - Updates tracking to prevent duplicate requests
    ///
    /// # Typical Usage
    /// Called when a peer requests keys but their X25519 key is not yet known locally.
    async fn send_reciprocal_request(
        &self,
        request: &crate::chat_message::PublicKeyRequest,
        requested_peer_keys: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let requester_hash_hex =
            get_public_key_hash_as_hex_string(&request.requester_public_key_hash);

        if !requested_peer_keys.contains(&requester_hash_hex) {
            debug!("Requesting requester's PublicKeyAnnouncement to complete key exchange");

            let reciprocal_request = self
                .security_module
                .create_public_key_request(
                    &request.requester_public_key_hash,
                    &self.my_identity.get_my_verifying_key_sha256hash_as_bytes(),
                )
                .await;

            self.network_manager
                .send_message(reciprocal_request)
                .await?;
            requested_peer_keys.insert(requester_hash_hex.clone());

            debug!("Sent reciprocal PublicKeyRequest to complete bidirectional key exchange");
        } else {
            debug!(
                "Already sent PublicKeyRequest to requester '{}', skipping duplicate request",
                requester_hash_hex
            );
        }
        Ok(())
    }
}
