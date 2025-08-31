use crate::{
    ChatPacket,
    chat_message::chat_packet::PacketType,
    crypto::{PeerSenderKey, ReceivedMessage, decrypt_message},
    identity::{MyIdentity, PeerIdentity},
};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::Aead};
use prost::Message;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::error;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;

use anyhow::{Result, anyhow, bail};

/// Configuration for network operations
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub multicast_address: SocketAddr,
    pub interface: Option<String>,
    pub buffer_size: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            multicast_address: "239.255.255.250:8080".parse().unwrap(), // unwrap ok because this will never fail
            interface: None,
            buffer_size: 65536, // 64KB buffer
        }
    }
}

/// Manages UDP multicast networking for communicating with other chat clients
pub struct NetworkManager {
    socket: UdpSocket,
    multicast_addr: SocketAddr,
    config: NetworkConfig,
}

impl NetworkManager {
    /// Create a new NetworkManager with the specified configuration
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        // Validate multicast address
        if !config.multicast_address.ip().is_multicast() {
            bail!(
                "Address {} is not a valid multicast address",
                config.multicast_address.ip()
            );
        }

        // Create the UDP socket using socket2 for advanced configuration
        let socket = Self::create_multicast_socket(&config)?;

        // Convert to tokio UdpSocket
        let tokio_socket = UdpSocket::from_std(socket)?;

        let manager = Self {
            socket: tokio_socket,
            multicast_addr: config.multicast_address,
            config,
        };

        Ok(manager)
    }

    /// Create and configure a UDP socket for multicast operations
    fn create_multicast_socket(config: &NetworkConfig) -> Result<std::net::UdpSocket> {
        // Create socket with socket2 for advanced configuration
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // Enable SO_REUSEADDR to allow multiple agents on the same machine
        socket.set_reuse_address(true)?;

        // On Unix systems, also set SO_REUSEPORT if available
        #[cfg(unix)]
        {
            if let Err(e) = socket.set_reuse_port(true) {
                tracing::warn!("Failed to set SO_REUSEPORT: {}", e);
            }
        }

        // Bind to the multicast address
        let bind_addr = SocketAddr::new(
            std::net::Ipv4Addr::UNSPECIFIED.into(),
            config.multicast_address.port(),
        );
        socket.bind(&bind_addr.into())?;

        // Join the multicast group
        if let SocketAddr::V4(multicast_v4) = config.multicast_address {
            let multicast_ip = *multicast_v4.ip();

            // Determine the interface to use
            let interface_ip = if let Some(ref interface_str) = config.interface {
                // Try to parse as IP address first
                interface_str
                    .parse::<Ipv4Addr>()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
            } else {
                Ipv4Addr::UNSPECIFIED
            };

            socket.join_multicast_v4(&multicast_ip, &interface_ip)?;

            tracing::debug!(
                "Joined multicast group {}:{} on interface {}",
                multicast_ip,
                multicast_v4.port(),
                interface_ip
            );
        } else {
            bail!("IPv6 multicast not currently supported".to_string(),);
        }

        // Set socket to non-blocking mode for tokio compatibility
        socket.set_nonblocking(true)?;

        // Convert to std::net::UdpSocket
        Ok(socket.into())
    }

    /// Send a message to the multicast group
    pub async fn send_message(&self, packet: ChatPacket) -> Result<()> {
        tracing::info!("Sending packet: {:?}", packet);
        if let Some(packet_to_send) = packet.packet_type {
            // Serialize the packet to bytes
            let packet_bytes = ChatPacket {
                packet_type: Some(packet_to_send),
            }
            .encode_to_vec();
            self.socket
                .send_to(&packet_bytes, self.multicast_addr)
                .await?;
            Ok(())
        } else {
            error!("Attempted to send empty packet");
            bail!("Empty packet cannot be sent");
        }
    }

    /// Receive a single message from the multicast group
    pub async fn receive_message(
        &self,
        my_identity: &MyIdentity,
        peer_identity: &PeerIdentity,
    ) -> Result<ReceivedMessage> {
        let mut buffer = vec![0u8; self.config.buffer_size];

        let (len, _) = self.socket.recv_from(&mut buffer).await?;
        // Deserialize the received bytes into a ChatPacket
        let packet = ChatPacket::decode(&buffer[..len])?;

        match packet.packet_type {
            Some(PacketType::PublicKey(announcement)) => {
                // Public keys are not encrypted.
                // Return them to the processor as-is for handling.
                let pk_packet = ChatPacket {
                    packet_type: Some(PacketType::PublicKey(announcement)),
                };
                Ok(ReceivedMessage::ChatPacket(pk_packet))
            }

            Some(PacketType::KeyDist(key_dist)) => {
                // Handle key distribution
                // Get the other peers sender key and add to peer_identity
                if key_dist.recipient_id != my_identity.my_sender_id {
                    // Ignore key distributions not intended for me
                    return Err(anyhow!("This key distribution not intended for me"));
                }

                let sender_x25519_public = peer_identity
                    .peer_x25519_keys
                    .get(key_dist.recipient_id.as_str())
                    .ok_or_else(|| anyhow!("Unknown sender: {}", key_dist.recipient_id))?;

                if key_dist.encrypted_sender_key.len() < 12 {
                    return Err(anyhow!("Encrypted data too short"));
                }

                // Extract nonce and encrypted key
                let (nonce_bytes, encrypted_key) = key_dist.encrypted_sender_key.split_at(12);
                let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

                // Perform ECDH to get shared secret
                let shared_secret = my_identity
                    .x25519_secret_key
                    .diffie_hellman(sender_x25519_public);

                // Use shared secret as decryption key
                let key = chacha20poly1305::Key::from_slice(shared_secret.as_bytes());
                let cipher = ChaCha20Poly1305::new(key);

                let decrypted_key = cipher
                    .decrypt(nonce, encrypted_key)
                    .map_err(|e| anyhow!("Creating the decrypted_key failed: {}", e))?;

                if decrypted_key.len() != 32 {
                    return Err(anyhow!("Invalid sender key length"));
                }

                let sender_key = Key::from_slice(&decrypted_key);
                let sender_cipher = ChaCha20Poly1305::new(sender_key);

                // Construct the sender key enum and return to processor
                let peer_sender_key: ReceivedMessage =
                    ReceivedMessage::PeerSenderKey(PeerSenderKey {
                        sender_key: key_dist.sender_id.clone(),
                        key_id: key_dist.key_id,
                        sender_cipher,
                    });

                // Return the sender key to the processor for updating peer_identity
                return Ok(peer_sender_key);
            }
            Some(PacketType::EncryptedMsg(encrypted_msg)) => {
                // Handle encrypted message
                let plaintext = decrypt_message(
                    &encrypted_msg.sender_id,
                    encrypted_msg.key_id,
                    &encrypted_msg.encrypted_payload,
                    &encrypted_msg.nonce,
                    &peer_identity,
                )?;
                Ok(ReceivedMessage::PlaintextPayload(plaintext))

                // if encrypted_msg.sender_id != my_identity.my_sender_id {
                //     match decrypt_message(
                //         &encrypted_msg.sender_id,
                //         encrypted_msg.key_id,
                //         &encrypted_msg.encrypted_payload,
                //         &encrypted_msg.nonce,
                //         &peer_identity,
                //     ) {
                //         Ok(payload) => Ok(ReceivedMessage::PlaintextPayload(payload)),
                //         Err(_) => {
                //             bail!(
                //                 "(encrypted message from {} - no key)",
                //                 encrypted_msg.sender_id
                //             );
                //         }
                //     }
                // } else {
                //     // Ignore messages sent by self
                //     Err(anyhow!("Ignoring self-sent message"))
                // }
            }
            None => todo!(),
        }
    }
}
