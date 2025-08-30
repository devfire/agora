use crate::{
    chat_message::{chat_packet::{self, PacketType}, EncryptedMessage}, crypto::encrypt_message, identity::{self, MyIdentity}, ChatPacket
};
use prost::Message;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use tracing_subscriber::layer::Identity;

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

/// Manages UDP multicast networking for agent communication
pub struct NetworkManager {
    socket: UdpSocket,
    multicast_addr: SocketAddr,
    agent_id: String,
    config: NetworkConfig,
}

impl NetworkManager {
    /// Create a new NetworkManager with the specified configuration
    pub async fn new(config: NetworkConfig, agent_id: String) -> Result<Self> {
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
            agent_id,
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
    pub async fn send_message(&self, identity: &MyIdentity, content: &str) -> Result<()> {
        let (encrypted_payload, nonce) = encrypt_message(content, &identity)?;

        let encrypted_msg = EncryptedMessage {
            sender_id: identity.my_sender_id.to_string(),
            key_id: identity.current_key_id,
            encrypted_payload,
            nonce,
        };

        let packet = ChatPacket {
            packet_type: Some(PacketType::EncryptedMsg(encrypted_msg)),
        };

        let packet_bytes = packet.encode_to_vec();
        self.socket
            .send_to(&packet_bytes, self.multicast_addr)
            .await?;

        println!("You: {}", content);
        Ok(())
    }

    /// Receive a single message from the multicast group
    pub async fn receive_message(&self, identity: &MyIdentity) -> Result<ChatPacket> {
        let mut buffer = vec![0u8; self.config.buffer_size];

        let (len, _) = self.socket.recv_from(&mut buffer).await?;

        let packet = ChatPacket::decode(&buffer[..len])?;

        match packet.packet_type {
            Some(PacketType::PublicKey(announcement)) => {
               todo!()
            }

            Some(PacketType::KeyDist(key_dist)) => {
                todo!()
            }

            Some(PacketType::EncryptedMsg(encrypted_msg)) => {
                if encrypted_msg.sender_id != identity.my_sender_id {
                    match decrypt_message(
                        &encrypted_msg.sender_id,
                        encrypted_msg.key_id,
                        &encrypted_msg.encrypted_payload,
                        &encrypted_msg.nonce,
                    ) {
                        Ok(content) => {
                            println!("{}: {}", encrypted_msg.sender_id, content);
                        }
                        Err(_) => {
                            println!(
                                "(encrypted message from {} - no key)",
                                encrypted_msg.sender_id
                            );
                        }
                    }
                }
            }
            None => todo!(),
        }
    }
}
