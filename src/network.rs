use crate::message::ChatMessage;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};

use thiserror::Error;
use tokio::net::UdpSocket;

/// Network-related error types
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Failed to create socket: {0}")]
    SocketCreation(#[from] std::io::Error),

    #[error("Failed to join multicast group: {0}")]
    MulticastJoin(String),

    #[error("Failed to send message: {0}")]
    SendError(String),

    #[error("Failed to receive message: {0}")]
    ReceiveError(String),

    #[error("Message serialization error: {0}")]
    SerializationError(#[from] prost::EncodeError),

    #[error("Message deserialization error: {0}")]
    DeserializationError(#[from] prost::DecodeError),

    #[error("Invalid network configuration: {0}")]
    ConfigError(String),
}

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
            multicast_address: "239.255.255.250:8080".parse().unwrap(),
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
    pub async fn new(config: NetworkConfig, agent_id: String) -> Result<Self, NetworkError> {
        // Validate multicast address
        if !config.multicast_address.ip().is_multicast() {
            return Err(NetworkError::ConfigError(format!(
                "Address {} is not a valid multicast address",
                config.multicast_address.ip()
            )));
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
    fn create_multicast_socket(
        config: &NetworkConfig,
    ) -> Result<std::net::UdpSocket, NetworkError> {
        // Create socket with socket2 for advanced configuration
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(NetworkError::SocketCreation)?;

        // Enable SO_REUSEADDR to allow multiple agents on the same machine
        socket
            .set_reuse_address(true)
            .map_err(NetworkError::SocketCreation)?;

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
        socket
            .bind(&bind_addr.into())
            .map_err(NetworkError::SocketCreation)?;

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

            socket
                .join_multicast_v4(&multicast_ip, &interface_ip)
                .map_err(|e| {
                    NetworkError::MulticastJoin(format!(
                        "Failed to join multicast group {}:{} on interface {}: {}",
                        multicast_ip,
                        multicast_v4.port(),
                        interface_ip,
                        e
                    ))
                })?;

            tracing::info!(
                "Joined multicast group {}:{} on interface {}",
                multicast_ip,
                multicast_v4.port(),
                interface_ip
            );
        } else {
            return Err(NetworkError::ConfigError(
                "IPv6 multicast not currently supported".to_string(),
            ));
        }

        // Set socket to non-blocking mode for tokio compatibility
        socket
            .set_nonblocking(true)
            .map_err(NetworkError::SocketCreation)?;

        // Convert to std::net::UdpSocket
        Ok(socket.into())
    }

    /// Send a message to the multicast group
    pub async fn send_message(&self, message: &ChatMessage) -> Result<(), NetworkError> {
        // Serialize the message using protobuf
        let serialized = message
            .serialize()
            .map_err(NetworkError::SerializationError)?;

        // Send the serialized message to the multicast address
        match self.socket.send_to(&serialized, self.multicast_addr).await {
            Ok(bytes_sent) => {
                tracing::debug!(
                    "Sent {} bytes to multicast group {} from agent {}",
                    bytes_sent,
                    self.multicast_addr,
                    self.agent_id
                );
                Ok(())
            }
            Err(e) => {
                let error_msg = format!(
                    "Failed to send message from agent {} to {}: {}",
                    self.agent_id, self.multicast_addr, e
                );
                tracing::error!("{}", error_msg);
                Err(NetworkError::SendError(error_msg))
            }
        }
    }

    /// Receive a single message from the multicast group
    pub async fn receive_message(&self) -> Result<ChatMessage, NetworkError> {
        let mut buffer = vec![0u8; self.config.buffer_size];

        match self.socket.recv_from(&mut buffer).await {
            Ok((bytes_received, sender_addr)) => {
                tracing::debug!(
                    "Received {} bytes from {} on client {}",
                    bytes_received,
                    sender_addr,
                    self.agent_id
                );

                // Trim buffer to actual message size
                buffer.truncate(bytes_received);

                // Deserialize the message
                match ChatMessage::deserialize(&buffer) {
                    Ok(message) => {
                        tracing::debug!(
                            "Successfully deserialized message from client {} with content: '{}'",
                            message.sender_id,
                            message.content.chars().take(50).collect::<String>()
                        );
                        Ok(message)
                    }
                    Err(e) => {
                        let error_msg =
                            format!("Failed to deserialize message from {}: {}", sender_addr, e);
                        tracing::warn!("{}", error_msg);
                        Err(NetworkError::DeserializationError(e))
                    }
                }
            }
            Err(e) => {
                let error_msg = format!(
                    "Failed to receive message on agent {}: {}",
                    self.agent_id, e
                );
                tracing::error!("{}", error_msg);
                Err(NetworkError::ReceiveError(error_msg))
            }
        }
    }
}
