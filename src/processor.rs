use crate::{
    chat_message::{PlaintextPayload, chat_packet::PacketType},
    crypto::{ReceivedMessage, create_encrypted_chat_packet},
    identity::{MyIdentity, PeerIdentity},
    network,
};
use anyhow::bail;
use rustyline::{DefaultEditor, error::ReadlineError};
use std::{collections::HashMap, sync::Arc};

use tokio::{sync::mpsc, task::JoinHandle};
use tracing::debug;

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
    pub async fn spawn_message_display_task(
        &self,
        mut receiver: tokio::sync::mpsc::Receiver<PlaintextPayload>,
        chat_id: &str,
    ) -> JoinHandle<anyhow::Result<()>> {
        // let message_handler = Arc::clone(&self.message_handler);
        let chat_id = chat_id.to_string();

        tokio::spawn(async move {
            debug!("Starting chat processing task for agent '{}'", chat_id);
            while let Some(message) = receiver.recv().await {
                // Filter messages sent by self
                if message.sender_id != chat_id {
                    debug!(
                        "Chat processing received message from '{}' with content: '{}'",
                        message.sender_id,
                        message.content // message.content.chars().take(50).collect::<String>()
                    );

                    // Clear the current prompt line and print the message, then re-display prompt
                    eprint!("\r\x1b[K"); // Carriage return and clear line
                    eprintln!(
                        "{} {}: {}",
                        message.timestamp, message.sender_id, message.content
                    );
                    eprint!("{} > ", chat_id); // Re-display the prompt
                } else {
                    debug!("Ignoring self-sent message from '{}'", message.sender_id);
                }
            }
            Ok(())
        })
    }

    /// Spawn UDP message intake task for continuous message reception.
    /// This task receives messages from multicast and sends them to MPSC channel.
    /// spawn_message_display_task() will handle the receiving end of the MPSC channel and forward messages back to channel.
    /// Then, receive_message() will trigger the spawn_message_display_task() to print messages to console.
    pub async fn spawn_udp_intake_task(
        &self,
        message_sender: mpsc::Sender<PlaintextPayload>,
        chat_id: &str,
    ) -> JoinHandle<anyhow::Result<()>> {
        let network_manager = Arc::clone(&self.network_manager);

        let chat_id = chat_id.to_string(); // Clone chat_id to move into the task
        let mut peer_identity = self.peer_identity.clone();
        let mut my_identity = self.my_identity.clone();
        tokio::spawn(async move {
            debug!("Starting UDP message intake task for agent '{}'", chat_id);

            loop {
                match network_manager
                    .receive_message(&my_identity, &peer_identity)
                    .await
                {
                    Ok(message) => {
                        match message {
                            ReceivedMessage::ChatPacket(packet) => {
                                debug!("Received ChatPacket: {:?}", packet);
                                match packet.packet_type {
                                    Some(PacketType::PublicKey(announcement)) => {
                                        debug!(
                                            "Received PublicKeyAnnouncement from '{}'",
                                            announcement.user_id
                                        );
                                        // Add peer keys to peer identity
                                        // TODO: Filter out self-sent announcements
                                        peer_identity.add_peer_keys(
                                            announcement.user_id.clone(),
                                            &announcement.x25519_public_key,
                                            &announcement.ed25519_public_key,
                                        )?;

                                        // Now, let's create a PlaintextPayload to announce the new user
                                        let payload = PlaintextPayload {
                                            sender_id: announcement.user_id.clone(),
                                            content: format!(
                                                "{} has joined the chat.",
                                                &announcement.user_id
                                            ),
                                            timestamp: std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)?
                                                .as_secs(),
                                        };
                                        // Forward the announcement to the message display task
                                        if payload.sender_id != chat_id {
                                            debug!(
                                                "Forwarding announcement from '{}'",
                                                payload.sender_id
                                            );
                                            message_sender.send(payload).await?;
                                        } else {
                                            debug!(
                                                "Ignoring self-sent announcement from '{}'",
                                                payload.sender_id
                                            );
                                        }
                                    }
                                    Some(PacketType::KeyDist(_key_dist)) => {
                                        debug!("Received KeyDistribution packet");
                                        // Handle KeyDistribution if needed
                                    }
                                    _ => {
                                        debug!("Received other ChatPacket type");
                                    }
                                }
                                // Handle ChatPacket if needed
                            }
                            ReceivedMessage::PlaintextPayload(payload) => {
                                debug!("Received PlaintextPayload: {:?}", payload);
                                // Forward the plaintext payload to the message display task
                                // Filter messages sent by self
                                if payload.sender_id != chat_id {
                                    debug!("Forwarding message from '{}'", payload.sender_id);
                                    message_sender.send(payload.clone()).await?;
                                } else {
                                    debug!(
                                        "Ignoring self-sent message from '{}'",
                                        payload.sender_id
                                    );
                                }
                            }
                            ReceivedMessage::PeerSenderKey(peer_sender_key) => {
                                debug!(
                                    "Received PeerSenderKey for sender '{}', key_id {}",
                                    peer_sender_key.sender_key, peer_sender_key.key_id
                                );

                                // Update peer_identity with the new sender key
                                peer_identity
                                    .peer_sender_keys
                                    .entry(peer_sender_key.sender_key.to_string())
                                    .or_insert_with(HashMap::new)
                                    .insert(peer_sender_key.key_id, peer_sender_key.sender_cipher);
                            }
                        }
                    }
                    Err(e) => {
                        bail!("UDP intake task failed: {}", e);
                    }
                }
            }
        })
    }

    /// Spawn a task to handle user input from stdin.
    /// This task reads lines from stdin and sends them as messages to the network manager for multicasting out.
    pub async fn spawn_stdin_input_task(&self, chat_id: &str) -> JoinHandle<anyhow::Result<()>> {
        let network_manager = Arc::clone(&self.network_manager);

        let chat_id = chat_id.to_string(); // Clone chat_id to move into the task
        let my_identity = self.my_identity.clone();
        debug!("Starting stdin input task for agent '{}'", chat_id);
        tokio::spawn(async move {
            // Initialize rustyline editor for input with history support
            let mut rustyline_editor = DefaultEditor::new()?;

            // Message to send when user exits
            let mic_drop = "User has left the chat.".to_string();
            loop {
                // Print prompt to stderr (unbuffered)
                // eprint!("{} > ", chat_id);
                let readline = rustyline_editor.readline(&format!("{} > ", chat_id));

                match readline {
                    Ok(line) => {
                        rustyline_editor.add_history_entry(line.as_str())?;

                        // Create and send the chat message
                        debug!("Stdin input read line: {}", line);

                        let encrypted_packet = create_encrypted_chat_packet(&line, &my_identity)?;
                        network_manager.send_message(encrypted_packet).await?;
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        let encrypted_packet_bye_bye =
                            create_encrypted_chat_packet(&mic_drop, &my_identity)?;
                        network_manager
                            .send_message(encrypted_packet_bye_bye)
                            .await?;
                        std::process::exit(0);
                    }

                    Err(err) => {
                        println!("Error: {:?}", err);
                        break;
                    }
                }
            }
            Ok(())
        })
    }
}
