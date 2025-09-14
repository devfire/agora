use crate::{
    chat_message::{chat_packet::PacketType, ChatPacket, PlaintextPayload},
    crypto::SecurityLayer,
    identity::{MyIdentity, PeerIdentity},
    message_buffer::MessageBuffer,
    network, packet_handler::PacketHandler,
};

use rustyline::{DefaultEditor, error::ReadlineError};
use std::{collections::HashSet, sync::Arc};

use tokio::sync::mpsc;
use tracing::{debug, error};


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