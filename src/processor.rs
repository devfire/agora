use crate::{message::ChatMessage, message_handler::MessageHandler, network};
use std::sync::Arc;

use tokio::{
    io::{AsyncBufReadExt, BufReader},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};

pub struct Processor {
    message_handler: Arc<MessageHandler>,
    network_manager: Arc<network::NetworkManager>,
}

impl Processor {
    pub fn new(
        message_handler: Arc<MessageHandler>,
        network_manager: Arc<network::NetworkManager>,
    ) -> Self {
        Self {
            message_handler,
            network_manager,
        }
    }

    /// Display task for printing messages to console. This task is READ ONLY and does not send messages.
    pub async fn spawn_message_display_task(&self) -> JoinHandle<Result<(), String>> {
        let message_handler = Arc::clone(&self.message_handler);

        tokio::spawn(async move {
            loop {
                match message_handler.receive_message().await {
                    Ok(message) => {
                        debug!(
                            "Chat processing received message from '{}' with content: '{}'",
                            message.sender_id,
                            message.content // message.content.chars().take(50).collect::<String>()
                        );

                        println!("{}: {}", message.sender_id, message.content);
                        // println!("{}: {}", chat_id, response_content);
                    }
                    Err(e) => {
                        error!("Message channel error: {}", e);
                        return Err(format!("Chat processing task failed: {}", e));
                    }
                }
            }
        })
    }

    /// Spawn UDP message intake task for continuous message reception
    /// This task receives messages from UDP multicast and sends them to MPSC channel
    pub async fn spawn_udp_intake_task(&self) -> JoinHandle<anyhow::Result<(), String>> {
        let network_manager = Arc::clone(&self.network_manager);
        let message_handler = Arc::clone(&self.message_handler);

        tokio::spawn(async move {
            info!(
                "Starting UDP message intake task for agent '{}'",
                message_handler.chat_id()
            );

            loop {
                match network_manager.receive_message().await {
                    Ok(message) => {
                        debug!(
                            "UDP intake received message from '{}' with content: '{}'",
                            message.sender_id,
                            message.content // message.content.chars().take(50).collect::<String>()
                        );

                        // Send message to MPSC channel (non-blocking)
                        message_handler
                            .try_send_message(message.clone())
                            .map_err(|e| e.to_string())?;
                    }
                    Err(network::NetworkError::DeserializationError(e)) => {
                        // Log malformed messages but continue processing
                        warn!("Received malformed message, skipping: {}", e);
                        continue;
                    }
                    Err(e) => {
                        error!("UDP message reception error: {}", e);
                        return Err(format!("UDP intake task failed: {}", e));
                    }
                }
            }
        })
    }

    /// Spawn a task to handle user input from stdin.
    /// This task reads lines from stdin and sends them as messages to the network manager.
    pub async fn spawn_stdin_input_task(&self, chat_id: &str) -> JoinHandle<Result<(), String>> {
        let network_manager = Arc::clone(&self.network_manager);

        let chat_id = chat_id.to_string(); // Clone chat_id to move into the task
        debug!("Starting stdin input task for agent '{}'", chat_id);
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let reader = BufReader::new(stdin);
            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
                if !line.trim().is_empty() {
                    // Create and send user's message
                    let message = ChatMessage::new(chat_id.clone(), line);
                    network_manager
                        .send_message(&message)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
            Ok(())
        })
    }
}
