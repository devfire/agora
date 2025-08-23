use crate::{message::ChatMessage, message_handler::MessageHandler, network};
use anyhow::bail;
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
    pub async fn spawn_message_display_task(&self) -> JoinHandle<anyhow::Result<()>> {
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
                        bail!("Chat processing task failed: {}", e);
                    }
                }
            }
        })
    }

    /// Spawn UDP message intake task for continuous message reception.
    /// This task receives messages from multicast and sends them to MPSC channel.
    /// MessageHandler will handle the receiving end of the MPSC channel and forward messages back to channel.
    /// Then, receive_message() will trigger the spawn_message_display_task() to print messages to console.
    pub async fn spawn_udp_intake_task(&self) -> JoinHandle<anyhow::Result<()>> {
        let network_manager = Arc::clone(&self.network_manager);
        let message_handler = Arc::clone(&self.message_handler);

        tokio::spawn(async move {
            debug!(
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
                        message_handler.try_send_message(message.clone())?;
                    }
                    Err(network::NetworkError::DeserializationError(e)) => {
                        // Log malformed messages but continue processing
                        warn!("Received malformed message, skipping: {}", e);
                        continue;
                    }
                    Err(e) => {
                        error!("UDP message reception error: {}", e);
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
        debug!("Starting stdin input task for agent '{}'", chat_id);
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let reader = BufReader::new(stdin);
            let mut lines = reader.lines();

            loop {
                // Print prompt to stderr (unbuffered)
                eprint!("{} > ", chat_id);

                if let Some(line) = lines.next_line().await? {
                    if !line.trim().is_empty() {
                        // Create and send user's message
                        let message = ChatMessage::new(chat_id.clone(), line);
                        network_manager.send_message(&message).await?;
                    }
                } else {
                    // EOF reached (Ctrl+D), exit cleanly
                    info!("Received EOF (Ctrl+D), exiting chat application");
                    std::process::exit(0);
                }
            }
            // Ok(())
        })
    }
}
