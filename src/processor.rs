use crate::{chat::get_chat_input, message::ChatMessage, message_handler::MessageHandler, network};
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

pub struct Processor {
    message_handler: Arc<MessageHandler>,
    network_manager: Arc<network::NetworkManager>,
    chat_id: String,
}

impl Processor {
    pub fn new(
        message_handler: Arc<MessageHandler>,
        network_manager: Arc<network::NetworkManager>,
        chat_id: String,
    ) -> Self {
        Self {
            message_handler,
            network_manager,
            chat_id,
        }
    }

    /// Spawn chat processing task for handling messages and generating responses
    /// This task receives messages from MPSC channel, filters self-messages, and generates LLM responses
    pub async fn spawn_chat_processing_task(&self) -> JoinHandle<Result<(), String>> {
        let message_handler = Arc::clone(&self.message_handler);
        let network_manager = Arc::clone(&self.network_manager);
        let chat_id = self.chat_id.clone();

        tokio::spawn(async move {
            loop {
                match message_handler.receive_message().await {
                    Ok(message) => {
                        debug!(
                            "Chat processing received message from '{}' with content: '{}'",
                            message.sender_id,
                            message.content // message.content.chars().take(50).collect::<String>()
                        );

                        // Get response
                        // let response_content = get_chat_input();
                        println!("{}: {}", message.sender_id, message.content);
                        // println!("{}: {}", chat_id, response_content);

                        // debug!(
                        //     "Sending response to message from '{}': '{}'",
                        //     message.sender_id, response_content
                        // );

                        // Create response message
                        let response_message = ChatMessage::new(chat_id.clone(), "Hi.".to_string());

                        // Broadcast response via network manager
                        network_manager
                            .send_message(&response_message)
                            .await
                            .expect("Failed to send msg");
                    }
                    Err(e) => {
                        error!("Message channel error: {}", e);
                        return Err(format!("LLM processing task failed: {}", e));
                    }
                }
            }
        })
    }

    /// Spawn UDP message intake task for continuous message reception
    /// This task receives messages from UDP multicast and sends them to MPSC channel
    pub async fn spawn_udp_intake_task(&self) -> JoinHandle<Result<(), String>> {
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
                        if let Err(e) = message_handler.try_send_message(message.clone()) {
                            warn!("Failed to send message to channel: {}", e);
                            // Continue processing other messages even if channel is full
                        } else {
                            debug!(
                                "Successfully forwarded message from '{}' to processing channel",
                                message.sender_id
                            );
                        }
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
}
