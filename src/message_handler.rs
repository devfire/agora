use crate::message::ChatMessage;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, warn};

/// Message handler error types
#[derive(Error, Debug)]
pub enum MessageHandlerError {
    #[error("Channel send error: {0}")]
    ChannelSendError(String),

    #[error("Channel closed")]
    ChannelClosed,
}

/// Message handler that manages MPSC channel communication between UDP intake and output
pub struct MessageHandler {
    /// Agent ID for filtering self-messages
    chat_id: String,
    /// Sender for UDP intake thread to send messages to chat processing thread
    message_sender: mpsc::Sender<ChatMessage>,
    /// Receiver for chat processing thread to receive messages
    message_receiver: Arc<Mutex<mpsc::Receiver<ChatMessage>>>,
}

impl MessageHandler {
    /// Create a new MessageHandler with the specified agent ID and configuration
    pub fn new(chat_id: String, buffer_size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(buffer_size);

        debug!(
            "Created message handler for agent '{}' with buffer size {}",
            chat_id, buffer_size
        );

        Self {
            chat_id,
            message_sender: sender,
            message_receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    /// Get the chat ID
    pub fn chat_id(&self) -> &str {
        &self.chat_id
    }

    /// Try to send a message without blocking (used by UDP intake thread)
    pub fn try_send_message(&self, message: ChatMessage) -> Result<(), MessageHandlerError> {
        match self.message_sender.try_send(message.clone()) {
            Ok(()) => {
                debug!(
                    "Successfully sent message from '{}' to channel (non-blocking) for chat '{}'",
                    message.sender_id, self.chat_id
                );
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(msg)) => {
                let error_msg = format!(
                    "Channel buffer full, dropping message from '{}' for agent '{}'",
                    msg.sender_id, self.chat_id
                );
                warn!("{}", error_msg);
                Err(MessageHandlerError::ChannelSendError(error_msg))
            }
            Err(mpsc::error::TrySendError::Closed(msg)) => {
                let error_msg = format!(
                    "Channel closed, cannot send message from '{}' for agent '{}'",
                    msg.sender_id, self.chat_id
                );
                error!("{}", error_msg);
                Err(MessageHandlerError::ChannelClosed)
            }
        }
    }

    /// Receive a message from the channel (used by chat processing thread)
    /// This method includes self-message filtering
    pub async fn receive_message(&self) -> Result<ChatMessage, MessageHandlerError> {
        let mut receiver = self.message_receiver.lock().await;

        loop {
            match receiver.recv().await {
                Some(message) => {
                    // Filter out self-messages to prevent self-replies
                    if message.sender_id == self.chat_id {
                        debug!(
                            "Filtered out self-message from agent '{}' with content: '{}'",
                            message.sender_id,
                            message.content.chars().take(50).collect::<String>()
                        );
                        continue; // Skip self-messages and continue receiving
                    }

                    debug!(
                        "Received message from '{}' for processing by agent '{}' with content: '{}'",
                        message.sender_id,
                        self.chat_id,
                        message.content.chars().take(50).collect::<String>()
                    );
                    return Ok(message); // Return the received message to processor.rs
                }
                None => {
                    let error_msg = format!("Message channel closed for agent '{}'", self.chat_id);
                    error!("{}", error_msg);
                    return Err(MessageHandlerError::ChannelClosed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_channel_buffer_overflow() {
        // Create a message handler with a small buffer size
        let handler = MessageHandler::new("overflow-agent".to_string(), 2);

        // Fill the buffer
        for i in 0..2 {
            let message = ChatMessage::new("sender".to_string(), format!("Message {}", i));
            let result = handler.try_send_message(message);
            assert!(result.is_ok());
        }

        // Try to send one more message - should fail due to buffer full
        let overflow_message =
            ChatMessage::new("sender".to_string(), "Overflow message".to_string());
        let overflow_result = handler.try_send_message(overflow_message);
        assert!(overflow_result.is_err());

        if let Err(MessageHandlerError::ChannelSendError(msg)) = overflow_result {
            assert!(msg.contains("Channel buffer full"));
        } else {
            panic!("Expected ChannelSendError for buffer overflow");
        }
    }
}
