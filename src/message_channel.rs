use tokio::sync::mpsc;

use crate::message::ChatMessage;

pub struct MessageChannel {
    sender: mpsc::Sender<ChatMessage>,
    chat_id: String,
}

impl MessageChannel {
    pub fn new(chat_id: String, buffer_size: usize) -> (Self, mpsc::Receiver<ChatMessage>) {
        let (sender, receiver) = mpsc::channel(buffer_size);
        let channel = Self { sender, chat_id };
        (channel, receiver)
    }

    pub fn sender(&self) -> mpsc::Sender<ChatMessage> {
        self.sender.clone()
    }

    pub fn chat_id(&self) -> &str {
        &self.chat_id
    }
}
