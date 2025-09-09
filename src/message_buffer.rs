use std::collections::{HashMap, VecDeque};

use crate::chat_message::EncryptedMessage;

pub struct MessageBuffer {
    pending_by_sender: HashMap<String, VecDeque<EncryptedMessage>>,
    total_messages: usize,
}

impl MessageBuffer {
    const MAX_PER_SENDER: usize = 5;
    const MAX_TOTAL: usize = 50;

    pub fn new() -> Self {
        Self {
            pending_by_sender: HashMap::new(),
            total_messages: 0,
        }
    }

    pub fn add_message(&mut self, sender_hash: String, msg: &EncryptedMessage) -> bool {
        // Reject if at global limit
        if self.total_messages >= Self::MAX_TOTAL {
            return false;
        }

        let queue = self.pending_by_sender.entry(sender_hash).or_default();

        // Drop oldest if sender at limit
        if queue.len() >= Self::MAX_PER_SENDER {
            queue.pop_front();
            self.total_messages -= 1;
        }

        // Add new message
        queue.push_back(msg.clone());
        self.total_messages += 1;

        true
    }

    pub fn take_sender_messages(&mut self, sender_hash: &str) -> Vec<EncryptedMessage> {
        if let Some(queue) = self.pending_by_sender.remove(sender_hash) {
            self.total_messages -= queue.len();
            queue.into()
        } else {
            Vec::new()
        }
    }
}
