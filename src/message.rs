use prost::Message;
use std::time::{SystemTime, UNIX_EPOCH};

// Include the generated protobuf code
pub mod chat_message {
    include!(concat!(env!("OUT_DIR"), "/agora_proto.rs"));
}

pub use chat_message::ChatMessage;

impl ChatMessage {
    /// Create a new ChatMessage with the current timestamp
    pub fn new(sender_id: String, content: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get current time")
            .as_secs() as i64;

        Self {
            sender_id,
            timestamp,
            content,
        }
    }

    /// Serialize the message to bytes using protobuf
    pub fn serialize(&self) -> Result<Vec<u8>, prost::EncodeError> {
        let mut buf = Vec::new();
        self.encode(&mut buf)?;
        Ok(buf)
    }

    /// Deserialize bytes to ChatMessage using protobuf
    pub fn deserialize(bytes: &[u8]) -> Result<Self, prost::DecodeError> {
        Self::decode(bytes)
    }
}
