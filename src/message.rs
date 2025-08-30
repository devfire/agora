use prost::Message;
use std::time::{SystemTime, UNIX_EPOCH};

// Include the generated protobuf code
pub mod chat_message {
    include!(concat!(env!("OUT_DIR"), "/agora_proto.rs"));
}

pub use chat_message::ChatMessage;

impl ChatMessage {

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
