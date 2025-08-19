// This module accepts messages from stdin
use std::io;

use thiserror::Error;

use crate::message::ChatMessage;

/// Chat error types
#[derive(Error, Debug)]
pub enum ChatError {
    #[error("Failed to receive proper input: {0}")]
    ChatInputError(String),
}

pub fn get_chat_input(chat_id: &str) -> Result<ChatMessage, ChatError> {
    // accept input from stdin and send it to the message handler
    // Create a new, mutable String to store the input
    let mut input = String::new();

    // Read a line from standard input and place it into our 'input' variable
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    // Trim the input to remove any trailing newline characters
    let trimmed_input = input.trim();

    // // Check if the input is empty
    // if trimmed_input.is_empty() {
    //     println!("No input provided. Please enter a message.");
    //     return;

    let chat_message = ChatMessage::new(chat_id.to_string(), trimmed_input.to_string());

    // Return the chat message
    Ok(chat_message)
}
