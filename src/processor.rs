use crate::{
    chat_message::PlaintextPayload,
    identity::{MyIdentity, PeerIdentity},
    network,
};
use anyhow::bail;
use rustyline::{DefaultEditor, error::ReadlineError};
use std::sync::Arc;

use tokio::{sync::mpsc, task::JoinHandle};
use tracing::debug;

pub struct Processor {
    network_manager: Arc<network::NetworkManager>,
    my_identity: MyIdentity,
    peer_identity: PeerIdentity,
}

impl Processor {
    pub fn new(
        network_manager: Arc<network::NetworkManager>,
        my_identity: MyIdentity,
        peer_identity: PeerIdentity,
    ) -> Self {
        Self {
            network_manager,
            my_identity,
            peer_identity,
        }
    }

    /// Display task for printing messages to console. This task is READ ONLY and does not send messages.
    pub async fn spawn_message_display_task(
        &self,
        mut receiver: tokio::sync::mpsc::Receiver<PlaintextPayload>,
        chat_id: &str,
    ) -> JoinHandle<anyhow::Result<()>> {
        // let message_handler = Arc::clone(&self.message_handler);
        let chat_id = chat_id.to_string();

        tokio::spawn(async move {
            debug!("Starting chat processing task for agent '{}'", chat_id);
            while let Some(message) = receiver.recv().await {
                // Filter messages sent by self
                if message.sender_id != chat_id {
                    debug!(
                        "Chat processing received message from '{}' with content: '{}'",
                        message.sender_id,
                        message.content // message.content.chars().take(50).collect::<String>()
                    );

                    // Clear the current prompt line and print the message, then re-display prompt
                    eprint!("\r\x1b[K"); // Carriage return and clear line
                    eprintln!(
                        "{} {}: {}",
                        message.timestamp, message.sender_id, message.content
                    );
                    eprint!("{} > ", chat_id); // Re-display the prompt
                } else {
                    debug!("Ignoring self-sent message from '{}'", message.sender_id);
                }
            }
            Ok(())
        })
    }

    /// Spawn UDP message intake task for continuous message reception.
    /// This task receives messages from multicast and sends them to MPSC channel.
    /// spawn_message_display_task() will handle the receiving end of the MPSC channel and forward messages back to channel.
    /// Then, receive_message() will trigger the spawn_message_display_task() to print messages to console.
    pub async fn spawn_udp_intake_task(
        &self,
        message_sender: mpsc::Sender<PlaintextPayload>,
        chat_id: &str,
    ) -> JoinHandle<anyhow::Result<()>> {
        let network_manager = Arc::clone(&self.network_manager);

        let chat_id = chat_id.to_string(); // Clone chat_id to move into the task
        let peer_identity = self.peer_identity.clone();
        let my_identity = self.my_identity.clone();
        tokio::spawn(async move {
            debug!("Starting UDP message intake task for agent '{}'", chat_id);

            loop {
                match network_manager
                    .receive_message(&my_identity, &peer_identity)
                    .await
                {
                    Ok(message) => {
                        debug!(
                            "UDP intake received message from '{}' with content: '{}'",
                            message.sender_id,
                            message.content // message.content.chars().take(50).collect::<String>()
                        );

                        // Filter messages sent by self
                        if message.sender_id != chat_id {
                            debug!("Sending message from '{}'", message.sender_id);
                            message_sender.send(message.clone()).await?;
                        } else {
                            debug!("Ignoring self-sent message from '{}'", message.sender_id);
                        }
                    }
                    Err(e) => {
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
        let my_identity = self.my_identity.clone();
        debug!("Starting stdin input task for agent '{}'", chat_id);
        tokio::spawn(async move {
            // Initialize rustyline editor for input with history support
            let mut rustyline_editor = DefaultEditor::new()?;

            loop {
                // Print prompt to stderr (unbuffered)
                // eprint!("{} > ", chat_id);
                let readline = rustyline_editor.readline(&format!("{} > ", chat_id));

                let mic_drop = "User has left the chat.".to_string();

                match readline {
                    Ok(line) => {
                        rustyline_editor.add_history_entry(line.as_str())?;
                        network_manager.send_message(&my_identity, &line).await?;
                    }
                    Err(ReadlineError::Interrupted) => {
                        network_manager
                            .send_message(&my_identity, &mic_drop)
                            .await?;
                        std::process::exit(0);
                    }
                    Err(ReadlineError::Eof) => {
                        network_manager
                            .send_message(&my_identity, &mic_drop)
                            .await?;
                        std::process::exit(0);
                    }
                    Err(err) => {
                        println!("Error: {:?}", err);
                        break;
                    }
                }
            }
            Ok(())
        })
    }
}
