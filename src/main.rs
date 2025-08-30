use chacha20poly1305::ChaCha20Poly1305;
use clap::Parser;

mod cli;

pub mod identity;

// alias type (ChaCha20Poly1305, [u8; 32]) to SenderKey
type SenderKey = (ChaCha20Poly1305, [u8; 32]);

mod network;
mod processor;
mod crypto;
use crate::{
    cli::ChatArgs, identity::MyIdentity, network::{NetworkConfig, NetworkManager}, processor::Processor
};

// Include the generated protobuf code
pub mod chat_message {
    include!(concat!(env!("OUT_DIR"), "/agora_proto.rs"));
}

use std::{path::Path, sync::Arc};

use tracing::{Level, debug, error, info};

use tracing_subscriber;

/// This application initializes the chat client, sets up logging, and starts the network listener.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command-line arguments
    let args = ChatArgs::parse();

    // Initialize tracing subscriber for logging (needed for validation errors)
    tracing_subscriber::fmt()
        .with_max_level(args.log_level.parse::<Level>().unwrap_or(Level::INFO))
        // Include thread IDs only if log level is debug or trace
        .with_thread_ids(args.log_level == "debug" || args.log_level == "trace")
        .with_thread_names(args.log_level == "debug" || args.log_level == "trace")
        .with_file(args.log_level == "debug" || args.log_level == "trace")
        .with_line_number(args.log_level == "debug" || args.log_level == "trace")
        .init();

    // Validate arguments
    if let Err(e) = args.validate() {
        error!("Error: {}", e);
        std::process::exit(1);
    }

    info!(
        "Starting chat '{}' with multicast address {}",
        args.chat_id, args.multicast_address
    );

    // Create network configuration
    let network_config = NetworkConfig {
        multicast_address: args.multicast_address.clone(),
        interface: args.interface.clone(),
        buffer_size: 65536, // 64KB buffer for better performance
    };

    // Load identity from SSH key file supplied or use default
    let identity = if let Some(key_path) = args.key_file.as_ref() {
        MyIdentity::new(key_path, &args.chat_id)?
    } else {
        // Use a default identity (for testing/demo purposes)
        info!("No key file provided, using default identity");
        MyIdentity::new(Path::new("~/.ssh/id_ed25519"), &args.chat_id)?
    };

    // Initialize network manager
    let network_manager =
        Arc::new(NetworkManager::new(network_config, args.chat_id.clone()).await?);

    let buffer_size = 1000; // Buffer up to 1000 messages

    // Initialize message handler. This sets up the MPSC channel for inter-task communication.
    // let message_handler = Arc::new(MessageHandler::new(args.chat_id.clone(), buffer_size));

    // let (channel, receiver) = MessageChannel::new(args.chat_id.clone(), buffer_size);
    let (message_sender, message_receiver) = tokio::sync::mpsc::channel::<ChatMessage>(buffer_size);

    let processor = Processor::new(Arc::clone(&network_manager), identity);

    // Spawn UDP message intake task
    let udp_intake_handle = processor
        .spawn_udp_intake_task(message_sender, &args.chat_id)
        .await;
    debug!("UDP message intake task spawned");

    // Spawn chat processing task, which displays incoming messages from the channel
    let display_handle = processor
        .spawn_message_display_task(message_receiver, &args.chat_id)
        .await;
    debug!("Chat processing task spawned");

    // Spawn stdin input task to read user input and send messages
    let stdin_input_handle = processor.spawn_stdin_input_task(&args.chat_id).await;
    debug!("Stdin input task spawned");

    // Wait for tasks to complete (they run indefinitely)
    let _result = tokio::try_join!(udp_intake_handle, display_handle, stdin_input_handle)?;

    // Use tokio::select! for clean shutdown
    // tokio::select! {
    //     result = udp_intake_handle => result??,
    //     result = stdin_input_handle => result??,
    //     result = chat_processing_handle => result??,
    //     _ = tokio::signal::ctrl_c() => {
    //         info!("Shutting down gracefully...");
    //     }
    // }

    Ok(())
}
