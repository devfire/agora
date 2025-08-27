use clap::Parser;

mod cli;

mod message;
mod message_handler;
mod network;
mod processor;
use crate::{
    cli::ChatArgs,
    message_handler::MessageHandler,
    network::{NetworkConfig, NetworkManager},
    processor::Processor,
};
use std::sync::Arc;

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

    // Initialize network manager
    let network_manager =
        Arc::new(NetworkManager::new(network_config, args.chat_id.clone()).await?);

    let buffer_size = 100; // Buffer up to 1000 messages

    let message_handler = Arc::new(MessageHandler::new(args.chat_id.clone(), buffer_size));

    let processor = Processor::new(Arc::clone(&message_handler), Arc::clone(&network_manager));

    // Spawn UDP message intake task
    let udp_intake_handle = processor.spawn_udp_intake_task().await;
    debug!("UDP message intake task spawned");

    // Spawn chat processing task, which handles incoming messages from the channel
    let chat_processing_handle = processor.spawn_message_display_task(&args.chat_id).await;
    debug!("Chat processing task spawned");

    // Spawn stdin input task to read user input and send messages
    let stdin_input_handle = processor.spawn_stdin_input_task(&args.chat_id).await;
    debug!("Stdin input task spawned");

    // Wait for tasks to complete (they run indefinitely)
    let _result = tokio::try_join!(
        udp_intake_handle,
        chat_processing_handle,
        stdin_input_handle
    )?;

    Ok(())
}
