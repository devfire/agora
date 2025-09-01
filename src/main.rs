use chacha20poly1305::ChaCha20Poly1305;
use clap::Parser;

mod cli;

pub mod identity;

// alias type (ChaCha20Poly1305, [u8; 32]) to SenderKey
type SenderKey = (ChaCha20Poly1305, [u8; 32]);

mod crypto;
mod network;
mod processor;
use crate::{
    chat_message::{ChatPacket, PlaintextPayload},
    cli::ChatArgs,
    crypto::create_public_key_announcement,
    identity::{MyIdentity, PeerIdentity},
    network::{NetworkConfig, NetworkManager},
    processor::Processor,
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
        // Use a default identity path if none provided
        info!("No key file provided, using default identity");
        MyIdentity::new(Path::new("~/.ssh/id_ed25519"), &args.chat_id)?
    };

    debug!("Loaded identity with sender ID: {}", identity.display_name);

    // Initialize peer identity (empty for now, will be populated as we receive messages)
    let peer_identity = PeerIdentity::new();

    // Initialize network manager
    let network_manager = Arc::new(NetworkManager::new(network_config).await?);

    let buffer_size = 1000; // Buffer up to 1000 messages

    let (message_sender, message_receiver) =
        tokio::sync::mpsc::channel::<PlaintextPayload>(buffer_size);

    let processor = Processor::new(Arc::clone(&network_manager), identity, peer_identity);

    // Note the distinct lack of .await here - we want to spawn these tasks and let them run concurrently
    // rather than waiting for each to complete before starting the next.
    // Spawn UDP message intake task
    let udp_intake_handle = processor.spawn_udp_intake_task(message_sender, &args.chat_id);
    debug!("UDP message intake task spawned");

    // Spawn chat processing task, which displays incoming messages from the channel
    let display_handle = processor.spawn_message_display_task(message_receiver, &args.chat_id);
    debug!("Chat processing task spawned");

    // Spawn stdin input task to read user input and send messages
    let stdin_input_handle = processor.spawn_stdin_input_task(&args.chat_id);
    debug!("Stdin input task spawned");

    processor
        .network_manager
        .send_message(create_public_key_announcement(&processor.my_identity).await)
        .await?;

    // Wait for tasks to complete (they run indefinitely)
    // let _result = tokio::try_join!(udp_intake_handle, display_handle, stdin_input_handle)?;
    // tokio::join!(udp_intake_handle, display_handle, stdin_input_handle);
    // Wait for any of the essential tasks to complete.
    // The stdin_input_handle is the only one designed to finish, triggering a shutdown.
    tokio::select! {
        _ = udp_intake_handle => info!("UDP intake task completed unexpectedly."),
        _ = display_handle => info!("Display task completed unexpectedly."),
        _ = stdin_input_handle => info!("Stdin task complete. Shutting down."),
    }

    info!("Chat application shut down.");
    Ok(())
}
