use chacha20poly1305::ChaCha20Poly1305;
use clap::Parser;

mod cli;

pub mod identity;

// alias type (ChaCha20Poly1305, [u8; 32]) to SenderKey
type SenderKey = (ChaCha20Poly1305, [u8; 32]);

mod crypto;
mod message_buffer;
mod network;
mod processor;

use crate::{
    chat_message::{ChatPacket, PlaintextPayload, chat_packet::PacketType},
    cli::ChatArgs,
    crypto::SecurityLayer,
    identity::{MyIdentity, PeerIdentity},
    network::{NetworkConfig, NetworkManager},
    processor::Processor,
};

// Include the generated protobuf code
pub mod chat_message {
    include!(concat!(env!("OUT_DIR"), "/agora_proto.rs"));
}

use std::{path::Path, sync::Arc};

use tracing::{Level, debug, error};

/// This application initializes the chat client, sets up logging, and starts the network listener.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command-line arguments
    let args = ChatArgs::parse();

    // a bit of hack but rustyline cannot go to debug, it pumps out mad amount of info.
    // sorry, rustyline :)
    let filter_directives = format!("{}{}", args.log_level, ",rustyline=info");

    debug!("My tracing filter directives: {}", filter_directives);

    let security_impl = 

    // Initialize tracing subscriber for logging (needed for validation errors)
    tracing_subscriber::fmt()
        .with_max_level(args.log_level.parse::<Level>().unwrap_or(Level::INFO))
        // Include thread IDs only if log level is debug or trace
        .with_thread_ids(args.log_level == "debug" || args.log_level == "trace")
        .with_thread_names(args.log_level == "debug" || args.log_level == "trace")
        .with_file(args.log_level == "debug" || args.log_level == "trace")
        .with_line_number(args.log_level == "debug" || args.log_level == "trace")
        .with_env_filter(filter_directives)
        .init();

    // Validate arguments
    if let Err(e) = args.validate() {
        error!("Error: {}", e);
        std::process::exit(1);
    }

    debug!(
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
        debug!("No key file provided, using default identity");
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

    let initial_public_key_announcement =
        create_public_key_announcement(&processor.my_identity).await;

    // put it into a packet
    let public_key_announcement_packet = ChatPacket {
        packet_type: Some(PacketType::PublicKey(initial_public_key_announcement)),
    };

    processor
        .network_manager
        .send_message(public_key_announcement_packet)
        .await?;

    // Wait for tasks to complete (they run indefinitely)
    // The stdin_input_handle is the only one designed to finish, triggering a shutdown.
    tokio::select! {
        _ = udp_intake_handle => debug!("UDP intake task completed unexpectedly."),
        _ = display_handle => debug!("Display task completed unexpectedly."),
        _ = stdin_input_handle => debug!("Stdin task complete. Shutting down."),
    }

    debug!("Chat application shut down.");
    Ok(())
}
