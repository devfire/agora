# Agora - A Fully Decentralized Chat System

Agora is a fully decentralized chat system communicating over UDP multicast.

## Overview

## Development

### Running Tests

To run the test suite, use the following command:

```sh
cargo test
```

### Building the Protocol Buffers

The project uses Protocol Buffers for message serialization. If you modify the `.proto` files, you'll need to rebuild the generated Rust code:

```sh
cargo build
```

## Message Flow Architecture

The following diagram illustrates how messages traverse through the Agora chat system:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    AGORA MESSAGE FLOW                                │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Chat Client A  │         │  Chat Client B  │         │  Chat Client C  │
│                 │         │                 │         │                 │
│ [NetworkManager]│◄────────┤ [NetworkManager]├────────►│ [NetworkManager]│
└─────────────────┘         └─────────────────┘         └─────────────────┘
         │                           │                           │
         │          UDP Multicast    │                           │
         │       239.255.255.250     │                           │
         │           :8080           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     │
                              ╔══════▼══════╗
                              ║   NETWORK   ║
                              ║  MULTICAST  ║
                              ║    LAYER    ║
                              ╚═════════════╝

────────────────────────────── SINGLE CHAT APP DETAIL ────────────────────────────

┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CHAT INTERNAL FLOW                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────┐
    │    main()   │
    └──────┬──────┘
           │ 1. Initialize components
           ▼
    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
    │NetworkManager│    │MessageHandler│    │ Processor   │
    └──────────────┘    └──────────────┘    └─────────────┘
           │                    │                 │
           │                    │ 2. Spawn tasks  │
           │                    │                 ▼
           │                    │          ┌─────────────┐
           │                    │          │   Task 1:   │
           │                    │          │ UDP Intake  │
           │                    │          └─────────────┘
           │                    │                 │
           │                    │                 ▼
           │                    │          ┌─────────────┐
           │                    │          │   Task 2:   │
           │                    │          │Chat Process │
           │                    │          └─────────────┘

────────────────────────────── MESSAGE FLOW STEPS ──────────────────────────────

INCOMING MESSAGE FLOW:
┌─┐
│1│ UDP Multicast Message Received
└─┘         │
            ▼
     ┌─────────────────┐
     │  NetworkManager │
     │  .receive_msg() │  ◄── BLOCKS on socket.recv_from().await
     └─────────────────┘       (async cooperative blocking)
            │ Deserializes protobuf
            ▼
┌─┐  ┌─────────────────┐
│2│  │ UDP Intake Task │  ◄── Runs in continuous loop
└─┘  │ (processor.rs)  │       Awaits UDP socket data
     └─────────────────┘
            │
            ▼
     ┌─────────────────┐
     │ MessageHandler  │
     │.try_send_msg()  │  ◄── Non-blocking send to MPSC channel
     └─────────────────┘       (Drops if buffer full)
            │
            ▼
     ┌─────────────────┐
     │ MPSC Channel    │  ◄── Buffered queue (default: 100 messages)
     │   (Tokio)       │
     └─────────────────┘
            │
            ▼
┌─┐  ┌─────────────────┐
│3│  │Chat Process Task│  ◄── Runs in continuous loop
└─┘  │ (processor.rs)  │       BLOCKS on channel receive
     └─────────────────┘
            │
            ▼
     ┌─────────────────┐
     │ MessageHandler  │
     │ .receive_msg()  │  ◄── BLOCKS on channel.recv().await
     └─────────────────┘       Filters out self-messages
            │
            ▼
     ┌─────────────────┐
     │ Message Filter  │  ◄── if msg.sender_id == self.chat_id: skip
     │  (Self-filter)  │       (continues loop if self-message)
     └─────────────────┘
            │
            ▼
┌─┐       │
│4│ ┌─────▼──────┐
└─┘ │Display Msg │
    └────────────┘
            │
            ▼
    ┌─────────────────┐
    │  get_chat_input │  ◄── BLOCKS on stdin.read_line()
    │   (chat.rs)     │       (synchronous blocking)
    └─────────────────┘
            │
            ▼

OUTGOING MESSAGE FLOW:
┌─┐  ┌─────────────────┐
│5│  │Create Response  │
└─┘  │  ChatMessage    │  ◄── ChatMessage::new(chat_id, input)
     └─────────────────┘
            │
            ▼
     ┌─────────────────┐
     │  NetworkManager │
     │  .send_msg()    │  ◄── Serializes to protobuf
     └─────────────────┘
            │
            ▼
┌─┐  ┌─────────────────┐
│6│  │ UDP Multicast   │  ◄── Broadcast to all agents
└─┘  │   Broadcast     │
     └─────────────────┘

────────────────────────────── KEY COMPONENTS ──────────────────────────────

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                COMPONENT DETAILS                               │
└─────────────────────────────────────────────────────────────────────────────────┘

NetworkManager:
├── Uses socket2 for advanced UDP configuration
├── SO_REUSEADDR + SO_REUSEPORT for multiple agents per machine
├── Joins IPv4 multicast group (239.255.255.250:8080 default)
├── Serializes/deserializes messages using protobuf
└── 64KB buffer for message reception

MessageHandler:
├── MPSC channel with configurable buffer (default: 100)
├── Non-blocking try_send() for UDP intake
├── Blocking receive() with self-message filtering
├── Thread-safe using Arc<Mutex<Receiver>>
└── Handles buffer overflow gracefully

Processor:
├── Orchestrates two independent async tasks
├── UDP Intake Task: Network → Channel (continuous)
├── Chat Process Task: Channel → Response (continuous)
└── Both tasks run concurrently using tokio::spawn

ChatMessage (protobuf):
├── sender_id: String (agent identifier)
├── timestamp: int64 (Unix timestamp)
├── content: String (message payload)
└── Automatic serialization/deserialization

Error Handling:
├── Network errors: Continue processing other messages
├── Deserialization errors: Log and skip malformed messages
├── Channel buffer full: Drop messages with warning
├── Self-message filtering: Prevents infinite loops
└── Graceful degradation on component failures
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.