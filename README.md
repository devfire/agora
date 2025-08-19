# Agora - A Fully Decentralized Chat System

Agora is a fully decentralized chat system communicating over UDP multicast.

## Overview

Agora allows multiple clients to communicate with each other in a peer-to-peer fashion without a central server. Messages are broadcasted to a multicast group, and every member of the group receives the messages.

## Development

### Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install)
*   [Protocol Buffers Compiler](https://grpc.io/docs/protoc-installation/)

### Building the Project

To build the project, run the following command:

```sh
cargo build
```

### Running Tests

To run the test suite, use the following command:

```sh
cargo test
```

### Building the Protocol Buffers

The project uses Protocol Buffers for message serialization. If you modify the `.proto` files, you'll need to rebuild the generated Rust code. The build script handles this automatically when you run `cargo build`.

## Message Flow Architecture

The following diagrams illustrate how messages traverse through the Agora chat system.

### High-Level Message Flow

```mermaid
graph TD
    subgraph Chat Network
        ClientA[Chat Client A]
        ClientB[Chat Client B]
        ClientC[Chat Client C]
    end

    subgraph UDP Multicast
        NetworkLayer(239.255.255.250:8080)
    end

    ClientA -- sends/receives --> NetworkLayer
    ClientB -- sends/receives --> NetworkLayer
    ClientC -- sends/receives --> NetworkLayer
```

### Single Chat App Detail

```mermaid
graph TD
    subgraph Initialization
        main["main()"]
    end

    subgraph Components
        NetworkManager
        MessageHandler
        Processor
    end
    
    subgraph Async Tasks
        UDP_Intake["Task 1: UDP Intake"]
        Chat_Process["Task 2: Chat Process"]
    end

    main -- 1. Initialize components --> NetworkManager
    main -- 1. Initialize components --> MessageHandler
    main -- 1. Initialize components --> Processor

    Processor -- 2. Spawn tasks --> UDP_Intake
    Processor -- 2. Spawn tasks --> Chat_Process
```

### Detailed Message Flow

#### Incoming Message Flow

```mermaid
sequenceDiagram
    participant UDP as UDP Multicast
    participant NM as NetworkManager
    participant UIT as UDP Intake Task
    participant MH as MessageHandler
    participant CPT as Chat Process Task
    participant UI as User Interface

    UDP->>+NM: Receives message
    NM->>NM: Deserializes protobuf
    NM->>-UIT: Sends deserialized message
    UIT->>+MH: try_send_msg() (non-blocking)
    MH->>-CPT: Sends message via MPSC channel
    CPT->>+MH: receive_msg() (blocking)
    MH->>MH: Filters out self-messages
    MH->>-UI: Displays message
```

#### Outgoing Message Flow

```mermaid
sequenceDiagram
    participant UI as User Interface
    participant NM as NetworkManager
    participant UDP as UDP Multicast

    UI->>+NM: Creates ChatMessage
    NM->>NM: Serializes to protobuf
    NM->>-UDP: Broadcasts message
```

## Key Components

*   **NetworkManager**: Handles UDP multicast communication, including sending and receiving messages. It uses `socket2` for advanced socket configuration.
*   **MessageHandler**: Manages the MPSC channel for decoupling network I/O from message processing.
*   **Processor**: Orchestrates the asynchronous tasks for handling incoming and outgoing messages.
*   **ChatMessage (protobuf)**: The data structure for chat messages, defined in `.proto` files.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.