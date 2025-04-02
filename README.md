# advanced-gossip

A secure extension of iroh-gossip providing authenticated pub/sub messaging with granular access control and automatic peer discovery.

!Work in progress!

## Features

- **Access Control**
  - Read Policies: `All` or `Custom(Vec<VerifyingKey>)` for message encryption
  - Write Policies: `All` or `Owner(VerifyingKey)` for publication control
  - Message authentication using Ed25519 signatures

- **Auto Discovery**
  - Built on iroh-topic-tracker
  - Automatic peer discovery and connection management
  - Decentralized topic membership

- **Message Properties**
  - Author verification via Ed25519 public keys
  - Cryptographic signatures
  - Timestamps
  - Optional encrypted payloads

## Important: Topic Coordination

For nodes to join the same topic, they must share identical:
- Read policy configuration
- Write policy configuration
- Owner's verifying key
- Topic name

These parameters are hashed to generate the topic identifier. Any mismatch in these values will result in nodes joining different topics.

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
advanced-gossip = "0.0.1"
```

### Example: Coordinated Topics

```rust
use advanced_gossip::{AdvancedGossip, Message, PolicyTopic, ReadPolicy, WritePolicy};
use ed25519_dalek::SigningKey;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // IMPORTANT: All nodes must share these same values
    let owner_key = SigningKey::from_bytes(&[/* known key bytes */])?;
    let topic_name = "shared_topic".to_string();
    let read_policy = ReadPolicy::Custom(vec![owner_key.verifying_key()]);
    let write_policy = WritePolicy::All;

    // Node-specific signing key
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);

    // Initialize gossip instance
    let gossip = AdvancedGossip::builder(&signing_key)
        .build()
        .await?;

    // Create topic with coordinated parameters
    let topic = PolicyTopic::new(
        read_policy.clone(),
        write_policy.clone(),
        owner_key.verifying_key(),
        topic_name,
    );

    // Subscribe to topic
    let (topic_tx, mut topic_rx) = gossip.subscribe(topic).await?;

    // Handle incoming messages
    tokio::spawn(async move {
        while let Some(message) = topic_rx.recv().await {
            println!("Received: {}", message);
        }
    });

    Ok(())
}
```

## Security Features

- Messages are signed using Ed25519 signatures
- Optional message encryption for restricted topics
- Write access control through policy enforcement
- Read access control through message encryption

## License

MIT License - Copyright (c) 2025 fun with rust y2
