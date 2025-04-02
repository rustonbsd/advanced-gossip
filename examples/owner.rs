use ed25519_dalek::SigningKey;
use advanced_gossip::{AdvancedGossip, Message, PolicyTopic, ReadPolicy, WritePolicy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let owner_signing_key = SigningKey::from_bytes(z32::decode(b"ppmmixsdbmwh6i3mgxk14yfut3t1mn7rcn41mh5gmp6iy33ghefo").unwrap().as_slice().try_into().unwrap());
    println!("owner_signing_key: {}", z32::encode(owner_signing_key.as_bytes()));
    //let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let signing_key = owner_signing_key.clone();

    let gossip = AdvancedGossip::builder(&signing_key).build().await?;

    let read_policy = ReadPolicy::Custom(vec![owner_signing_key.clone().verifying_key()]);
    let write_policy = WritePolicy::All; //WritePolicy::Owner(owner_signing_key.clone().verifying_key());

    let (topic_tx, mut topic_rx) = gossip.subscribe(PolicyTopic::new(
        read_policy.clone(),
        write_policy.clone(),
        owner_signing_key.clone().verifying_key(),
        "test topic".to_string(),
    )).await?;

    tokio::spawn(async move {
        while let Some(message) = topic_rx.recv().await {
            println!("Received message: {}", message);
        }
    });

    // Main input loop for sending messages
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    loop {
        print!("> ");
        stdin.read_line(&mut buffer).unwrap();
        let message = Message::new(&buffer.clone().replace("\n","").into(), &signing_key, &read_policy);
        if message.is_legal(&write_policy) {
            topic_tx.send(message).await.unwrap();
        } else {
            println!("Message not legal for this topic");
        }
        buffer.clear();
    }

    Ok(())
}
