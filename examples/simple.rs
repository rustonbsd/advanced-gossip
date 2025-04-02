use ed25519_dalek::SigningKey;
use advanced_gossip::{AdvancedGossip, PolicyTopic, ReadPolicy, WritePolicy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let owner_signing_key = SigningKey::from_bytes(z32::decode(b"ppmmixsdbmwh6i3mgxk14yfut3t1mn7rcn41mh5gmp6iy33ghefo").unwrap().as_slice().try_into().unwrap());
    println!("owner_signing_key: {}", z32::encode(owner_signing_key.as_bytes()));
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    //let signing_key = owner_signing_key.clone();

    let gossip = AdvancedGossip::builder(&signing_key).build().await?;

    gossip.subscribe(PolicyTopic::new(
        ReadPolicy::All,
        WritePolicy::Owner(owner_signing_key.clone().verifying_key()),
        owner_signing_key.clone().verifying_key(),
        "test topic".to_string(),
    )).await?;

    Ok(())
}
