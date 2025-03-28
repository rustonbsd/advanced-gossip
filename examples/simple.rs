use iroh::Endpoint;
use iroh_gossip::net::Gossip;
use iroh_topic_tracker::{integrations::iroh_gossip::{AutoDiscoveryBuilder, AutoDiscoveryGossip}, topic_tracker::Topic};
use rand_core::OsRng;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Generate a new secret key for secure communication
    let mut csprng = OsRng;
    let secret_key = iroh::SecretKey::generate(&mut csprng);

    // Set up endpoint with discovery enabled
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .discovery_n0()
        .discovery_dht()
        .bind()
        .await?;


    // Initialize gossip with auto-discovery
    let gossip = Gossip::builder()
        .spawn_with_auto_discovery(endpoint.clone())
        .await?;

    // Set up protocol router
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.gossip.clone())
        .spawn()
        .await?;

    // Create topic from passphrase
    let topic = Topic::from_passphrase("my-iroh-gossip-topic");

    // Split into sink (sending) and stream (receiving) 
    let (sink, mut stream) = gossip.subscribe_and_join(topic.into()).await?.split();

    Ok(())
}