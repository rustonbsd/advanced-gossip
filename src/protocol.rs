use crate::{structs::Message, PolicyTopic, WritePolicy};
use std::{collections::HashMap, sync::Arc};
use anyhow::Error;
use ed25519_dalek::SigningKey;
use iroh::{protocol::Router, Endpoint};
use iroh_topic_tracker::integrations::iroh_gossip::{AutoDiscoveryBuilder, AutoDiscoveryGossip, GossipAutoDiscovery};
use tokio::{sync::mpsc, task::AbortHandle};
use tracing::{error_span, warn, Instrument};
use futures_lite::StreamExt;
use iroh_gossip::net::{Event, GossipEvent, GossipReceiver, GossipTopic};
use tokio_stream::wrappers::ReceiverStream;
use futures_concurrency::stream::{stream_group, StreamGroup};

#[derive(Clone)]
pub struct AdvancedGossip {
    inner: Arc<Inner>,
}

enum ToActor {
    Subscribe {
        topic: PolicyTopic,
        resp_tx: mpsc::Sender<anyhow::Result<(mpsc::Sender<Message>,mpsc::Receiver<Message>)>>,
    },
    Leave {
        topic: PolicyTopic,
    },
    SendMessage {
        message: Message,
        topic: PolicyTopic,
    }
}

#[derive(Debug,Clone)]
struct Inner {
    to_actor_tx: mpsc::Sender<ToActor>,
    _actor_handle: AbortHandle,
}

impl AdvancedGossip {
    pub async fn subscribe(
        policy_topic: &PolicyTopic,
    ) -> anyhow::Result<(mpsc::Sender<Message>,mpsc::Receiver<Message>)> {
        todo!()
    }
}

pub struct Builder {
    signing_key: SigningKey,
    endpoint: Option<Endpoint>,
    router: Option<&'static Router>,
    gossip: Option<&'static GossipAutoDiscovery>,
    topics: Vec<PolicyTopic>,
}

impl Builder {
    pub fn new(signing_key: &SigningKey) -> Self {
        Self {
            signing_key: signing_key.clone(),
            endpoint: None,
            router: None,
            gossip: None,
            topics: vec![],
        }
    }

    pub fn endpoint(mut self, endpoint: &Endpoint) -> Self {
        self.endpoint = Some(endpoint.clone());
        self
    }

    pub fn router(mut self, router: &'static Router) -> Self {
        self.router = Some(router);
        self
    }

    pub fn gossip(mut self, gossip: &'static GossipAutoDiscovery) -> Self {
        self.gossip = Some(gossip);
        self
    }

    pub fn topics(mut self, topics: Vec<PolicyTopic>) -> Self {
        self.topics = topics;
        self
    }

    pub fn signing_key(mut self, signing_key: SigningKey) -> Self {
        self.signing_key = signing_key;
        self
    }

    pub async fn build(mut self) -> anyhow::Result<AdvancedGossip> {

        let endpoint = if self.endpoint.is_none() {
            Endpoint::builder().discovery_n0().secret_key(self.signing_key.into()).bind().await?
        } else {
            self.endpoint.unwrap()
        };

        let gossip = if self.gossip.is_none() {
            iroh_gossip::net::Gossip::builder().spawn_with_auto_discovery(endpoint.clone()).await?
        } else {
            self.gossip.unwrap().clone()
        };

        let router = if self.router.is_none() {
            iroh::protocol::Router::builder(endpoint.clone())
            .accept(iroh_gossip::ALPN, gossip.gossip.clone())
            .spawn()
            .await?
        } else {
            self.router.unwrap().clone()
        };

        let (actor, to_actor_tx) = Actor::new(endpoint.clone(), gossip);
        
        let actor_handle = tokio::spawn(
            async move {
                if let Err(err) = actor.run().await {
                    warn!("gossip actor closed with error: {err:?}");
                }
            }
            .instrument(error_span!("gossip", node_id = %endpoint.node_id())),
        );

        Ok(AdvancedGossip {
            inner: Inner {
                to_actor_tx,
                _actor_handle: actor_handle.abort_handle(),
            }.into(),
        })
    }
}

struct Actor {
    to_actor_tx: mpsc::Sender<ToActor>,
    to_actor_rx: mpsc::Receiver<ToActor>,
    topics: HashMap<PolicyTopic, TopicState>,
    endpoint: Endpoint,
    gossip: GossipAutoDiscovery,
    gossip_streams: HashMap<PolicyTopic, GossipTopic>,
    subscribers_rx: HashMap<PolicyTopic, mpsc::Receiver<Message>>,
}

#[derive(Debug,Clone)]
struct TopicState {
    subscribers_tx: Vec<mpsc::Sender<Message>>,
    write_policy: WritePolicy,
}

impl Actor {
    fn new(endpoint: Endpoint, gossip: GossipAutoDiscovery) -> (Self, mpsc::Sender<ToActor>) {
        let (to_actor_tx, to_actor_rx) = mpsc::channel(32);

        let actor = Actor {
            to_actor_tx: to_actor_tx.clone(),
            to_actor_rx,
            topics: HashMap::new(),
            endpoint,
            gossip,
            gossip_streams: HashMap::new(),
            subscribers_rx: HashMap::new(),
        };

        (actor, to_actor_tx)
    }

    async fn run(mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                Some(msg) = self.to_actor_rx.recv() => {
                    match msg {
                        ToActor::Subscribe { topic, resp_tx } => {
                            let gossip_topic = self.gossip.subscribe_and_join(topic.to_topic().into()).await?;
                            let (to_subscriber_tx, to_subscriber_rx) = mpsc::channel::<Message>(32);
                            let (from_subscriber_tx, from_subscriber_rx) = mpsc::channel::<Message>(32);

                            // Store subscriber
                            self.topics.entry(topic.clone()).or_insert(TopicState {
                                subscribers_tx: Vec::new(),
                                write_policy: topic.write_policy().clone(),
                            }).subscribers_tx.push(from_subscriber_tx);

                            // Store gossip receiver stream
                            self.gossip_streams.insert(topic.clone(), gossip_topic);
                            self.subscribers_rx.insert(topic.clone(), from_subscriber_rx);

                            let _ = resp_tx.send(Ok((from_subscriber_tx, to_subscriber_rx)));
                        },
                        ToActor::Leave { topic } => {
                            self.gossip_streams.remove(&topic);
                            self.subscribers_rx.remove(&topic);
                            self.topics.remove(&topic);
                        },
                        ToActor::SendMessage { message, topic } => {
                            if let Some(topic_state) = self.topics.get(&topic) {
                                if message.is_legal(&topic_state.write_policy) {
                                    if let Some(sender) = self.gossip_streams.get(&topic) {
                                        let _ = sender.broadcast(message.clone().to_bytes().into()).await;
                                    }
                                }
                            }
                            
                        }
                    }
                },
                // ![MOVE STREAMGROUP out of loop, resource waste]
                Some((topic, maybe_event)) = stream_group::StreamGroup::new(
                    self.subscribers_rx.iter_mut()
                        .map(|(topic, recv)| 
                            ReceiverStream::new(*recv)
                                .map(move |msg| (topic.clone(), msg))
                        )
                        .collect::<Vec<_>>()
                ).next() => {
                    if let Some(Ok(message)) = maybe_event {
                        if let Some(topic_state) = self.topics.get(&topic) {
                            if message.is_legal(&topic_state.write_policy) {
                                if let Some(sender) = self.gossip_streams.get(&topic) {
                                    let _ = sender.broadcast(message.clone()).await;
                                }
                            }
                        }
                    }
                },
                // Handle incoming gossip messages for all topics
                Some((topic, maybe_event)) = stream_group::StreamGroup::select(
                    self.gossip_streams
                        .iter_mut()
                        .map(|(topic, receiver)| {
                            receiver.map(move |event| (topic.clone(), event))
                        })
                        .collect::<Vec<_>>()
                ).next() => {
                    if let Some(Ok(Event::Gossip(GossipEvent::Received(msg)))) = maybe_event {
                        if let Ok(message) = crate::structs::Message::from_bytes(
                            msg.content.to_vec(),
                            Some(&ed25519_dalek::SigningKey::from_bytes(&self.endpoint.secret_key().to_bytes()))
                        ) {
                            if let Some(topic_state) = self.topics.get(&topic) {
                                if message.is_legal(&topic_state.write_policy) {
                                    for subscriber in &topic_state.subscribers_tx {
                                        let _ = subscriber.send(message.clone()).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
