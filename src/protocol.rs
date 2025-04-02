use crate::{structs::Message, PolicyTopic, WritePolicy};
use anyhow::Error;
use ed25519_dalek::SigningKey;
use futures::{future::BoxFuture, stream::FuturesUnordered};
use futures_concurrency::stream::{stream_group, StreamGroup};
use futures_lite::StreamExt;
use iroh::{protocol::Router, Endpoint};
use iroh_gossip::net::{Event, GossipEvent, GossipReceiver, GossipSender, GossipTopic};
use iroh_topic_tracker::integrations::iroh_gossip::{
    AutoDiscoveryBuilder, AutoDiscoveryGossip, GossipAutoDiscovery,
};
use std::{collections::HashMap, pin::Pin, sync::Arc};
use tokio::{
    sync::{mpsc, Mutex},
    task::AbortHandle,
};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error_span, warn, Instrument};

#[derive(Clone)]
pub struct AdvancedGossip {
    inner: Arc<Inner>,
}

enum ToActor {
    Subscribe {
        topic: PolicyTopic,
        resp_tx: mpsc::Sender<anyhow::Result<(mpsc::Sender<Message>, mpsc::Receiver<Message>)>>,
    },
    Leave {
        topic: PolicyTopic,
    },
    SendMessage {
        message: Message,
        topic: PolicyTopic,
    },
    ReceivedMessage {
        message: Message,
        topic: PolicyTopic,
    },
}

#[derive(Debug, Clone)]
struct Inner {
    to_actor_tx: mpsc::Sender<ToActor>,
    _actor_handle: AbortHandle,
}

impl AdvancedGossip {
    pub fn builder(signing_key: &SigningKey) -> Builder {
        Builder::new(signing_key)
    }

    pub async fn subscribe(&self, topic: PolicyTopic) -> anyhow::Result<(mpsc::Sender<Message>, mpsc::Receiver<Message>)> {
        let (resp_tx, mut resp_rx) = mpsc::channel(2);
        let ret = match self.inner.to_actor_tx.send(ToActor::Subscribe { topic: topic, resp_tx: resp_tx.clone() }).await {
            Ok(_) => {
                println!("Res: {:?}",resp_rx.is_closed());
                let res = resp_rx.recv().await;
                println!("Res: {:?}",resp_rx.is_closed());
                match res {
                    Some(Ok((from_subscriber_tx, to_subscriber_rx))) => Ok((from_subscriber_tx, to_subscriber_rx)),
                    Some(Err(err)) => Err(err),
                    None => Err(anyhow::anyhow!("Actor closed 1")),
                }
            },
            Err(_) => Err(anyhow::anyhow!("Actor closed 2")),
        };
        drop(resp_rx);
        ret
    }
}

#[derive(Debug, Clone)]
pub struct Builder {
    signing_key: SigningKey,
    endpoint: Option<Endpoint>,
    router: Option<&'static Router>,
    gossip: Option<&'static GossipAutoDiscovery>,
}

impl Builder {
    pub fn new(signing_key: &SigningKey) -> Self {
        Self {
            signing_key: signing_key.clone(),
            endpoint: None,
            router: None,
            gossip: None,
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

    pub fn signing_key(mut self, signing_key: SigningKey) -> Self {
        self.signing_key = signing_key;
        self
    }

    pub async fn build(self) -> anyhow::Result<AdvancedGossip> {
        let endpoint = if self.endpoint.is_none() {
            Endpoint::builder()
                .discovery_n0()
                .secret_key(self.signing_key.into())
                .bind()
                .await?
        } else {
            self.endpoint.unwrap()
        };

        let gossip = if self.gossip.is_none() {
            iroh_gossip::net::Gossip::builder()
                .spawn_with_auto_discovery(endpoint.clone())
                .await?
        } else {
            self.gossip.unwrap().clone()
        };

        let router = if let Some(router) = self.router {
            router.clone()
        } else {
            iroh::protocol::Router::builder(endpoint.clone())
                .accept(iroh_gossip::ALPN, gossip.gossip.clone())
                .spawn()
                .await?
        };

        let (actor, to_actor_tx) = Actor::new(endpoint.clone(),router, gossip);

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
            }
            .into(),
        })
    }
}

struct Actor {
    to_actor_tx: mpsc::Sender<ToActor>,
    to_actor_rx: mpsc::Receiver<ToActor>,
    topics: HashMap<PolicyTopic, TopicState>,
    endpoint: Endpoint,
    router: Router,
    gossip: GossipAutoDiscovery,
    subscriber_futures: FuturesUnordered<BoxFuture<'static, anyhow::Result<(PolicyTopic, Option<Message>, mpsc::Receiver<Message>)>>>,
    gossip_futures: FuturesUnordered<BoxFuture<'static, anyhow::Result<(PolicyTopic, Option<Event>, GossipReceiver)>>>,
}

#[derive(Debug, Clone)]
struct TopicState {
    subscribers_tx: mpsc::Sender<Message>,
    gossip_tx: Arc<GossipSender>,
    write_policy: WritePolicy,
}

impl Actor {
    fn new(endpoint: Endpoint, router: Router,gossip: GossipAutoDiscovery) -> (Self, mpsc::Sender<ToActor>) {
        let (to_actor_tx, to_actor_rx) = mpsc::channel(32);

        let actor = Actor {
            to_actor_tx: to_actor_tx.clone(),
            to_actor_rx,
            topics: HashMap::new(),
            endpoint,
            router,
            gossip,
            subscriber_futures: FuturesUnordered::new(),
            gossip_futures: FuturesUnordered::new(),
        };

        (actor, to_actor_tx)
    }

    fn future_box_subscriber(
        topic: PolicyTopic,
        mut from_subscriber_rx: mpsc::Receiver<Message>,
    ) -> Pin<
        Box<
            dyn futures::Future<
                    Output = anyhow::Result<(
                        PolicyTopic,
                        Option<Message>,
                        mpsc::Receiver<Message>,
                    )>,
                > + Send
                + 'static,
        >,
    > {
        Box::pin(async move {
            let message_option = from_subscriber_rx.recv().await;
            Ok((topic, message_option, from_subscriber_rx))
        })
    }

    fn future_box_gossip(
        topic: PolicyTopic,
        mut gossip_rx: GossipReceiver,
    ) -> Pin<
        Box<
            dyn futures::Future<
                    Output = anyhow::Result<(PolicyTopic, Option<Event>, GossipReceiver)>,
                > + Send
                + 'static,
        >,
    > {
        Box::pin(async move {
            let event = match gossip_rx.next().await {
                Some(event_res) => event_res.ok(),
                None => None,
            };
            Ok((topic, event, gossip_rx))
        })
    }

    async fn run(mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                Some(msg) = self.to_actor_rx.recv() => {
                    match msg {
                        ToActor::Subscribe { topic, resp_tx } => {

                            println!("Subbed");
                            if self.topics.contains_key(&topic) {
                                println!("Topic already subbed");
                                let _ = resp_tx.send(Err(anyhow::anyhow!("Topic already subscribed")));
                                continue;
                            }

                            let gossip_topic_handle = self.gossip.subscribe_and_join(topic.clone().to_topic().into()).await?;
                            let gossip_topic = gossip_topic_handle.split();
                            let (to_subscriber_tx, to_subscriber_rx) = mpsc::channel::<Message>(32);
                            let (from_subscriber_tx, from_subscriber_rx) = mpsc::channel::<Message>(32);

                            // Store subscriber
                            self.topics.entry(topic.clone()).or_insert(TopicState {
                                subscribers_tx: to_subscriber_tx.clone(),
                                write_policy: topic.write_policy().clone(),
                                gossip_tx: Arc::new(gossip_topic.0),
                            });

                            // Store gossip receiver stream
                            let _topic = topic.clone();
                            self.gossip_futures.push(Self::future_box_gossip(topic.clone(), gossip_topic.1));

                            // Store subscriber_tx receiver stream
                            let _topic = topic.clone();
                            self.subscriber_futures.push(Self::future_box_subscriber(topic.clone(), from_subscriber_rx));

                            let _ = resp_tx.send(Ok((from_subscriber_tx, to_subscriber_rx)));
                            println!("Send ok");
                        },
                        ToActor::Leave { topic } => {
                            let _ = self.topics.remove(&topic);

                        },
                        ToActor::SendMessage { message, topic } => {
                            if let Some(topic_state) = self.topics.get(&topic) {
                                if message.is_legal(&topic_state.write_policy) {
                                    let _ = topic_state.gossip_tx.broadcast(message.clone().to_bytes().into()).await;
                                }
                            }

                        },
                        ToActor::ReceivedMessage { message, topic } => {
                            if let Some(topic_state) = self.topics.get(&topic) {
                                if message.is_legal(&topic_state.write_policy) {
                                    let _ = topic_state.subscribers_tx.send(message.clone()).await;
                                }
                            }

                        }
                    }
                },
                // Stream_tx receiver from external
                Some(Ok((topic, maybe_message, from_subscriber_rx))) = self.subscriber_futures.next() => {
                    if let Some(message) = maybe_message {
                        if self.topics.contains_key(&topic) {
                            self.to_actor_tx.send(ToActor::SendMessage { message, topic: topic.clone() }).await?;
                            self.subscriber_futures.push(Self::future_box_subscriber(topic, from_subscriber_rx));
                        }
                    }
                },
                // Handle incoming gossip messages for all topics
                Some(Ok((topic, maybe_event, gossip_rx))) = self.gossip_futures.next() => {
                    if let Some(Event::Gossip(GossipEvent::Received(msg))) = maybe_event {
                        if let Ok(message) = Message::from_bytes(
                            msg.content.to_vec(),
                            Some(&ed25519_dalek::SigningKey::from_bytes(&self.endpoint.secret_key().to_bytes()))
                        ) {
                            if let Some(topic_state) = self.topics.get(&topic) {
                                if message.is_legal(&topic_state.write_policy) {
                                    self.to_actor_tx.send(ToActor::ReceivedMessage { message, topic: topic.clone() }).await?;
                                }
                            }
                        }

                        self.gossip_futures.push(Self::future_box_gossip(topic, gossip_rx));
                    }
                }
            }
        }
    }
}
