use crate::{structs::Message, PolicyTopic, WritePolicy};
use std::{collections::HashMap, sync::Arc};
use iroh::Endpoint;
use iroh_topic_tracker::integrations::iroh_gossip::GossipAutoDiscovery;
use tokio::{sync::mpsc, task::AbortHandle};

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
    },
    ReceivedMessage {
        message: Message,
        topic: PolicyTopic,
    },
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

struct Actor {
    to_actor_tx: mpsc::Sender<ToActor>,
    to_actor_rx: mpsc::Receiver<ToActor>,
    topics: HashMap<PolicyTopic, TopicState>,
    endpoint: Endpoint,
    gossip: GossipAutoDiscovery,
}

#[derive(Debug,Clone)]
struct TopicState {
    subscribers: Vec<mpsc::Sender<Message>>,
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
        };

        (actor, to_actor_tx)
    }

    async fn run(mut self) -> anyhow::Result<()> {
        while let Some(msg) = self.to_actor_rx.recv().await {
            match msg {
                ToActor::Subscribe { topic, resp_tx } => {
                    let (subscriber_tx,subscriber_rx) = mpsc::channel::<Message>(32);
                    let (sender_tx, mut sender_rx) = mpsc::channel::<Message>(32);

                    // Store subscriber
                    self.topics.entry(topic.clone()).or_insert(TopicState {
                        subscribers: Vec::new(),
                        write_policy: topic.write_policy().clone(),
                    }).subscribers.push(subscriber_tx);

                    // Subscriber message handler
                    tokio::spawn({
                        let to_actor_tx = self.to_actor_tx.clone();
                        async move {
                            while let Some(message) = sender_rx.recv().await {
                                let _ = to_actor_tx.send(ToActor::SendMessage { message: message.clone(), topic: topic.clone() }).await;
                            }
                    }});

                    let _ = resp_tx.send(Ok((sender_tx,subscriber_rx)));
                },
                ToActor::Leave { topic } => {

                },
                ToActor::SendMessage { message, topic } => {
                    if let Some(topic_state) = self.topics.get(&topic) {
                        if message.is_legal(&topic_state.write_policy) {
                            for subscriber in &topic_state.subscribers {
                                let _ = self.gossip.se
                            }
                        }
                    }
                },
                ToActor::ReceivedMessage { message, topic } => {
                    if let Some(topic_state) = self.topics.get(&topic) {
                        if message.is_legal(&topic_state.write_policy) {
                            for subscriber in &topic_state.subscribers {
                                let _ = subscriber.send(message.clone()).await;
                            }
                        }
                    }
                },
            }
        }
        Ok(())
    }
}
