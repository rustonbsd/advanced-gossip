use iroh::NodeId;
use iroh_topic_tracker::topic_tracker::Topic;

use crate::structs::{ReadPolicy, WritePolicy};

pub trait Policy {
    fn read() -> ReadPolicy;
    fn write() -> WritePolicy;
    fn to_topic(owner: NodeId) -> Topic;
}