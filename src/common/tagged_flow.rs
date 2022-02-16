use super::flow::Flow;
use super::tag::Tag;

pub trait Encode {
    fn encode(&self);
}

pub struct TaggedFlow {
    flow: Flow,
    tag: Tag,
}

impl TaggedFlow {
    pub fn sequential_merge(&self, f: &TaggedFlow) {}
    pub fn write_to_pb(&self) {}
    pub fn reverse(&self) {}
}

impl Encode for TaggedFlow {
    fn encode(&self) {
        self.write_to_pb();
    }
}
