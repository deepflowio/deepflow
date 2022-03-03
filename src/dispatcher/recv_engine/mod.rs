use crate::error;

pub struct Packet {
	// TODO: add contents
	//     raw_packet, capture_info, etc.
}

pub trait RecvEngine {
	fn close(&self);
	fn recv(&self) -> error::Result<Packet>;
}