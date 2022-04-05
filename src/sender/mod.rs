// NpbBandwidthWatcher NewFragmenterBuilder NewCompressorBuilder NewPCapBuilder NewUniformCollectSender

mod tcp_packet;

use std::time::Duration;

const COMPRESSOR_PORT: u16 = 20033;
const SEQUENCE_OFFSET: usize = 8;
const RCV_TIMEOUT: Duration = Duration::from_secs(1);
const ERR_INTERVAL: Duration = Duration::from_secs(30);
