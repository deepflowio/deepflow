use std::time::Duration;

use lru::LruCache;

pub struct L7RrtCache(LruCache<u128, Duration>);

impl L7RrtCache {
    pub fn new(cap: usize) -> L7RrtCache {
        L7RrtCache(LruCache::new(cap))
    }

    pub fn add_req_time(&mut self, flow_id: u64, stream_id: u32, timestamp: Duration) {
        self.0
            .put((stream_id as u128) << 64 | flow_id as u128, timestamp);
    }

    // 获取请求包的时间，找到并删除该节点
    pub fn get_and_remove_l7_req_time(&mut self, flow_id: u64, stream_id: u32) -> Option<Duration> {
        self.0.pop(&((stream_id as u128) << 64 | flow_id as u128))
    }

    pub fn get_and_remove_l7_req_timeout(&mut self, flow_id: u64) -> u32 {
        self.0.pop(&(flow_id as u128));
        0
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }
}
