/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::VecDeque;
use std::time::Duration;

use lru::LruCache;

const SUB_QUEUE_SIZE: usize = 1024;

pub struct L7RrtCache {
    double_key_cache: LruCache<u64, VecDeque<(u32, Duration)>>,
    single_key_cache: LruCache<u64, Duration>,
}

impl L7RrtCache {
    pub fn new(cap: usize) -> L7RrtCache {
        let cap = cap.try_into().unwrap();
        L7RrtCache {
            double_key_cache: LruCache::new(cap),
            single_key_cache: LruCache::new(cap),
        }
    }

    fn double_key_cache_add_req_time(&mut self, key0: u64, key1: u32, timestamp: Duration) {
        if let Some(vec) = self.double_key_cache.get_mut(&key0) {
            match vec.binary_search_by_key(&key1, |&(a, _)| a) {
                Ok(i) => vec[i].1 = timestamp,
                Err(i) => {
                    vec.insert(i, (key1, timestamp));
                    if vec.len() > SUB_QUEUE_SIZE {
                        vec.pop_front();
                    }
                }
            }
        } else {
            self.double_key_cache
                .put(key0, vec![(key1, timestamp)].into());
        }
    }

    pub fn add_req_time(&mut self, key0: u64, key1: Option<u32>, timestamp: Duration) {
        if let Some(k1) = key1 {
            self.double_key_cache_add_req_time(key0, k1, timestamp)
        } else {
            self.single_key_cache.put(key0, timestamp);
        }
    }

    fn double_key_cache_get_and_remove_l7_req_time(
        &mut self,
        key0: u64,
        key1: u32,
    ) -> Option<Duration> {
        if let Some(vec) = self.double_key_cache.get_mut(&key0) {
            match vec.binary_search_by_key(&key1, |&(a, _)| a) {
                Ok(i) => {
                    let ret = Some(vec.remove(i).unwrap().1);
                    if vec.is_empty() {
                        self.double_key_cache.pop(&key0);
                    }
                    ret
                }
                Err(_) => None,
            }
        } else {
            None
        }
    }

    // 获取请求包的时间，找到并删除该节点
    pub fn get_and_remove_l7_req_time(&mut self, key0: u64, key1: Option<u32>) -> Option<Duration> {
        if let Some(id) = key1 {
            self.double_key_cache_get_and_remove_l7_req_time(key0, id)
        } else {
            self.single_key_cache.pop(&key0)
        }
    }

    pub fn get_and_remove_l7_req_timeout(&mut self, key0: u64) -> usize {
        if let Some(t) = self.double_key_cache.pop(&key0) {
            t.len()
        } else if self.single_key_cache.pop(&key0).is_some() {
            1
        } else {
            0
        }
    }

    pub fn clear(&mut self) {
        self.double_key_cache.clear();
        self.single_key_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal() {
        let mut rrt_cache = L7RrtCache::new(100);
        let key0 = 1608539048480171398;
        let key11 = Some(8888 as u32);
        let key12 = Some(9999 as u32);

        rrt_cache.add_req_time(key0, key11, Duration::from_micros(800));
        assert_eq!(
            Some(Duration::from_micros(800)),
            rrt_cache.get_and_remove_l7_req_time(key0, key11)
        );
        assert_eq!(None, rrt_cache.get_and_remove_l7_req_time(key0, key11));

        rrt_cache.add_req_time(key0, None, Duration::from_micros(800));
        assert_eq!(
            Some(Duration::from_micros(800)),
            rrt_cache.get_and_remove_l7_req_time(key0, None)
        );
        assert_eq!(None, rrt_cache.get_and_remove_l7_req_time(key0, None));

        rrt_cache.add_req_time(key0, key12, Duration::from_micros(900));
        assert_eq!(
            Some(Duration::from_micros(900)),
            rrt_cache.get_and_remove_l7_req_time(key0, key12)
        );
        assert_eq!(None, rrt_cache.get_and_remove_l7_req_time(key0, key12));
    }

    #[test]
    fn timeout() {
        let mut rrt_cache = L7RrtCache::new(100);
        let key0 = 1608539048480171398;
        let key11 = Some(8888 as u32);
        let key12 = Some(9999 as u32);

        rrt_cache.add_req_time(key0, key11, Duration::from_micros(800));
        rrt_cache.add_req_time(key0, key12, Duration::from_micros(900));
        assert_eq!(2, rrt_cache.get_and_remove_l7_req_timeout(key0));

        rrt_cache.add_req_time(key0, None, Duration::from_micros(800));
        rrt_cache.add_req_time(key0, None, Duration::from_micros(900));
        assert_eq!(1, rrt_cache.get_and_remove_l7_req_timeout(key0));
    }
}
