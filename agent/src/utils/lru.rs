use std::borrow::Borrow;
use std::hash::Hash;

use lru::LruCache;

pub struct Lru<K, V> {
    cache: LruCache<K, V>,
    init_cap: usize,
    max_cap: usize,

    cap: usize,
}

impl<K: Hash + Eq, V> Lru<K, V> {
    pub fn with_capacity(init_cap: usize, max_cap: usize) -> Self {
        let init_cap = init_cap.next_power_of_two();
        let max_cap = max_cap.next_power_of_two().max(init_cap);
        Self {
            cache: LruCache::new(init_cap.try_into().unwrap()),
            init_cap,
            max_cap,
            cap: init_cap,
        }
    }

    pub fn iter(&self) -> lru::Iter<K, V> {
        self.cache.iter()
    }

    pub fn put(&mut self, k: K, v: V) -> Option<V> {
        let r = self.cache.put(k, v);
        if r.is_none() && self.cache.len() >= self.cap && self.cap < self.max_cap {
            // new entry, check capacity
            self.cap <<= 1;
            self.cache.resize(self.cap.try_into().unwrap());
        }
        r
    }

    pub fn get_mut<'a, Q>(&'a mut self, k: &Q) -> Option<&'a mut V>
    where
        lru::KeyRef<K>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.cache.get_mut(k)
    }

    pub fn clear(&mut self) {
        self.cache.resize(self.init_cap.try_into().unwrap());
        self.cap = self.init_cap;
        self.cache.clear();
    }
}
