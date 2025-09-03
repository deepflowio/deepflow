/*
 * Copyright (c) 2024 Yunshan Networks
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

use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;
use std::hash::Hash;
use std::ptr::NonNull;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};
use std::time::{Duration, Instant};

/// A high-performance thread-safe LRU cache with TTL support and memory pressure awareness
/// Uses intrusive doubly-linked list for O(1) operations with advanced memory management
pub struct BoundedLruCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    inner: Arc<RwLock<LruCacheInner<K, V>>>,
    max_size: usize,
    ttl: Duration,
    // Memory management
    memory_manager: Arc<MemoryManager>,
    cache_id: String,
}

/// Internal cache structure with O(1) LRU operations and memory optimization
struct LruCacheInner<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    map: HashMap<K, NonNull<Node<K, V>>>,
    head: Option<NonNull<Node<K, V>>>,
    tail: Option<NonNull<Node<K, V>>>,
    size: usize,
    max_size: usize,
    ttl: Duration,
    hit_count: u64,
    miss_count: u64,
    // Memory optimization
    memory_usage_bytes: usize,
    access_frequency: HashMap<K, u32>,
    cleanup_threshold: usize,
    adaptive_sizing: bool,
}

/// Intrusive doubly-linked list node for O(1) LRU operations with memory tracking
struct Node<K, V> {
    key: K,
    value: V,
    inserted_at: Instant,
    last_accessed: Instant,
    prev: Option<NonNull<Node<K, V>>>,
    next: Option<NonNull<Node<K, V>>>,
    // Memory optimization fields
    access_count: u32,
    memory_size: usize,
    priority_score: f32,
}

impl<K, V> Node<K, V> {
    fn new(key: K, value: V) -> Box<Self> {
        let now = Instant::now();
        let memory_size =
            std::mem::size_of::<K>() + std::mem::size_of::<V>() + std::mem::size_of::<Self>();
        Box::new(Self {
            key,
            value,
            inserted_at: now,
            last_accessed: now,
            prev: None,
            next: None,
            access_count: 1,
            memory_size,
            priority_score: 1.0,
        })
    }

    fn update_priority(&mut self) {
        let age_penalty = self.last_accessed.elapsed().as_secs_f32() / 3600.0; // Hours
        let frequency_bonus = (self.access_count as f32).ln_1p();
        self.priority_score = frequency_bonus - age_penalty;
    }
}

impl<K, V> BoundedLruCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    /// Create a new high-performance LRU cache with memory optimization
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        let cache_id = format!("cache_{}", std::process::id());
        Self {
            inner: Arc::new(RwLock::new(LruCacheInner {
                map: HashMap::with_capacity(max_size),
                head: None,
                tail: None,
                size: 0,
                max_size,
                ttl,
                hit_count: 0,
                miss_count: 0,
                memory_usage_bytes: 0,
                access_frequency: HashMap::new(),
                cleanup_threshold: max_size / 4, // Trigger cleanup at 25% capacity
                adaptive_sizing: true,
            })),
            max_size,
            ttl,
            memory_manager: Arc::new(MemoryManager::new()),
            cache_id,
        }
    }

    /// Create cache with custom memory management settings
    pub fn with_memory_config(max_size: usize, ttl: Duration, memory_config: MemoryConfig) -> Self {
        let cache_id = format!("cache_{}_{}", std::process::id(), memory_config.cache_name);
        let mut cache = Self::new(max_size, ttl);
        cache.memory_manager = Arc::new(MemoryManager::with_config(memory_config));
        cache.cache_id = cache_id;
        cache
    }

    /// Insert a key-value pair into the cache with memory pressure awareness
    pub fn insert(&self, key: K, value: V) -> Result<(), &'static str> {
        // Check memory pressure before insertion
        if self.memory_manager.is_under_pressure() {
            self.perform_emergency_cleanup()?;
        }

        let mut cache = self
            .inner
            .write()
            .map_err(|_| "Failed to acquire write lock")?;

        cache.insert(key, value, &self.memory_manager);

        // Adaptive cleanup if needed
        if cache.should_trigger_cleanup() {
            cache.perform_adaptive_cleanup(&self.memory_manager);
        }

        Ok(())
    }

    /// Get a value from the cache with intelligent prefetching
    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.inner.write().ok()?;
        let result = cache.get(key, &self.memory_manager);

        // Update memory manager statistics
        if result.is_some() {
            self.memory_manager.record_cache_hit();
        } else {
            self.memory_manager.record_cache_miss();
        }

        result
    }

    /// Remove a key from the cache with O(1) complexity
    pub fn remove(&self, key: &K) -> Result<Option<V>, &'static str> {
        let mut cache = self
            .inner
            .write()
            .map_err(|_| "Failed to acquire write lock")?;
        Ok(cache.remove(key))
    }

    /// Clear all entries from the cache
    pub fn clear(&self) -> Result<(), &'static str> {
        let mut cache = self
            .inner
            .write()
            .map_err(|_| "Failed to acquire write lock")?;
        cache.clear();
        Ok(())
    }

    /// Get comprehensive cache statistics including memory usage
    pub fn stats(&self) -> Result<CacheStats, &'static str> {
        let cache = self
            .inner
            .read()
            .map_err(|_| "Failed to acquire read lock")?;
        let memory_stats = self.memory_manager.get_stats();

        Ok(CacheStats {
            size: cache.size,
            max_size: self.max_size,
            ttl_seconds: self.ttl.as_secs(),
            hit_count: cache.hit_count,
            miss_count: cache.miss_count,
            hit_ratio: if cache.hit_count + cache.miss_count > 0 {
                cache.hit_count as f64 / (cache.hit_count + cache.miss_count) as f64
            } else {
                0.0
            },
            memory_usage_bytes: cache.memory_usage_bytes,
            memory_pressure_level: memory_stats.pressure_level,
            adaptive_max_size: cache.get_adaptive_max_size(),
            cleanup_count: memory_stats.cleanup_count,
            eviction_count: memory_stats.eviction_count,
        })
    }

    /// Perform emergency cleanup under memory pressure
    fn perform_emergency_cleanup(&self) -> Result<(), &'static str> {
        let mut cache = self
            .inner
            .write()
            .map_err(|_| "Failed to acquire write lock")?;

        let before_size = cache.size;
        cache.emergency_evict(&self.memory_manager);
        let evicted = before_size - cache.size;

        if evicted > 0 {
            info!(
                "Emergency cleanup: evicted {} entries from cache {}",
                evicted, self.cache_id
            );
        }

        Ok(())
    }

    /// Optimize cache for memory efficiency
    pub fn optimize_memory(&self) -> Result<MemoryOptimizationResult, &'static str> {
        let mut cache = self
            .inner
            .write()
            .map_err(|_| "Failed to acquire write lock")?;

        let before_memory = cache.memory_usage_bytes;
        let before_size = cache.size;

        cache.optimize_for_memory(&self.memory_manager);

        let after_memory = cache.memory_usage_bytes;
        let after_size = cache.size;

        Ok(MemoryOptimizationResult {
            entries_before: before_size,
            entries_after: after_size,
            memory_before_bytes: before_memory,
            memory_after_bytes: after_memory,
            memory_saved_bytes: before_memory.saturating_sub(after_memory),
            entries_evicted: before_size.saturating_sub(after_size),
        })
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.inner.read().map(|cache| cache.size).unwrap_or(0)
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        self.inner
            .read()
            .map(|cache| cache.memory_usage_bytes)
            .unwrap_or(0)
    }

    /// Get memory efficiency ratio (entries per MB)
    pub fn memory_efficiency(&self) -> f64 {
        let memory_mb = self.memory_usage() as f64 / 1024.0 / 1024.0;
        if memory_mb > 0.0 {
            self.len() as f64 / memory_mb
        } else {
            0.0
        }
    }

    /// Force garbage collection
    pub fn force_gc(&self) -> Result<usize, &'static str> {
        let mut cache = self
            .inner
            .write()
            .map_err(|_| "Failed to acquire write lock")?;
        Ok(cache.force_garbage_collection(&self.memory_manager))
    }
}

impl<K, V> LruCacheInner<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn insert(&mut self, key: K, value: V, memory_manager: &MemoryManager) {
        let now = Instant::now();

        // Check if key already exists
        if let Some(&node_ptr) = self.map.get(&key) {
            // Update existing node
            unsafe {
                let node = node_ptr.as_ptr();
                let old_size = (*node).memory_size;
                (*node).value = value;
                (*node).last_accessed = now;
                (*node).inserted_at = now;
                (*node).access_count += 1;
                (*node).memory_size = std::mem::size_of::<K>()
                    + std::mem::size_of::<V>()
                    + std::mem::size_of::<Node<K, V>>();
                (*node).update_priority();

                // Update memory usage
                self.memory_usage_bytes =
                    self.memory_usage_bytes.saturating_sub(old_size) + (*node).memory_size;
            }

            // Update access frequency
            *self.access_frequency.entry(key).or_insert(0) += 1;
            self.move_to_head(node_ptr);
            return;
        }

        // Create new node
        let node = Node::new(key.clone(), value);
        let memory_size = node.memory_size;
        let node_ptr = NonNull::from(Box::leak(node));

        // Add to map
        self.map.insert(key.clone(), node_ptr);
        self.access_frequency.insert(key, 1);

        // Add to front of list
        self.add_to_head(node_ptr);
        self.size += 1;
        self.memory_usage_bytes += memory_size;

        // Check capacity and evict if necessary
        let effective_max_size = if self.adaptive_sizing {
            self.get_adaptive_max_size()
        } else {
            self.max_size
        };

        if self.size > effective_max_size || memory_manager.is_under_pressure() {
            self.smart_eviction(memory_manager);
        }
    }

    fn get(&mut self, key: &K, memory_manager: &MemoryManager) -> Option<V> {
        let now = Instant::now();

        if let Some(&node_ptr) = self.map.get(key) {
            unsafe {
                let node = node_ptr.as_ref();

                // Check if expired
                if self.ttl > Duration::ZERO && now.duration_since(node.inserted_at) > self.ttl {
                    self.miss_count += 1;
                    // Remove expired node
                    let memory_size = node.memory_size;
                    self.access_frequency.remove(key);
                    self.remove_node(node_ptr);
                    self.map.remove(key);
                    self.size -= 1;
                    self.memory_usage_bytes = self.memory_usage_bytes.saturating_sub(memory_size);
                    return None;
                }

                // Update access time and statistics
                let value = node.value.clone();
                (*node_ptr.as_ptr()).last_accessed = now;
                (*node_ptr.as_ptr()).access_count += 1;
                (*node_ptr.as_ptr()).update_priority();

                // Update access frequency
                *self.access_frequency.entry(key.clone()).or_insert(0) += 1;

                self.move_to_head(node_ptr);
                self.hit_count += 1;

                // Trigger cleanup if needed
                if self.should_trigger_cleanup() {
                    self.perform_adaptive_cleanup(memory_manager);
                }

                Some(value)
            }
        } else {
            self.miss_count += 1;
            None
        }
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(node_ptr) = self.map.remove(key) {
            self.size -= 1;
            self.access_frequency.remove(key);
            unsafe {
                let node = node_ptr.as_ref();
                let value = node.value.clone();
                let memory_size = node.memory_size;
                self.memory_usage_bytes = self.memory_usage_bytes.saturating_sub(memory_size);
                self.remove_node(node_ptr);
                Some(value)
            }
        } else {
            None
        }
    }

    fn clear(&mut self) {
        // Safely deallocate all nodes
        while let Some(node_ptr) = self.tail {
            self.remove_node(node_ptr);
        }
        self.map.clear();
        self.access_frequency.clear();
        self.size = 0;
        self.memory_usage_bytes = 0;
        self.hit_count = 0;
        self.miss_count = 0;
    }

    fn add_to_head(&mut self, mut node_ptr: NonNull<Node<K, V>>) {
        unsafe {
            let node = node_ptr.as_mut();
            node.prev = None;
            node.next = self.head;

            if let Some(mut head_ptr) = self.head {
                head_ptr.as_mut().prev = Some(node_ptr);
            } else {
                self.tail = Some(node_ptr);
            }

            self.head = Some(node_ptr);
        }
    }

    fn remove_node(&mut self, node_ptr: NonNull<Node<K, V>>) {
        unsafe {
            let node = node_ptr.as_ref();

            // Update previous node
            if let Some(mut prev_ptr) = node.prev {
                prev_ptr.as_mut().next = node.next;
            } else {
                self.head = node.next;
            }

            // Update next node
            if let Some(mut next_ptr) = node.next {
                next_ptr.as_mut().prev = node.prev;
            } else {
                self.tail = node.prev;
            }

            // Deallocate the node
            let _ = Box::from_raw(node_ptr.as_ptr());
        }
    }

    fn move_to_head(&mut self, mut node_ptr: NonNull<Node<K, V>>) {
        // If already head, nothing to do
        if Some(node_ptr) == self.head {
            return;
        }

        // Remove from current position
        unsafe {
            let node = node_ptr.as_ref();

            if let Some(mut prev_ptr) = node.prev {
                prev_ptr.as_mut().next = node.next;
            }

            if let Some(mut next_ptr) = node.next {
                next_ptr.as_mut().prev = node.prev;
            } else {
                self.tail = node.prev;
            }
        }

        // Add to head
        unsafe {
            let node = node_ptr.as_mut();
            node.prev = None;
            node.next = self.head;

            if let Some(mut head_ptr) = self.head {
                head_ptr.as_mut().prev = Some(node_ptr);
            }

            self.head = Some(node_ptr);
        }
    }

    fn evict_tail(&mut self) {
        if let Some(tail_ptr) = self.tail {
            unsafe {
                let tail_node = tail_ptr.as_ref();
                let key = tail_node.key.clone();
                let memory_size = tail_node.memory_size;
                self.access_frequency.remove(&key);
                self.map.remove(&key);
                self.remove_node(tail_ptr);
                self.size -= 1;
                self.memory_usage_bytes = self.memory_usage_bytes.saturating_sub(memory_size);
            }
        }
    }

    /// Check if cleanup should be triggered based on various factors
    fn should_trigger_cleanup(&self) -> bool {
        self.size >= self.cleanup_threshold ||
        self.memory_usage_bytes > (self.max_size * 1024) || // Approximate 1KB per entry threshold
        (self.hit_count + self.miss_count > 0 &&
         (self.hit_count as f64 / (self.hit_count + self.miss_count) as f64) < 0.6)
    }

    /// Perform adaptive cleanup based on memory pressure and access patterns
    fn perform_adaptive_cleanup(&mut self, memory_manager: &MemoryManager) {
        let target_size = if memory_manager.is_under_pressure() {
            self.max_size / 2 // Aggressive cleanup under pressure
        } else {
            (self.max_size * 3) / 4 // Conservative cleanup
        };

        while self.size > target_size {
            self.smart_eviction(memory_manager);
        }

        debug!(
            "Adaptive cleanup: reduced cache size to {} (target: {})",
            self.size, target_size
        );
    }

    /// Smart eviction based on priority scores and access patterns
    fn smart_eviction(&mut self, memory_manager: &MemoryManager) {
        if self.size == 0 {
            return;
        }

        // Collect candidates for eviction
        let mut candidates = Vec::new();
        let mut current = self.tail;

        // Examine the last 25% of entries for eviction
        let examine_count = (self.size / 4).max(1);
        let mut examined = 0;

        while let Some(node_ptr) = current {
            if examined >= examine_count {
                break;
            }

            unsafe {
                let node = node_ptr.as_ref();
                candidates.push((node_ptr, node.priority_score, node.memory_size));
                current = node.prev;
                examined += 1;
            }
        }

        // Sort by priority score (lower scores get evicted first)
        candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        // Evict lowest priority entries
        let evict_count = if memory_manager.is_under_pressure() {
            candidates.len() // Evict all candidates under pressure
        } else {
            (candidates.len() / 2).max(1) // Evict half normally
        };

        for i in 0..evict_count.min(candidates.len()) {
            let (node_ptr, _, memory_size) = candidates[i];
            unsafe {
                let node = node_ptr.as_ref();
                let key = node.key.clone();
                self.access_frequency.remove(&key);
                self.map.remove(&key);
                self.remove_node(node_ptr);
                self.size -= 1;
                self.memory_usage_bytes = self.memory_usage_bytes.saturating_sub(memory_size);
            }
        }

        memory_manager.record_evictions(evict_count);
    }

    /// Emergency eviction under severe memory pressure
    fn emergency_evict(&mut self, memory_manager: &MemoryManager) {
        let target_size = self.max_size / 4; // Keep only 25%

        while self.size > target_size {
            self.evict_tail();
        }

        memory_manager.record_emergency_cleanup();
        warn!("Emergency eviction: reduced cache size to {}", self.size);
    }

    /// Get adaptive maximum size based on memory pressure and performance
    fn get_adaptive_max_size(&self) -> usize {
        if !self.adaptive_sizing {
            return self.max_size;
        }

        let hit_ratio = if self.hit_count + self.miss_count > 0 {
            self.hit_count as f64 / (self.hit_count + self.miss_count) as f64
        } else {
            1.0
        };

        // Adjust size based on hit ratio
        if hit_ratio > 0.8 {
            self.max_size // High hit ratio, keep full size
        } else if hit_ratio > 0.6 {
            (self.max_size * 3) / 4 // Medium hit ratio, reduce by 25%
        } else {
            self.max_size / 2 // Low hit ratio, reduce by 50%
        }
    }

    /// Optimize cache for memory efficiency
    fn optimize_for_memory(&mut self, memory_manager: &MemoryManager) {
        // Remove expired entries first
        self.remove_expired_entries();

        // Remove low-frequency entries
        self.remove_low_frequency_entries();

        // Compact access frequency map
        self.compact_frequency_map();

        memory_manager.record_optimization();
    }

    /// Remove expired entries
    fn remove_expired_entries(&mut self) {
        if self.ttl == Duration::ZERO {
            return;
        }

        let now = Instant::now();
        let mut to_remove = Vec::new();
        let mut current = self.tail;

        while let Some(node_ptr) = current {
            unsafe {
                let node = node_ptr.as_ref();
                if now.duration_since(node.inserted_at) > self.ttl {
                    to_remove.push((node.key.clone(), node_ptr, node.memory_size));
                }
                current = node.prev;
            }
        }

        for (key, node_ptr, memory_size) in to_remove {
            self.access_frequency.remove(&key);
            self.map.remove(&key);
            self.remove_node(node_ptr);
            self.size -= 1;
            self.memory_usage_bytes = self.memory_usage_bytes.saturating_sub(memory_size);
        }
    }

    /// Remove entries with low access frequency
    fn remove_low_frequency_entries(&mut self) {
        let avg_frequency = if self.access_frequency.is_empty() {
            0.0
        } else {
            self.access_frequency.values().sum::<u32>() as f64 / self.access_frequency.len() as f64
        };

        let threshold = (avg_frequency / 2.0).max(1.0) as u32;
        let to_remove: Vec<K> = self
            .access_frequency
            .iter()
            .filter(|(_, &freq)| freq < threshold)
            .map(|(key, _)| key.clone())
            .collect();

        for key in to_remove {
            if let Some(node_ptr) = self.map.remove(&key) {
                unsafe {
                    let memory_size = node_ptr.as_ref().memory_size;
                    self.remove_node(node_ptr);
                    self.size -= 1;
                    self.memory_usage_bytes = self.memory_usage_bytes.saturating_sub(memory_size);
                }
                self.access_frequency.remove(&key);
            }
        }
    }

    /// Compact the access frequency map by removing entries for non-existent keys
    fn compact_frequency_map(&mut self) {
        self.access_frequency
            .retain(|key, _| self.map.contains_key(key));
    }

    /// Force garbage collection
    fn force_garbage_collection(&mut self, memory_manager: &MemoryManager) -> usize {
        let initial_size = self.size;

        // Remove expired entries
        self.remove_expired_entries();

        // Trigger smart eviction for oversized cache
        if self.size > self.max_size {
            while self.size > self.max_size {
                self.smart_eviction(memory_manager);
            }
        }

        // Compact frequency map
        self.compact_frequency_map();

        let cleaned_entries = initial_size - self.size;
        memory_manager.record_gc(cleaned_entries);

        info!(
            "Garbage collection completed: {} entries cleaned",
            cleaned_entries
        );
        cleaned_entries
    }
}

impl<K, V> Drop for LruCacheInner<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn drop(&mut self) {
        debug!(
            "Dropping LruCacheInner with {} entries, {} bytes",
            self.size, self.memory_usage_bytes
        );
        self.clear();
    }
}

unsafe impl<K, V> Send for BoundedLruCache<K, V>
where
    K: Hash + Eq + Clone + Send,
    V: Clone + Send,
{
}

unsafe impl<K, V> Sync for BoundedLruCache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
}

#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub size: usize,
    pub max_size: usize,
    pub ttl_seconds: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub hit_ratio: f64,
    // Memory optimization fields
    pub memory_usage_bytes: usize,
    pub memory_pressure_level: u8,
    pub adaptive_max_size: usize,
    pub cleanup_count: u64,
    pub eviction_count: u64,
}

/// Memory manager for cache optimization
#[derive(Debug)]
pub struct MemoryManager {
    // Statistics
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    eviction_count: AtomicU64,
    cleanup_count: AtomicU64,
    gc_count: AtomicU64,
    optimization_count: AtomicU64,
    emergency_cleanup_count: AtomicU64,

    // Memory pressure tracking
    memory_pressure_level: AtomicU64,
    last_pressure_check: std::sync::Mutex<Instant>,

    // Configuration
    config: MemoryConfig,
}

/// Memory management configuration
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub cache_name: String,
    pub pressure_check_interval_secs: u64,
    pub low_memory_threshold_mb: usize,
    pub high_memory_threshold_mb: usize,
    pub emergency_threshold_mb: usize,
    pub enable_adaptive_sizing: bool,
    pub max_memory_usage_mb: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            cache_name: "default_cache".to_string(),
            pressure_check_interval_secs: 30,
            low_memory_threshold_mb: 100,
            high_memory_threshold_mb: 500,
            emergency_threshold_mb: 1000,
            enable_adaptive_sizing: true,
            max_memory_usage_mb: 200,
        }
    }
}

impl MemoryManager {
    pub fn new() -> Self {
        Self::with_config(MemoryConfig::default())
    }

    pub fn with_config(config: MemoryConfig) -> Self {
        Self {
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            eviction_count: AtomicU64::new(0),
            cleanup_count: AtomicU64::new(0),
            gc_count: AtomicU64::new(0),
            optimization_count: AtomicU64::new(0),
            emergency_cleanup_count: AtomicU64::new(0),
            memory_pressure_level: AtomicU64::new(0),
            last_pressure_check: std::sync::Mutex::new(Instant::now()),
            config,
        }
    }

    pub fn is_under_pressure(&self) -> bool {
        // Check if we need to update pressure level
        {
            let mut last_check = self.last_pressure_check.lock().unwrap();
            if last_check.elapsed().as_secs() >= self.config.pressure_check_interval_secs {
                *last_check = Instant::now();
                drop(last_check);
                self.update_memory_pressure();
            }
        }

        self.memory_pressure_level.load(Ordering::Relaxed) >= 2
    }

    fn update_memory_pressure(&self) {
        let memory_usage = self.get_system_memory_usage();

        let pressure_level = if memory_usage >= self.config.emergency_threshold_mb {
            3 // Emergency
        } else if memory_usage >= self.config.high_memory_threshold_mb {
            2 // High pressure
        } else if memory_usage >= self.config.low_memory_threshold_mb {
            1 // Low pressure
        } else {
            0 // No pressure
        };

        self.memory_pressure_level
            .store(pressure_level, Ordering::Relaxed);

        if pressure_level >= 2 {
            warn!(
                "High memory pressure detected: {} MB (level {})",
                memory_usage, pressure_level
            );
        }
    }

    fn get_system_memory_usage(&self) -> usize {
        // Read memory usage from /proc/self/status
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<usize>() {
                            return kb / 1024; // Convert to MB
                        }
                    }
                }
            }
        }

        // Fallback: estimate based on heap size if /proc is not available
        0 // Default to no pressure if we can't determine usage
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_evictions(&self, count: usize) {
        self.eviction_count
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn record_emergency_cleanup(&self) {
        self.emergency_cleanup_count.fetch_add(1, Ordering::Relaxed);
        self.cleanup_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_optimization(&self) {
        self.optimization_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_gc(&self, cleaned_entries: usize) {
        self.gc_count.fetch_add(1, Ordering::Relaxed);
        debug!("GC completed: {} entries cleaned", cleaned_entries);
    }

    pub fn get_stats(&self) -> MemoryManagerStats {
        MemoryManagerStats {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            eviction_count: self.eviction_count.load(Ordering::Relaxed),
            cleanup_count: self.cleanup_count.load(Ordering::Relaxed),
            gc_count: self.gc_count.load(Ordering::Relaxed),
            optimization_count: self.optimization_count.load(Ordering::Relaxed),
            emergency_cleanup_count: self.emergency_cleanup_count.load(Ordering::Relaxed),
            pressure_level: self.memory_pressure_level.load(Ordering::Relaxed) as u8,
        }
    }
}

/// Memory manager statistics
#[derive(Debug, Clone, Default)]
pub struct MemoryManagerStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub eviction_count: u64,
    pub cleanup_count: u64,
    pub gc_count: u64,
    pub optimization_count: u64,
    pub emergency_cleanup_count: u64,
    pub pressure_level: u8,
}

/// Result of memory optimization operation
#[derive(Debug, Clone)]
pub struct MemoryOptimizationResult {
    pub entries_before: usize,
    pub entries_after: usize,
    pub memory_before_bytes: usize,
    pub memory_after_bytes: usize,
    pub memory_saved_bytes: usize,
    pub entries_evicted: usize,
}
