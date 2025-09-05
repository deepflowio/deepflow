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

//! Tests for memory optimization and cache enhancements

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crate::unwind::{
        cache::{BoundedLruCache, MemoryConfig, MemoryManager},
        monitoring::ProfilerMetrics,
    };

    fn create_test_cache() -> BoundedLruCache<u32, String> {
        BoundedLruCache::new(100, Duration::from_secs(60))
    }

    fn create_memory_optimized_cache() -> BoundedLruCache<u32, String> {
        let config = MemoryConfig {
            cache_name: "test_cache".to_string(),
            pressure_check_interval_secs: 1,
            low_memory_threshold_mb: 10,
            high_memory_threshold_mb: 50,
            emergency_threshold_mb: 100,
            enable_adaptive_sizing: true,
            max_memory_usage_mb: 20,
        };
        BoundedLruCache::with_memory_config(100, Duration::from_secs(60), config)
    }

    #[test]
    fn test_memory_tracking() {
        let cache = create_test_cache();

        // Insert some entries
        for i in 0..10 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        let stats = cache.stats().unwrap();
        assert_eq!(stats.size, 10);
        assert!(stats.memory_usage_bytes > 0);

        // Remove an entry
        cache.remove(&5).unwrap();
        let stats_after = cache.stats().unwrap();
        assert_eq!(stats_after.size, 9);
        assert!(stats_after.memory_usage_bytes < stats.memory_usage_bytes);
    }

    #[test]
    fn test_memory_efficiency() {
        let cache = create_test_cache();

        // Insert entries with different value sizes
        cache.insert(1, "small".to_string()).unwrap();
        cache.insert(2, "a".repeat(1000)).unwrap();
        cache.insert(3, "medium_sized_value".to_string()).unwrap();

        let efficiency = cache.memory_efficiency();
        assert!(efficiency > 0.0);

        let usage = cache.memory_usage();
        assert!(usage > 1000); // Should be larger due to the long string
    }

    #[test]
    fn test_adaptive_sizing() {
        let cache = create_memory_optimized_cache();

        // Fill cache beyond normal capacity
        for i in 0..150 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        let stats = cache.stats().unwrap();
        // Cache should have been automatically reduced due to adaptive sizing
        assert!(stats.size <= stats.max_size);
        assert!(stats.adaptive_max_size <= stats.max_size);
    }

    #[test]
    fn test_smart_eviction() {
        let cache = create_test_cache();

        // Insert entries with different access patterns
        for i in 0..50 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        // Access some entries more frequently
        for _ in 0..10 {
            for i in 0..5 {
                cache.get(&i);
            }
        }

        // Insert more entries to trigger eviction
        for i in 50..120 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        let stats = cache.stats().unwrap();
        assert!(stats.size <= stats.max_size);

        // Frequently accessed entries should still be present
        for i in 0..5 {
            assert!(
                cache.get(&i).is_some(),
                "Frequently accessed entry {} should be present",
                i
            );
        }
    }

    #[test]
    fn test_memory_optimization() {
        let cache = create_test_cache();

        // Insert many entries including some that will expire
        for i in 0..80 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        // Access some entries to create frequency patterns
        for i in 0..10 {
            for _ in 0..5 {
                cache.get(&i);
            }
        }

        // Perform memory optimization
        let result = cache.optimize_memory().unwrap();

        assert!(result.entries_before >= result.entries_after);
        assert!(result.memory_before_bytes >= result.memory_after_bytes);

        if result.entries_evicted > 0 {
            assert!(result.memory_saved_bytes > 0);
        }

        println!("Memory optimization result: {:?}", result);
    }

    #[test]
    fn test_garbage_collection() {
        let cache = create_test_cache();

        // Insert entries
        for i in 0..50 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        let before_gc = cache.stats().unwrap();
        let cleaned = cache.force_gc().unwrap();

        let after_gc = cache.stats().unwrap();

        // GC should not remove valid entries if they're not expired
        assert_eq!(before_gc.size, after_gc.size);

        println!("GC cleaned {} entries", cleaned);
    }

    #[test]
    fn test_memory_manager() {
        let manager = MemoryManager::new();
        let stats = manager.get_stats();

        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.cache_misses, 0);

        // Record some operations
        manager.record_cache_hit();
        manager.record_cache_miss();
        manager.record_evictions(5);

        let updated_stats = manager.get_stats();
        assert_eq!(updated_stats.cache_hits, 1);
        assert_eq!(updated_stats.cache_misses, 1);
        assert_eq!(updated_stats.eviction_count, 5);
    }

    #[test]
    fn test_memory_pressure_handling() {
        let cache = create_memory_optimized_cache();

        // Insert many large entries to potentially trigger pressure
        for i in 0..200 {
            let large_value = "x".repeat(1000); // 1KB per entry
            cache.insert(i, large_value).unwrap();
        }

        let stats = cache.stats().unwrap();

        // Cache should handle memory pressure gracefully
        assert!(stats.size <= stats.max_size);

        // Check that the cache is still functional
        cache.insert(9999, "test_value".to_string()).unwrap();
        assert!(cache.get(&9999).is_some());
    }

    #[test]
    fn test_concurrent_memory_optimization() {
        let cache = Arc::new(create_memory_optimized_cache());
        let mut handles = vec![];

        // Spawn multiple threads to stress test memory optimization
        for thread_id in 0..4 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let key = thread_id * 100 + i;
                    cache_clone
                        .insert(key, format!("thread_{}_value_{}", thread_id, i))
                        .unwrap();

                    // Occasionally access old entries
                    if i % 10 == 0 && i > 0 {
                        cache_clone.get(&(key - 10));
                    }

                    // Periodically trigger optimization
                    if i % 30 == 0 {
                        let _ = cache_clone.optimize_memory();
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let stats = cache.stats().unwrap();
        assert!(stats.size > 0);
        assert!(stats.hit_count > 0);

        println!("Concurrent test final stats: {:?}", stats);
    }

    #[test]
    fn test_cache_with_ttl_and_memory_optimization() {
        let cache = BoundedLruCache::new(50, Duration::from_millis(100));

        // Insert entries
        for i in 0..30 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(150));

        // Insert a new entry, which should trigger cleanup of expired entries
        cache.insert(100, "new_value".to_string()).unwrap();

        // Perform optimization to clean up expired entries
        let result = cache.optimize_memory().unwrap();

        // Should have cleaned up expired entries
        let stats = cache.stats().unwrap();
        assert!(
            stats.size < 30,
            "TTL cleanup should have removed expired entries"
        );

        println!("TTL + optimization result: {:?}", result);
    }

    #[test]
    fn test_priority_based_eviction() {
        let cache = create_test_cache();

        // Insert entries
        for i in 0..60 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        // Create different access patterns to establish priorities
        // High priority: access frequently
        for _ in 0..20 {
            for i in 0..5 {
                cache.get(&i);
            }
        }

        // Medium priority: access occasionally
        for _ in 0..5 {
            for i in 5..10 {
                cache.get(&i);
            }
        }

        // Low priority: access once (already inserted)

        // Fill beyond capacity to trigger priority-based eviction
        for i in 60..120 {
            cache.insert(i, format!("value_{}", i)).unwrap();
        }

        let stats = cache.stats().unwrap();
        assert!(stats.size <= stats.max_size);

        // High priority entries should still be present
        for i in 0..5 {
            assert!(
                cache.get(&i).is_some(),
                "High priority entry {} should be present",
                i
            );
        }

        // Low priority entries are more likely to be evicted
        let mut low_priority_found = 0;
        for i in 15..20 {
            if cache.get(&i).is_some() {
                low_priority_found += 1;
            }
        }

        // At least some high priority entries should remain
        assert!(
            low_priority_found < 5,
            "Some low priority entries should have been evicted"
        );
    }

    #[test]
    fn test_memory_manager_pressure_levels() {
        let config = MemoryConfig {
            cache_name: "pressure_test".to_string(),
            pressure_check_interval_secs: 0, // Immediate checks
            low_memory_threshold_mb: 1,      // Very low threshold for testing
            high_memory_threshold_mb: 2,     // Very low threshold for testing
            emergency_threshold_mb: 3,       // Very low threshold for testing
            enable_adaptive_sizing: true,
            max_memory_usage_mb: 2,
        };

        let manager = MemoryManager::with_config(config);

        // Test pressure detection (will depend on actual system memory)
        let is_under_pressure = manager.is_under_pressure();
        let stats = manager.get_stats();

        println!(
            "Memory pressure: {}, level: {}",
            is_under_pressure, stats.pressure_level
        );

        // Test recording operations
        manager.record_emergency_cleanup();
        let updated_stats = manager.get_stats();
        assert_eq!(updated_stats.emergency_cleanup_count, 1);
        assert_eq!(updated_stats.cleanup_count, 1);
    }
}
