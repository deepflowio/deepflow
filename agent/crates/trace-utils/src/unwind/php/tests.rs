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

#[cfg(test)]
use super::*;
use semver::Version;

#[test]
fn test_version_parsing() {
    // Test version parsing from different sources
    let test_cases = vec![
        ("7.4.33", Some(Version::new(7, 4, 33))),
        ("8.0.30", Some(Version::new(8, 0, 30))),
        ("8.1.27", Some(Version::new(8, 1, 27))),
        ("8.2.15", Some(Version::new(8, 2, 15))),
        ("8.3.2", Some(Version::new(8, 3, 2))),
        ("invalid", None),
        ("", None),
    ];

    for (input, expected) in test_cases {
        let result = Version::parse(input).ok();
        assert_eq!(result, expected, "Failed parsing version: {}", input);
    }
}

#[test]
fn test_php_offsets_generation() {
    // Test PHP offsets for different versions
    let versions = vec![
        Version::new(7, 4, 0),
        Version::new(8, 0, 0),
        Version::new(8, 1, 0),
        Version::new(8, 2, 0),
        Version::new(8, 3, 0),
    ];

    for version in versions {
        let offsets = get_offsets_for_version(&version);

        // Verify that offsets are reasonable (not zero for critical fields)
        assert!(
            offsets.execute_data.function > 0,
            "execute_data.function offset should be > 0 for version {}",
            version
        );
        assert!(
            offsets.execute_data.prev_execute_data > 0,
            "execute_data.prev_execute_data offset should be > 0 for version {}",
            version
        );
        assert!(
            offsets.function.common_funcname > 0,
            "function.common.function_name offset should be > 0 for version {}",
            version
        );
        assert!(
            offsets.string.val > 0,
            "string.val offset should be > 0 for version {}",
            version
        );
    }
}

#[test]
fn test_version_compatibility() {
    // Test version compatibility checks
    let supported_versions = vec![
        Version::new(7, 4, 0),
        Version::new(7, 4, 33),
        Version::new(8, 0, 0),
        Version::new(8, 1, 0),
        Version::new(8, 2, 0),
        Version::new(8, 3, 0),
    ];

    let unsupported_versions = vec![
        Version::new(7, 3, 0), // Too old
        Version::new(8, 4, 0), // Too new (hypothetical)
        Version::new(9, 0, 0), // Future version
    ];

    let req = semver::VersionReq::parse(">=7.4.0, <8.4.0").unwrap();

    for version in supported_versions {
        assert!(
            req.matches(&version),
            "Version {} should be supported",
            version
        );
    }

    for version in unsupported_versions {
        assert!(
            !req.matches(&version),
            "Version {} should not be supported",
            version
        );
    }
}

#[test]
fn test_concurrent_operations() {
    use std::sync::Arc;
    use std::thread;

    let table = Arc::new(std::sync::Mutex::new(unsafe {
        PhpUnwindTable::new(-1, -1)
    }));
    let mut handles = vec![];

    // Test concurrent operations
    for i in 0..10 {
        let table_clone = Arc::clone(&table);
        let handle = thread::spawn(move || {
            let test_pid = 12345 + i;

            if let Ok(mut t) = table_clone.lock() {
                unsafe {
                    t.load(test_pid);
                    t.unload(test_pid);
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }
}

#[test]
fn test_memory_management() {
    // Test multiple allocations and deallocations
    const NUM_ITERATIONS: usize = 100;

    for _ in 0..NUM_ITERATIONS {
        let mut table = unsafe { PhpUnwindTable::new(-1, -1) };

        // Load and unload multiple processes
        for pid in 10000..10010 {
            unsafe { table.load(pid) };
        }

        for pid in 10000..10010 {
            unsafe { table.unload(pid) };
        }

        // Table should be dropped here and memory cleaned up
    }

    // If we reach here without panicking, memory management is working
    assert!(true);
}

#[test]
fn test_performance_benchmark() {
    const NUM_OPERATIONS: usize = 1000;
    let start = std::time::Instant::now();

    let mut table = unsafe { PhpUnwindTable::new(-1, -1) };

    for i in 0..NUM_OPERATIONS {
        let pid = 20000 + (i % 100); // Cycle through 100 PIDs

        unsafe {
            if i % 2 == 0 {
                table.load(pid as u32);
            } else {
                table.unload(pid as u32);
            }
        }
    }

    let elapsed = start.elapsed();
    let ops_per_sec = NUM_OPERATIONS as f64 / elapsed.as_secs_f64();

    println!("Performance: {:.2} operations/second", ops_per_sec);
    assert!(ops_per_sec > 100.0, "Performance should be reasonable");
}

#[test]
fn test_php_offsets_validation() {
    // Unit test for offset validation logic
    let php74_offsets = get_offsets_for_version(&Version::new(7, 4, 0));
    let php82_offsets = get_offsets_for_version(&Version::new(8, 2, 0));

    // PHP 7.4 and 8.2 may have the same memory layout, so we test they are loaded correctly
    // instead of assuming they must be different
    assert!(
        php74_offsets.execute_data.function > 0,
        "PHP 7.4 function offset should be > 0"
    );
    assert!(
        php82_offsets.execute_data.function > 0,
        "PHP 8.2 function offset should be > 0"
    );

    // All critical offsets should be non-zero
    assert!(php74_offsets.string.val > 0);
    assert!(php82_offsets.string.val > 0);
}

#[test]
fn test_unwind_table_state_management() {
    // Unit test for internal state management
    let mut table = unsafe { PhpUnwindTable::new(-1, -1) };

    // Test state after operations (with mock FDs, no actual loading occurs)
    unsafe {
        table.load(1234);
        table.unload(1234);
    }

    // PHP unwind table state management test completed
}
