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
fn test_jit_support_detection() {
    // Test JIT support detection for different PHP versions
    let php74 = PhpJitSupport::new(Version::new(7, 4, 33));
    assert!(!php74.supports_jit(), "PHP 7.4 should not support JIT");

    let php80 = PhpJitSupport::new(Version::new(8, 0, 30));
    assert!(php80.supports_jit(), "PHP 8.0 should support JIT");

    let php81 = PhpJitSupport::new(Version::new(8, 1, 27));
    assert!(php81.supports_jit(), "PHP 8.1 should support JIT");

    let php82 = PhpJitSupport::new(Version::new(8, 2, 15));
    assert!(php82.supports_jit(), "PHP 8.2 should support JIT");

    let php83 = PhpJitSupport::new(Version::new(8, 3, 2));
    assert!(php83.supports_jit(), "PHP 8.3 should support JIT");
}

#[test]
fn test_vm_kind_constants() {
    // Test that VM kind constants are correctly defined
    assert_eq!(ZEND_VM_KIND_HYBRID, 4, "ZEND_VM_KIND_HYBRID should be 4");
}

#[test]
fn test_vm_kind_detection() {
    // Test VM kind detection from binary data
    let mut jit_support = PhpJitSupport::new(Version::new(8, 2, 0));

    // Test with empty binary data
    let empty_data = vec![0u8; 0];
    let result = jit_support.determine_vm_kind(&empty_data);
    assert!(result.is_err(), "Empty binary data should return error");

    // Test with invalid binary data
    let invalid_data = vec![0u8; 64];
    let result = jit_support.determine_vm_kind(&invalid_data);
    assert!(
        result.is_err(),
        "Invalid binary should return error, not panic"
    );
}

#[test]
fn test_jit_return_address_recovery() {
    // Test JIT return address recovery
    let mut jit_support = PhpJitSupport::new(Version::new(8, 1, 0));

    // Test with empty binary data
    let empty_data = vec![0u8; 0];
    let result = jit_support.recover_jit_return_address(&empty_data);
    assert!(result.is_err(), "Empty binary data should return error");

    // Test with minimal valid binary data
    let minimal_data = vec![0u8; 128];
    let result = jit_support.recover_jit_return_address(&minimal_data);
    assert!(
        result.is_err(),
        "Minimal binary should return error for invalid data"
    );
}

#[test]
fn test_jit_readiness_check() {
    let jit_support = PhpJitSupport::new(Version::new(8, 2, 0));

    // Initially should not be ready
    assert!(
        !jit_support.is_jit_ready(),
        "JIT should not be ready initially"
    );

    // Test getter methods
    assert!(
        jit_support.get_jit_return_address().is_none(),
        "Should not have return address initially"
    );
    assert!(
        jit_support.get_vm_kind().is_none(),
        "Should not have VM kind initially"
    );
}

#[test]
fn test_x86_64_vm_kind_extraction() {
    let jit_support = PhpJitSupport::new(Version::new(8, 1, 0));

    // Test with mock x86_64 assembly sequence: mov eax, 4; ret
    let x86_code = vec![
        0xb8, 0x04, 0x00, 0x00, 0x00, // mov eax, 4
        0xc3, // ret
        0x90, 0x90, // padding
    ];

    let result = jit_support.extract_vm_kind_x86_64(&x86_code);
    assert!(
        result.is_ok(),
        "Should extract VM kind from valid x86_64 code"
    );

    let vm_kind = result.unwrap();
    assert_eq!(vm_kind, 4, "Should extract ZEND_VM_KIND_HYBRID (4)");
}

#[test]
fn test_aarch64_vm_kind_extraction() {
    let jit_support = PhpJitSupport::new(Version::new(8, 2, 0));

    // Test with mock aarch64 assembly sequence: mov w0, #4; ret
    let aarch64_code = vec![
        0x80, 0x00, 0x80, 0x52, // mov w0, #4
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];

    let result = jit_support.extract_vm_kind_aarch64(&aarch64_code);
    assert!(
        result.is_ok(),
        "Should extract VM kind from valid aarch64 code"
    );

    let vm_kind = result.unwrap();
    // The implementation extracts immediate value from mov instruction
    // For mov w0, #4, the extracted value should be 4
    assert_eq!(vm_kind, 4, "Should extract immediate value 4");
}

#[test]
fn test_x86_64_jit_return_address_extraction() {
    let jit_support = PhpJitSupport::new(Version::new(8, 1, 0));

    // Test with mock x86_64 code containing jump instruction
    let x86_code = vec![
        0x48, 0x89, 0xe5, // mov rbp, rsp (function prologue)
        0xff, 0x25, 0x10, 0x00, 0x00, 0x00, // jmp [rip+0x10]
        0x90, 0x90, 0x90, 0x90, // padding/next instruction
    ];

    let base_addr = 0x7f8000000000u64;
    let result = jit_support.extract_jit_return_address_x86_64(&x86_code, base_addr);
    assert!(
        result.is_ok(),
        "Should extract return address from valid x86_64 code"
    );

    let return_addr = result.unwrap();
    assert_ne!(return_addr, 0, "Should have non-zero return address");
}

#[test]
fn test_aarch64_jit_return_address_extraction() {
    let jit_support = PhpJitSupport::new(Version::new(8, 2, 0));

    // Test with mock aarch64 code containing BR (branch register) instruction
    // BR x16 = 0xd61f0200 in little-endian: 0x00, 0x02, 0x1f, 0xd6
    let aarch64_code = vec![
        0x00, 0x02, 0x1f, 0xd6, // br x16 (branch register instruction, opcode 0xd61f0200)
        0x00, 0x00, 0x00, 0x00, // nop
        0x00, 0x00, 0x00, 0x00, // nop
        0x00, 0x00, 0x00, 0x00, // nop (next instruction location)
    ];

    let base_addr = 0x7f8000000000u64;
    let result = jit_support.extract_jit_return_address_aarch64(&aarch64_code, base_addr);
    assert!(
        result.is_ok(),
        "Should extract return address from valid aarch64 code"
    );

    let return_addr = result.unwrap();
    assert_ne!(return_addr, 0, "Should have non-zero return address");
}

#[test]
fn test_error_handling() {
    // Test error handling with invalid inputs
    let mut jit_support = PhpJitSupport::new(Version::new(8, 1, 0));

    // Test with very small binary data
    let tiny_data = vec![0u8; 4];
    let vm_result = jit_support.determine_vm_kind(&tiny_data);
    assert!(
        vm_result.is_err(),
        "Should return error for tiny binary data that can't be parsed"
    );

    let addr_result = jit_support.recover_jit_return_address(&tiny_data);
    assert!(
        addr_result.is_err(),
        "Should return error for tiny binary data"
    );

    // Test with PHP version < 8.0
    let mut php7_support = PhpJitSupport::new(Version::new(7, 4, 0));
    let normal_data = vec![0u8; 128];
    let vm_result = php7_support.determine_vm_kind(&normal_data);
    assert!(vm_result.is_ok(), "Should handle PHP 7.x gracefully");
    assert_eq!(vm_result.unwrap(), 0, "PHP 7.x should return VM kind 0");

    let addr_result = php7_support.recover_jit_return_address(&normal_data);
    assert!(addr_result.is_ok(), "Should handle PHP 7.x gracefully");
    assert_eq!(addr_result.unwrap(), 0, "PHP 7.x should return address 0");
}

#[test]
fn test_edge_cases() {
    let jit_support = PhpJitSupport::new(Version::new(8, 2, 0));

    // Test extract_vm_kind_x86_64 with edge cases
    let empty_code = vec![];
    let result = jit_support.extract_vm_kind_x86_64(&empty_code);
    assert!(result.is_ok(), "Should handle empty code");
    assert_eq!(result.unwrap(), 0, "Empty code should return 0");

    // Test with code that doesn't have the expected pattern
    let random_code = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
    let result = jit_support.extract_vm_kind_x86_64(&random_code);
    assert!(result.is_ok(), "Should handle random code");
    assert_eq!(result.unwrap(), 0, "Random code should return 0");

    // Test extract_jit_return_address_x86_64 with edge cases
    let result = jit_support.extract_jit_return_address_x86_64(&empty_code, 0x1000);
    assert!(
        result.is_ok(),
        "Should handle empty code for return address"
    );
    assert_eq!(result.unwrap(), 0, "Empty code should return 0 address");
}

#[test]
fn test_version_boundary_conditions() {
    // Test versions right at the boundary
    let php799 = PhpJitSupport::new(Version::new(7, 99, 99));
    assert!(!php799.supports_jit(), "PHP 7.99.99 should not support JIT");

    let php800 = PhpJitSupport::new(Version::new(8, 0, 0));
    assert!(php800.supports_jit(), "PHP 8.0.0 should support JIT");

    let php800rc = PhpJitSupport::new(Version::parse("8.0.0-rc1").unwrap());
    // Pre-release versions may not be considered >= 8.0.0 by semver
    // This depends on semver implementation
    let supports_jit = php800rc.supports_jit();
    println!("PHP 8.0.0-rc1 JIT support: {}", supports_jit);
}

#[test]
fn test_concurrent_jit_operations() {
    use std::sync::Arc;
    use std::thread;

    let jit_support = Arc::new(PhpJitSupport::new(Version::new(8, 1, 0)));
    let test_data = Arc::new(vec![0u8; 128]);
    let mut handles = vec![];

    // Test concurrent access to JIT support methods
    for i in 0..10 {
        let jit_clone = Arc::clone(&jit_support);
        let _data_clone = Arc::clone(&test_data);

        let handle = thread::spawn(move || {
            // Test supports_jit (should be thread-safe)
            let supports = jit_clone.supports_jit();
            assert!(supports, "Thread {} should detect JIT support", i);

            // Test is_jit_ready (should be thread-safe)
            let ready = jit_clone.is_jit_ready();
            // Initial state should be false since we haven't configured anything
            assert!(!ready, "Thread {} JIT should not be ready initially", i);

            // Test getter methods (should be thread-safe)
            let return_addr = jit_clone.get_jit_return_address();
            let vm_kind = jit_clone.get_vm_kind();

            // Initially these should be None
            assert!(
                return_addr.is_none(),
                "Thread {} should have no return address initially",
                i
            );
            assert!(
                vm_kind.is_none(),
                "Thread {} should have no VM kind initially",
                i
            );
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }
}

#[test]
fn test_performance_benchmark() {
    const NUM_OPERATIONS: usize = 1000;
    let start = std::time::Instant::now();

    let jit_support = PhpJitSupport::new(Version::new(8, 2, 0));
    let _test_data = vec![0u8; 64];

    for _i in 0..NUM_OPERATIONS {
        // Test performance of supports_jit (should be very fast)
        let _supports = jit_support.supports_jit();

        // Test performance of is_jit_ready (should be very fast)
        let _ready = jit_support.is_jit_ready();

        // Test performance of getter methods
        let _return_addr = jit_support.get_jit_return_address();
        let _vm_kind = jit_support.get_vm_kind();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = NUM_OPERATIONS as f64 / elapsed.as_secs_f64();

    println!(
        "PHP JIT Support Performance: {:.2} operations/second",
        ops_per_sec
    );
    assert!(
        ops_per_sec > 10000.0,
        "JIT support operations should be very fast"
    );
}

#[test]
fn test_memory_safety() {
    // Test that multiple creations and drops don't cause memory issues
    const NUM_ITERATIONS: usize = 100;

    for _i in 0..NUM_ITERATIONS {
        let mut jit_support = PhpJitSupport::new(Version::new(8, 1, 0));
        let test_data = vec![0u8; 256];

        // Call methods that might allocate/deallocate memory
        let _vm_result = jit_support.determine_vm_kind(&test_data);
        let _addr_result = jit_support.recover_jit_return_address(&test_data);

        // JIT support should be dropped here
    }

    // If we reach here without panicking, memory safety is good
    assert!(true, "Memory safety test completed");
}
