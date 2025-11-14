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

//! Unit tests for V8 symbolizer module (v8_symbolizer.rs)

#[cfg(test)]
use super::*;

#[test]
fn test_smi_parsing() {
    let memory = RemoteMemory::new(std::process::id());
    let offsets = V8Offsets::default();
    let reader = V8ObjectReader::new(&memory, &offsets);

    // SMI encoding: value << 32 | 0x0
    let smi_value = (42i32 as u64) << V8_SMI_TAG_SHIFT;
    assert_eq!(reader.parse_smi(smi_value), Some(42));

    // Heap object pointer (not SMI)
    let heap_ptr = 0x123456789 | V8_HEAP_OBJECT_TAG;
    assert_eq!(reader.parse_smi(heap_ptr), None);
}

#[test]
fn test_heap_object_verification() {
    let memory = RemoteMemory::new(std::process::id());
    let offsets = V8Offsets::default();
    let reader = V8ObjectReader::new(&memory, &offsets);

    // Valid heap object pointer
    let heap_ptr = 0x123456788 | V8_HEAP_OBJECT_TAG;
    assert_eq!(reader.verify_heap_object(heap_ptr), Some(0x123456788));

    // Invalid (SMI)
    let smi = (42u64) << V8_SMI_TAG_SHIFT;
    assert_eq!(reader.verify_heap_object(smi), None);

    // Null pointer
    assert_eq!(reader.verify_heap_object(0), None);
}

#[test]
fn test_frame_type_mapping() {
    use crate::unwind::v8::{V8_10_OFFSETS, V8_11_OFFSETS, V8_9_OFFSETS};

    // Test that frame type values are correctly mapped for different V8 versions

    // V8 9.x frame types
    let v9_types = &V8_9_OFFSETS.frame_types;
    assert_eq!(v9_types.entry_frame, 1);
    assert_eq!(v9_types.exit_frame, 3);
    assert_eq!(v9_types.baseline_frame, 12);
    assert_eq!(v9_types.optimized_frame, 13);

    // V8 10.x frame types
    let v10_types = &V8_10_OFFSETS.frame_types;
    assert_eq!(v10_types.entry_frame, 1);
    assert_eq!(v10_types.exit_frame, 3);
    assert_eq!(v10_types.baseline_frame, 13);
    assert_eq!(v10_types.optimized_frame, 14);

    // V8 11.x frame types (uses turbofan_frame instead of optimized_frame)
    let v11_types = &V8_11_OFFSETS.frame_types;
    assert_eq!(v11_types.entry_frame, 1);
    assert_eq!(v11_types.exit_frame, 3);
    assert_eq!(v11_types.baseline_frame, 14);
    assert_eq!(v11_types.turbofan_frame, 16); // V8 11+ uses turbofan_frame
    assert_eq!(v11_types.maglev_frame, 15); // V8 11+ also has maglev
}

#[test]
fn test_symbolize_stub_frame_v9() {
    use crate::unwind::v8::V8_9_OFFSETS;

    let frame_types = &V8_9_OFFSETS.frame_types;

    // Test EntryFrame
    let result = symbolize_stub_frame(1, frame_types);
    assert_eq!(result, "V8:EntryFrame");

    // Test ExitFrame
    let result = symbolize_stub_frame(3, frame_types);
    assert_eq!(result, "V8:ExitFrame");

    // Test BaselineFrame
    let result = symbolize_stub_frame(12, frame_types);
    assert_eq!(result, "V8:BaselineFrame");

    // Test unknown frame type
    let result = symbolize_stub_frame(99, frame_types);
    assert_eq!(result, "V8:UnknownStub#99");
}

#[test]
fn test_symbolize_stub_frame_v11() {
    use crate::unwind::v8::V8_11_OFFSETS;

    let frame_types = &V8_11_OFFSETS.frame_types;

    // Test EntryFrame (same across versions)
    let result = symbolize_stub_frame(1, frame_types);
    assert_eq!(result, "V8:EntryFrame");

    // Test TurbofanFrame (V8 11+ uses turbofan_frame instead of optimized_frame)
    let result = symbolize_stub_frame(16, frame_types);
    assert_eq!(result, "V8:TurbofanFrame");

    // Test BaselineFrame (different value in V8 11.x)
    let result = symbolize_stub_frame(14, frame_types);
    assert_eq!(result, "V8:BaselineFrame");
}
