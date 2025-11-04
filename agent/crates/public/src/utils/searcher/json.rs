/*
 * Copyright (c) 2025 Yunshan Networks
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

use super::{
    bytes_to_string, find_byte, find_bytes_case_sensitive, find_bytes_ignore_case,
    skip_whitespace_from_bytes, SearchError,
};

pub fn search_key_case_sensitive(payload: &[u8], key: &str) -> Result<String, SearchError> {
    search_key_impl(payload, key, find_bytes_case_sensitive)
}

pub fn search_key_ignore_case(payload: &[u8], key: &str) -> Result<String, SearchError> {
    search_key_impl(payload, key, find_bytes_ignore_case)
}

fn search_key_impl(
    payload: &[u8],
    key: &str,
    finder: fn(&[u8], &[u8]) -> Option<usize>,
) -> Result<String, SearchError> {
    let key_pattern = format!("\"{}\"", key);

    let key_idx = match finder(payload, &key_pattern.as_bytes()) {
        Some(idx) => idx,
        None => return Err(SearchError::KeyNotFound),
    };
    extract_value_at_position_from_bytes(payload, key_idx, key_pattern.len())
}

fn extract_value_at_position_from_bytes(
    payload: &[u8],
    key_idx: usize,
    key_len: usize,
) -> Result<String, SearchError> {
    if key_idx + key_len + 1 >= payload.len() {
        return Err(SearchError::InvalidInputFormat);
    }

    let after_key = &payload[key_idx + key_len..];
    let colon_idx = match find_byte(after_key, b':') {
        Some(idx) => idx,
        None => return Err(SearchError::InvalidInputFormat),
    };

    let after_colon = skip_whitespace_from_bytes(&after_key[colon_idx + 1..]);
    if after_colon.is_empty() {
        return Err(SearchError::InvalidInputFormat);
    }

    match after_colon[0] {
        b'"' => extract_string_value_from_bytes(after_colon),
        b'{' => extract_object_value_from_bytes(after_colon),
        b'[' => extract_array_value_from_bytes(after_colon),
        // maybe start next line
        _ => extract_primitive_value_from_bytes(after_colon),
    }
}

fn extract_string_value_from_bytes(input: &[u8]) -> Result<String, SearchError> {
    assert_eq!(input.get(0), Some(&b'"'));
    let mut i = 1; // Skip opening quote
    while i < input.len() {
        let byte = input[i];
        match byte {
            b'\\' => {
                if i + 2 >= input.len() {
                    i += 1;
                    break;
                } else {
                    // when use escaped, like: "\"test\"", don't break by \"
                    i += 2;
                }
            }
            b'"' => break,
            _ => {
                i += 1;
            }
        }
    }

    bytes_to_string(&input, 1, i)
}

fn extract_object_value_from_bytes(input: &[u8]) -> Result<String, SearchError> {
    assert_eq!(input.get(0), Some(&b'{'));
    let mut brace_count = 0;
    let mut end = 0;
    for (i, &byte) in input.iter().enumerate() {
        match byte {
            b'{' => brace_count += 1,
            b'}' => {
                brace_count -= 1;
                if brace_count == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
        end = i + 1;
    }

    bytes_to_string(&input, 0, end)
}

fn extract_array_value_from_bytes(input: &[u8]) -> Result<String, SearchError> {
    assert_eq!(input.get(0), Some(&b'['));
    let mut bracket_count = 0;
    let mut end = 0;
    for (i, &byte) in input.iter().enumerate() {
        match byte {
            b'[' => bracket_count += 1,
            b']' => {
                bracket_count -= 1;
                if bracket_count == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
        end = i + 1;
    }

    bytes_to_string(&input, 0, end)
}

fn extract_primitive_value_from_bytes(input: &[u8]) -> Result<String, SearchError> {
    let mut end = 0;
    for &byte in input {
        match byte {
            b',' | b'}' | b']' | b' ' | b'\n' | b'\t' | b'\r' => break,
            _ => end += 1,
        }
    }

    if end == 0 {
        return Err(SearchError::InvalidInputFormat);
    }

    bytes_to_string(&input, 0, end)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    pub fn extract_string_value_from_str(input: &str) -> Result<String, SearchError> {
        extract_string_value_from_bytes(input.as_bytes())
    }

    fn extract_object_value_from_str(input: &str) -> Result<String, SearchError> {
        extract_object_value_from_bytes(input.as_bytes())
    }

    fn extract_array_value_from_str(input: &str) -> Result<String, SearchError> {
        extract_array_value_from_bytes(input.as_bytes())
    }

    pub fn extract_primitive_value_from_str(input: &str) -> Result<String, SearchError> {
        extract_primitive_value_from_bytes(input.as_bytes())
    }

    #[test]
    fn test_search_key_simple() {
        let payload = r#"{"name": "Alice", "age": 30, "score": 95.5}"#;
        let result = search_key_case_sensitive(payload.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_case_sensitive(payload.as_bytes(), "age");
        assert_eq!(result.unwrap(), "30");

        let result = search_key_case_sensitive(payload.as_bytes(), "score");
        assert_eq!(result.unwrap(), "95.5");

        // boolean
        let payload = r#"{"active": true, "verified": false}"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "active");
        assert_eq!(result.unwrap(), "true");

        let result = search_key_case_sensitive(payload.as_bytes(), "verified");
        assert_eq!(result.unwrap(), "false");

        // null
        let payload = r#"{"data": null}"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "data");
        assert_eq!(result.unwrap(), "null");

        // nested object
        let payload = r#"{"user": {"name": "Bob", "details": {"age": 25}}}"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "user");
        assert_eq!(
            result.unwrap(),
            r#"{"name": "Bob", "details": {"age": 25}}"#
        );

        // array
        let payload = r#"{"numbers": [1, 2, 3], "users": [{"name": "Alice"}, {"name": "Bob"}]}"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "numbers");
        assert_eq!(result.unwrap(), "[1, 2, 3]");

        let result = search_key_case_sensitive(payload.as_bytes(), "users");
        assert_eq!(result.unwrap(), r#"[{"name": "Alice"}, {"name": "Bob"}]"#);

        // with whitespace
        let payload = r#"{ "name" : "Alice" , "age" :   30   }"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_case_sensitive(payload.as_bytes(), "age");
        assert_eq!(result.unwrap(), "30");

        // newline
        let payload = r#"{
            "name": "Alice",
            "config": {
                "debug": true
            }
        }"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_case_sensitive(payload.as_bytes(), "config");
        assert!(result.unwrap().contains("debug"));

        // escaped quotes
        let payload = r#"{"message": "He said \"Hello\" to me"}"#;
        let result = search_key_case_sensitive(payload.as_bytes(), "message");
        assert_eq!(result.unwrap(), r#"He said \"Hello\" to me"#);

        // empty string
        let payload = r#"{"empty": "", "name": "Alice"}"#;
        let result = search_key_case_sensitive(payload.as_bytes(), "empty");
        assert_eq!(result.unwrap(), "");

        // not found
        let payload = r#"{"name": "Alice"}"#;
        let result = search_key_case_sensitive(payload.as_bytes(), "nonexistent");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);

        // mixed string
        let payload = r#"random things in string, then suddenly comes a "name": "Alice""#;
        let result = search_key_case_sensitive(payload.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");
    }

    #[test]
    fn test_search_key_exception() {
        let payload = r#"{"name" "Alice"}"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "name");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::InvalidInputFormat);

        let payload = r#"{"name":}"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "name");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::InvalidInputFormat);
    }

    #[test]
    fn test_search_key_case_mixed() {
        let payload = r#"{"Name": "Alice", "AGE": 30}"#;

        let result = search_key_ignore_case(payload.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_ignore_case(payload.as_bytes(), "age");
        assert_eq!(result.unwrap(), "30");

        let result = search_key_ignore_case(payload.as_bytes(), "NonExistent");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);

        let result = search_key_case_sensitive(payload.as_bytes(), "name");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);

        // mixed case
        let payload = r#"{"UserName": "Alice", "Password": "secret"}"#;

        let result = search_key_ignore_case(payload.as_bytes(), "username");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_ignore_case(payload.as_bytes(), "PASSWORD");
        assert_eq!(result.unwrap(), "secret");
    }

    #[test]
    fn test_extract_string_basic_functions() {
        // skip whitespace
        assert_eq!(skip_whitespace("  hello"), "hello");
        assert_eq!(skip_whitespace("\t\n\r  hello"), "hello");
        assert_eq!(skip_whitespace("hello"), "hello");
        assert_eq!(skip_whitespace("   "), "");
        assert_eq!(skip_whitespace(""), "");

        // extract string
        assert_eq!(
            extract_string_value_from_str(r#""hello""#).unwrap(),
            "hello"
        );
        assert_eq!(
            extract_string_value_from_str(r#""hello","#).unwrap(),
            "hello"
        );
        assert_eq!(
            extract_string_value_from_str(r#""hello"}"#).unwrap(),
            "hello"
        );
        assert_eq!(extract_string_value_from_str(r#""""#).unwrap(), "");
        assert_eq!(
            extract_string_value_from_str(r#""hello world"#).unwrap(),
            "hello world"
        );
        assert_eq!(
            extract_string_value_from_str(r#""hello \"world\"""#).unwrap(),
            r#"hello \"world\""#
        );
        assert_eq!(
            extract_string_value_from_str(r#""line1\\nline2""#).unwrap(),
            r#"line1\\nline2"#
        );

        // not quoted string, get error
        // assert!(extract_string_value_from_str("hello").is_err());
        // assert!(extract_string_value_from_str("").is_err());
        // assert!(extract_string_value_from_str("123").is_err());

        // extract object
        assert_eq!(
            extract_object_value_from_str(r#"{"key": "value"}"#).unwrap(),
            r#"{"key": "value"}"#
        );
        assert_eq!(extract_object_value_from_str(r#"{}"#).unwrap(), "{}");

        let input = r#"{"user": {"name": "Alice", "details": {"age": 25}}}"#;
        assert_eq!(extract_object_value_from_str(input).unwrap(), input);

        assert_eq!(
            extract_object_value_from_str(r#"{"key": "value"}, "other""#).unwrap(),
            r#"{"key": "value"}"#
        );

        // assert!(extract_object_value_from_str("not an object").is_err());
        // assert!(extract_object_value_from_str("").is_err());
        // assert!(extract_object_value_from_str("[1,2,3]").is_err());

        // partial object
        let input = r#"{"key": "value", "nested": {"incomplete"#;
        let result = extract_object_value_from_str(input).unwrap();
        assert_eq!(result, input);

        // extract array
        assert_eq!(
            extract_array_value_from_str("[1, 2, 3]").unwrap(),
            "[1, 2, 3]"
        );
        assert_eq!(extract_array_value_from_str("[]").unwrap(), "[]");

        let input = r#"[{"name": "Alice"}, [1, 2, [3, 4]], "string"]"#;
        assert_eq!(extract_array_value_from_str(input).unwrap(), input);

        assert_eq!(
            extract_array_value_from_str(r#"[1, 2, 3], "other""#).unwrap(),
            "[1, 2, 3]"
        );
        // assert!(extract_array_value_from_str("not an array").is_err());
        // assert!(extract_array_value_from_str("").is_err());
        // assert!(extract_array_value_from_str(r#"{"key": "value"}"#).is_err());

        let input = "[1, 2, [3, 4";
        let result = extract_array_value_from_str(input).unwrap();
        assert_eq!(result, input);

        // number
        assert_eq!(extract_primitive_value_from_str("123").unwrap(), "123");
        assert_eq!(
            extract_primitive_value_from_str("123.45").unwrap(),
            "123.45"
        );
        assert_eq!(extract_primitive_value_from_str("-42").unwrap(), "-42");

        // boolean
        assert_eq!(extract_primitive_value_from_str("true").unwrap(), "true");
        assert_eq!(extract_primitive_value_from_str("false").unwrap(), "false");
        // null
        assert_eq!(extract_primitive_value_from_str("null").unwrap(), "null");

        // string mixed
        assert_eq!(extract_primitive_value_from_str("123,").unwrap(), "123");
        assert_eq!(extract_primitive_value_from_str("true}").unwrap(), "true");
        assert_eq!(extract_primitive_value_from_str("null]").unwrap(), "null");
        assert_eq!(extract_primitive_value_from_str("42 ").unwrap(), "42");

        // string with whitespace
        assert_eq!(extract_primitive_value_from_str("123\n").unwrap(), "123");
        assert_eq!(extract_primitive_value_from_str("true\t").unwrap(), "true");
        assert_eq!(extract_primitive_value_from_str("null\r").unwrap(), "null");

        // empty string
        assert!(extract_primitive_value_from_str("").is_err());
        assert!(extract_primitive_value_from_str("   ").is_err());
    }

    #[test]
    fn test_complex_real_world_json() {
        let payload = r#"{
            "api_version": "1.0",
            "status": "success",
            "data": {
                "users": [
                    {
                        "id": 1,
                        "name": "Alice",
                        "profile": {
                            "age": 30,
                            "verified": true,
                            "preferences": {
                                "theme": "dark",
                                "notifications": true
                            }
                        },
                        "tags": ["admin", "developer"]
                    },
                    {
                        "id": 2,
                        "name": "Bob",
                        "profile": {
                            "age": 25,
                            "verified": false,
                            "preferences": null
                        },
                        "tags": []
                    }
                ],
                "meta": {
                    "total": 2,
                    "page": 1,
                    "has_more": false
                }
            },
            "timestamp": "2025-01-15T10:30:00Z"
        }"#;

        assert_eq!(
            search_key_case_sensitive(payload.as_bytes(), "api_version").unwrap(),
            "1.0"
        );
        assert_eq!(
            search_key_case_sensitive(payload.as_bytes(), "status").unwrap(),
            "success"
        );
        assert!(search_key_case_sensitive(payload.as_bytes(), "data")
            .unwrap()
            .contains("users"));
        assert_eq!(
            search_key_case_sensitive(payload.as_bytes(), "timestamp").unwrap(),
            "2025-01-15T10:30:00Z"
        );
    }

    #[test]
    fn test_edge_case_search_key() {
        // duplicate key case
        let payload =
            r#"{"description": "This contains the word name in it", "name": "actual_name"}"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "name");
        assert_eq!(result.unwrap(), "actual_name");

        // unicode not support case
        let payload = r#"{"emoji": "🌟", "中文": "测试"}"#;

        let result = search_key_case_sensitive(payload.as_bytes(), "emoji");
        assert_eq!(result.unwrap(), "🌟");

        let result = search_key_case_sensitive(payload.as_bytes(), "中文");
        assert_eq!(result.unwrap(), "测试");

        // key with special characters
        let payload = r#"{"key-with-dash": "value1", "key_with_underscore": "value2", "key.with.dots": "value3"}"#;
        assert_eq!(
            search_key_case_sensitive(payload.as_bytes(), "key-with-dash").unwrap(),
            "value1"
        );
        assert_eq!(
            search_key_case_sensitive(payload.as_bytes(), "key_with_underscore").unwrap(),
            "value2"
        );
        assert_eq!(
            search_key_case_sensitive(payload.as_bytes(), "key.with.dots").unwrap(),
            "value3"
        );
    }

    #[test]
    fn test_large_json_performance() {
        let mut large_payload = String::from("{");

        for i in 0..1000 {
            if i > 0 {
                large_payload.push(',');
            }
            large_payload.push_str(&format!(r#""key{}": "value{}""#, i, i));
        }
        large_payload.push('}');

        let result = search_key_case_sensitive(large_payload.as_bytes(), "key500");
        assert_eq!(result.unwrap(), "value500");

        let result = search_key_case_sensitive(large_payload.as_bytes(), "key999");
        assert_eq!(result.unwrap(), "value999");

        let result = search_key_case_sensitive(large_payload.as_bytes(), "nonexistent");
        assert!(result.is_err());
    }
}
