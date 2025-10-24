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
    bytes_to_string, find_bytes_case_sensitive, find_bytes_ignore_case, skip_whitespace_from_bytes,
    SearchError,
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
    if key.is_empty() {
        return Err(SearchError::InvalidInputFormat);
    }

    let mut cursor = 0usize;
    while cursor < payload.len() {
        let relative_idx = match finder(&payload[cursor..], &key.as_bytes()) {
            Some(idx) => idx,
            None => return Err(SearchError::KeyNotFound),
        };
        let absolute_idx = cursor + relative_idx;
        cursor = absolute_idx.saturating_add(1);
        // priority: tag > attribute
        // 先尝试解 tag，如果不是再尝试解 attribute
        if let Some((start, end)) =
            extract_tag_value(payload, &key.as_bytes(), absolute_idx, finder)
        {
            return bytes_to_string(payload, start, end);
        }

        if let Some((start, end)) = extract_attribute_value(payload, absolute_idx, key.len()) {
            return bytes_to_string(payload, start, end);
        }
    }
    Err(SearchError::KeyNotFound)
}

fn extract_tag_value(
    payload: &[u8],
    key: &[u8],
    key_start_idx: usize,
    finder: fn(&[u8], &[u8]) -> Option<usize>,
) -> Option<(usize, usize)> {
    // find out if tag is <tag
    if !is_opening_tag(payload, key_start_idx, key.len()) {
        return None;
    }

    if key_start_idx + key.len() > payload.len() {
        return None;
    }

    let key_end_idx = key_start_idx + key.len();
    let mut tag_close_idx = key_end_idx;
    while tag_close_idx < payload.len() {
        if payload[tag_close_idx] == b'>' {
            break;
        }
        tag_close_idx += 1;
    }

    if tag_close_idx >= payload.len() {
        return None;
    }

    // find out if tag is <tag/>
    if is_self_closing_tag(payload, key_end_idx, tag_close_idx) {
        return None;
    }

    let content_start_idx = tag_close_idx + 1;
    if content_start_idx > payload.len() {
        return None;
    }

    // find close tag like </tag>, value is between <tag> and </tag>
    let mut close_tag = Vec::with_capacity(key.len() + 3);
    close_tag.extend_from_slice(b"</");
    close_tag.extend_from_slice(key);
    close_tag.push(b'>');

    let content_end_idx = match finder(&payload[content_start_idx..], &close_tag) {
        Some(idx) => content_start_idx + idx,
        None => payload.len(),
    };

    Some((content_start_idx, content_end_idx))
}

// find out if tag is <tag
fn is_opening_tag(payload: &[u8], start_idx: usize, key_len: usize) -> bool {
    if start_idx == 0 || start_idx > payload.len() {
        return false;
    }
    if payload[start_idx - 1] != b'<' {
        return false;
    }

    let end_idx = start_idx + key_len;
    if end_idx >= payload.len() {
        return false;
    }

    matches!(payload[end_idx], b'>' | b'/' | b' ' | b'\t' | b'\n' | b'\r')
}

fn is_self_closing_tag(payload: &[u8], end_idx: usize, tag_close_idx: usize) -> bool {
    let mut idx = tag_close_idx;
    while idx > end_idx {
        idx -= 1;
        match payload[idx] {
            b' ' | b'\t' | b'\n' | b'\r' => continue,
            b'/' => return true,
            _ => return false,
        }
    }
    false
}

fn extract_attribute_value(
    payload: &[u8],
    key_start_idx: usize,
    key_len: usize,
) -> Option<(usize, usize)> {
    if !is_attribute_boundary_before(payload, key_start_idx) {
        return None;
    }
    if !inside_open_tag(payload, key_start_idx) {
        return None;
    }

    let key_end_idx = key_start_idx + key_len;
    if key_end_idx > payload.len() {
        return None;
    }

    let equal_char_start_idx = skip_whitespace_from_bytes(&payload[key_end_idx..]);
    // when we cannot find '=' or any values after attribute key, should not return None
    // so we could hint the upstream caller: we found key but value is nothing
    // 当 attribute key 后面没有可用内容时，返回结束索引，告诉上游调用后面是空值，而不是没找到 key
    if equal_char_start_idx.is_empty() || equal_char_start_idx[0] != b'=' {
        return Some((key_end_idx, key_end_idx));
    }

    // find absolute value index in payload
    // value_idx = key_end_idx + whitespace_len + 1 = key_end_idx + (payload[key_end_idx..].len() - trimmed_after_key_end.len()) + 1
    let value_idx = key_end_idx + payload[key_end_idx..].len() - equal_char_start_idx.len() + 1;
    if value_idx > payload.len() {
        return None;
    }

    let (start, end) = find_attribute_value_range(&payload[value_idx..]);
    Some((value_idx + start, value_idx + end))
}

fn find_attribute_value_range(input: &[u8]) -> (usize, usize) {
    let trimmed = skip_whitespace_from_bytes(input);
    if trimmed.is_empty() {
        return (0, 0);
    }
    let offset = input.len() - trimmed.len();
    let first = trimmed[0];

    if first == b'"' || first == b'\'' {
        // if value inside "" or ''
        let mut idx = 1;
        while idx < trimmed.len() {
            match trimmed[idx] {
                m if m == first => break, // find matched pair
                _ => idx += 1,
            }
        }
        (offset + 1, offset + idx)
    } else {
        let mut idx = 0;
        while idx < trimmed.len() {
            match trimmed[idx] {
                b' ' | b'\t' | b'\n' | b'\r' | b'>' => break,
                _ => idx += 1,
            }
        }
        (offset, offset + idx)
    }
}

// find out if attribute was inside another key
fn is_attribute_boundary_before(payload: &[u8], start_idx: usize) -> bool {
    if start_idx == 0 {
        return true;
    }

    match payload[start_idx - 1] {
        b' ' | b'\t' | b'\n' | b'\r' | b'<' => true,
        _ => false,
    }
}

// find out if attribute is <tag attr="value">
fn inside_open_tag(payload: &[u8], mut idx: usize) -> bool {
    while idx > 0 {
        idx -= 1;
        match payload[idx] {
            b'<' => {
                return matches!(
                    payload[idx + 1],
                    b':' | b'_' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
                );
            }
            b'>' => return false,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    fn search_tag(
        payload: &[u8],
        tag_name: &str,
        finder: fn(&[u8], &[u8]) -> Option<usize>,
    ) -> Result<String, SearchError> {
        let mut cursor = 0usize;
        while cursor < payload.len() {
            let relative_idx = match finder(&payload[cursor..], &tag_name.as_bytes()) {
                Some(idx) => idx,
                None => return Err(SearchError::KeyNotFound),
            };
            let absolute_idx = cursor + relative_idx;
            cursor = absolute_idx.saturating_add(1);

            if let Some((start, end)) =
                extract_tag_value(payload, &tag_name.as_bytes(), absolute_idx, finder)
            {
                return bytes_to_string(payload, start, end);
            }
        }

        Err(SearchError::KeyNotFound)
    }

    fn search_attribute(
        payload: &[u8],
        attr_name: &str,
        finder: fn(&[u8], &[u8]) -> Option<usize>,
    ) -> Result<String, SearchError> {
        let mut cursor = 0usize;
        while cursor < payload.len() {
            let relative_idx = match finder(&payload[cursor..], &attr_name.as_bytes()) {
                Some(idx) => idx,
                None => return Err(SearchError::KeyNotFound),
            };
            let absolute_idx = cursor + relative_idx;
            cursor = absolute_idx.saturating_add(1);
            if let Some((start, end)) =
                extract_attribute_value(payload, absolute_idx, attr_name.len())
            {
                return bytes_to_string(payload, start, end);
            }
        }

        Err(SearchError::KeyNotFound)
    }
    #[test]
    fn test_search_tag_content_simple() {
        let payloads = vec![
            ("<name>Alice</name>", "Alice"),
            ("<name>  Alice  </name>", "  Alice  "),
            ("<name></name>", ""),
        ];

        for (payload, expected) in payloads {
            let result = search_tag(payload.as_bytes(), "name", find_bytes_ignore_case);
            assert_eq!(result.unwrap(), expected);
        }
    }

    #[test]
    fn test_search_tag_content_complicated() {
        // nested
        let payload = "<user><name>Alice</name><age>30</age></user>";

        let result = search_tag(payload.as_bytes(), "user", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "<name>Alice</name><age>30</age>");

        let result = search_tag(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Alice");

        let result = search_tag(payload.as_bytes(), "age", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "30");

        // self-closing
        let result = search_tag("<name/>".as_bytes(), "name", find_bytes_ignore_case);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);

        // not end
        let result = search_tag("<name>Alice".as_bytes(), "name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Alice");

        // non-exists key
        let result = search_tag(
            "<name>Alice</name>".as_bytes(),
            "age",
            find_bytes_ignore_case,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);
    }

    #[test]
    fn test_search_tag_content_multiline() {
        let payload = r#"<config>
            <name>Alice</name>
            <settings>
                <theme>dark</theme>
            </settings>
        </config>"#;

        let result = search_tag(payload.as_bytes(), "config", find_bytes_ignore_case);
        assert!(result.clone().unwrap().contains("name>Alice</name"));
        assert!(result.unwrap().contains("theme>dark</theme"));
    }

    #[test]
    fn test_search_tag_mixed_case() {
        // ignore case
        let payload = "<NAME>Alice</NAME><Age>30</Age>";

        let result = search_tag(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Alice");

        let result = search_tag(payload.as_bytes(), "AGE", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "30");

        let result = search_tag(payload.as_bytes(), "Name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Alice");

        // case sensitive
        let result = search_tag(
            "<name>Alice</name>".as_bytes(),
            "NAME",
            find_bytes_case_sensitive,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);

        // mixed case
        let payload = "<UserName>Alice</UserName><PassWord>secret</PassWord>";

        let result = search_tag(payload.as_bytes(), "username", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Alice");

        let result = search_tag(payload.as_bytes(), "PASSWORD", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "secret");

        let result = search_tag(payload.as_bytes(), "UserName", find_bytes_case_sensitive);
        assert_eq!(result.unwrap(), "Alice");
    }

    #[test]
    fn test_search_attribute() {
        // quoted
        let payload = r#"<user id="123" name="Alice" active="true">"#;

        let result = search_attribute(payload.as_bytes(), "id", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "123");

        let result = search_attribute(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Alice");

        let result = search_attribute(payload.as_bytes(), "active", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "true");

        // single-quoted
        let payload = r#"<user id='456' name='Bob'>"#;

        let result = search_attribute(payload.as_bytes(), "id", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "456");

        let result = search_attribute(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Bob");

        // unquoted
        let payload = "<user id=789 name=Charlie>";

        let result = search_attribute(payload.as_bytes(), "id", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "789");

        let result = search_attribute(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Charlie");

        let payload = r#"<user  id = "123"  name = "Alice"  >"#;

        let result = search_attribute(payload.as_bytes(), "id", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "123");

        let result = search_attribute(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Alice");

        // not found attribute
        let payload = r#"<user id="123">"#;
        let result = search_tag(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);

        let result = search_attribute(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);

        // malformed
        let result = search_attribute("<user id=\"123\"".as_bytes(), "id", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "123");

        // repeated
        let result = search_key_case_sensitive(
            r#"<user name="Alice"><name>Bob</name></user>"#.as_bytes(),
            "name",
        );
        assert_eq!(result.unwrap(), "Alice");

        // self-closing tag
        let payload = r#"<user id="123" name="Alice"/>"#;

        let result = search_attribute(payload.as_bytes(), "id", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "123");

        let result = search_attribute(payload.as_bytes(), "name", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "Alice");
    }

    #[test]
    fn test_search_key() {
        let result = search_key_case_sensitive(r#"<name>Alice</name>"#.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_case_sensitive(
            r#"<root>prefix name <name>Content</name></root>"#.as_bytes(),
            "name",
        );
        assert_eq!(result.unwrap(), "Content");

        let result = search_key_case_sensitive(r#"<user ns:name="Alice"/>"#.as_bytes(), "ns:name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_case_sensitive(r#"<user  name =  "Alice"/>"#.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_case_sensitive(r#"<ns:name>Alice</ns:name>"#.as_bytes(), "ns:name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_case_sensitive(
            r#"<user username="alice"/><name>bob</name>"#.as_bytes(),
            "name",
        );
        assert_eq!(result.unwrap(), "bob");
    }

    #[test]
    fn test_search_key_ignore_case() {
        let result = search_key_ignore_case(r#"<NAME>Alice</NAME>"#.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");

        let result = search_key_ignore_case(r#"<user NAME="Alice"/>"#.as_bytes(), "name");
        assert_eq!(result.unwrap(), "Alice");

        // not found started key
        let result = search_key_ignore_case(r#"<root></name>"#.as_bytes(), "name");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SearchError::KeyNotFound);
    }

    #[test]
    fn test_attribute_value_extraction_in_context() {
        // Test double quoted values in XML attribute context
        let result = search_attribute(
            r#"<user name="Alice">"#.as_bytes(),
            "name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "Alice");

        // Test single quoted values
        let result = search_attribute(
            r#"<user name='Bob'>"#.as_bytes(),
            "name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "Bob");

        // Test unquoted values
        let result = search_attribute(
            r#"<user name=Charlie>"#.as_bytes(),
            "name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "Charlie");

        // Test values with spaces
        let result = search_attribute(
            r#"<user name="John Doe">"#.as_bytes(),
            "name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "John Doe");

        // Test numeric values
        let result = search_attribute(
            r#"<user age=30>"#.as_bytes(),
            "age",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "30");

        // Test boolean values
        let result = search_attribute(
            r#"<user active=false>"#.as_bytes(),
            "active",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "false");

        // Test special characters
        let result = search_attribute(
            r#"<user email="test@example.com">"#.as_bytes(),
            "email",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "test@example.com");

        // Test values with XML special characters
        let result = search_attribute(
            r#"<user data="<xml>content</xml>">"#.as_bytes(),
            "data",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "<xml>content</xml>");

        // Test empty quoted values
        let result = search_attribute(
            r#"<user name="">"#.as_bytes(),
            "name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "");

        // Test values with whitespace padding
        let result = search_attribute(
            r#"<user  name =  "Alice"  >"#.as_bytes(),
            "name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "Alice");

        // Test self-closing tags
        let result = search_attribute(
            r#"<user name="Alice"/>"#.as_bytes(),
            "name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "Alice");

        // Test multiple attributes
        let result = search_attribute(
            r#"<user id="123" name="Alice" active="false">"#.as_bytes(),
            "name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "Alice");

        // Test attribute with namespace
        let result = search_attribute(
            r#"<ns:user ns:name="Alice">"#.as_bytes(),
            "ns:name",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "Alice");

        // Test attribute value containing equals
        let result = search_attribute(
            r#"<config path="/api/v1=test">"#.as_bytes(),
            "path",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "/api/v1=test");
    }

    #[test]
    fn test_complex_real_world_xml() {
        let payload = r#"<?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Header>
                    <auth token="abc123" user="admin"/>
                </soap:Header>
                <soap:Body>
                    <getUserRequest>
                        <userId>12345</userId>
                        <includeProfile>true</includeProfile>
                    </getUserRequest>
                    <metadata version="1.0">
                        <timestamp>2025-01-15T10:30:00Z</timestamp>
                        <source>api-gateway</source>
                    </metadata>
                </soap:Body>
            </soap:Envelope>
        "#;

        assert_eq!(
            search_attribute(payload.as_bytes(), "token", find_bytes_case_sensitive).unwrap(),
            "abc123"
        );
        assert_eq!(
            search_attribute(payload.as_bytes(), "user", find_bytes_case_sensitive).unwrap(),
            "admin"
        );
        assert_eq!(
            search_attribute(payload.as_bytes(), "version", find_bytes_case_sensitive).unwrap(),
            "1.0"
        );
    }

    #[test]
    fn test_edge_cases_tag_names() {
        let payload = r#"
            <user-info>Alice</user-info>
            <user_profile>Bob</user_profile>
            <user.data>Charlie</user.data>
            <user123>David</user123>
        "#;

        assert_eq!(
            search_tag(payload.as_bytes(), "user-info", find_bytes_case_sensitive).unwrap(),
            "Alice"
        );
        assert_eq!(
            search_tag(
                payload.as_bytes(),
                "user_profile",
                find_bytes_case_sensitive
            )
            .unwrap(),
            "Bob"
        );
        assert_eq!(
            search_tag(payload.as_bytes(), "user.data", find_bytes_case_sensitive).unwrap(),
            "Charlie"
        );
        assert_eq!(
            search_tag(payload.as_bytes(), "user123", find_bytes_case_sensitive).unwrap(),
            "David"
        );
    }

    #[test]
    fn test_unicode_support() {
        let payload = r#"<用户>张三</用户><emoji>🌟</emoji><中文>测试</中文>"#;

        assert_eq!(
            search_tag(payload.as_bytes(), "用户", find_bytes_case_sensitive).unwrap(),
            "张三"
        );
        assert_eq!(
            search_tag(payload.as_bytes(), "emoji", find_bytes_case_sensitive).unwrap(),
            "🌟"
        );
        assert_eq!(
            search_tag(payload.as_bytes(), "中文", find_bytes_case_sensitive).unwrap(),
            "测试"
        );
    }

    #[test]
    fn test_xml_with_full_format() {
        // cdata
        let payload = r#"<message><![CDATA[This is <b>HTML</b> content]]></message>"#;

        let result = search_tag(payload.as_bytes(), "message", find_bytes_ignore_case);
        assert_eq!(result.unwrap(), "<![CDATA[This is <b>HTML</b> content]]>");

        let payload = r#"
            <root xmlns:ns1="http://example.com/ns1" xmlns:ns2="http://example.com/ns2">
                <ns1:user id="123">
                    <ns1:name>Alice</ns1:name>
                    <ns2:profile>
                        <ns2:age>30</ns2:age>
                    </ns2:profile>
                </ns1:user>
            </root>
        "#;

        assert_eq!(
            search_tag(payload.as_bytes(), "ns1:name", find_bytes_ignore_case).unwrap(),
            "Alice"
        );
        assert_eq!(
            search_tag(payload.as_bytes(), "ns2:age", find_bytes_ignore_case).unwrap(),
            "30"
        );
        assert_eq!(
            search_attribute(payload.as_bytes(), "id", find_bytes_case_sensitive).unwrap(),
            "123"
        );

        // comment
        let payload = r#"
            <?xml version="1.0"?>
            <!-- This is a comment -->
            <root>
                <!-- Another comment -->
                <name>Alice</name>
                <?processing instruction?>
                <age>30</age>
            </root>
        "#;

        assert_eq!(
            search_tag(payload.as_bytes(), "name", find_bytes_case_sensitive).unwrap(),
            "Alice"
        );
        assert_eq!(
            search_tag(payload.as_bytes(), "age", find_bytes_case_sensitive).unwrap(),
            "30"
        );

        let root_content =
            search_tag(payload.as_bytes(), "root", find_bytes_case_sensitive).unwrap();
        assert!(root_content.contains("<!-- Another comment -->"));
        assert!(root_content.contains("<?processing instruction?>"));

        // recover exception case
        let payload1 = "<name>Alice<age>30</age>".as_bytes();
        assert_eq!(
            search_tag(payload1, "name", find_bytes_case_sensitive).unwrap(),
            "Alice<age>30</age>"
        );
        assert_eq!(
            search_tag(payload1, "age", find_bytes_case_sensitive).unwrap(),
            "30"
        );

        let payload2 = r#"<user id="123" name="Alice" active>"#.as_bytes();
        assert_eq!(
            search_attribute(payload2, "id", find_bytes_case_sensitive).unwrap(),
            "123"
        );
        assert_eq!(
            search_attribute(payload2, "name", find_bytes_case_sensitive).unwrap(),
            "Alice"
        );
        assert_eq!(
            search_attribute(payload2, "active", find_bytes_case_sensitive).unwrap(),
            ""
        );
    }

    #[test]
    fn test_performance_large_xml() {
        let mut large_payload = String::from("<root>");

        for i in 0..1000 {
            large_payload.push_str(&format!("<item{0}>value{0}</item{0}>", i));
        }
        large_payload.push_str("</root>");

        let result = search_tag(
            large_payload.as_bytes(),
            "item500",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "value500");

        let result = search_tag(
            large_payload.as_bytes(),
            "item999",
            find_bytes_case_sensitive,
        );
        assert_eq!(result.unwrap(), "value999");
    }
}
