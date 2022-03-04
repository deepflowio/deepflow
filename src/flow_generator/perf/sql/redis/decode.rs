use std::str;

const SEPARATOR_SIZE: usize = 2;

// 协议解析：http://redisdoc.com/topic/protocol.html#

fn find_separator(payload: &[u8]) -> Option<usize> {
    let len = payload.len();
    if len < 2 {
        return None;
    }

    for i in 0..len - 1 {
        if payload[i] == b'\r' && payload[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

fn decode_integer(payload: &[u8]) -> Option<(isize, usize)> {
    let separator_pos = find_separator(payload)?;
    // 整数至少占一位
    if separator_pos < 1 {
        return None;
    }

    let integer = str::from_utf8(&payload[..separator_pos])
        .unwrap_or_default()
        .parse::<isize>()
        .ok()?;

    Some((integer, separator_pos + SEPARATOR_SIZE))
}

// 格式为"$3\r\nSET\r\n"
fn decode_dollor(payload: &[u8], strict: bool) -> Option<(&[u8], usize)> {
    let mut offset = 1; // 开头的$
    let (next_data_len, sub_offset) = decode_integer(&payload[offset..])?;

    // $-1 $0时返回
    if next_data_len <= 0 {
        return Some((
            &payload[offset..offset + sub_offset - SEPARATOR_SIZE],
            offset + sub_offset,
        ));
    }

    offset += sub_offset;
    let next_data_len = next_data_len as usize;

    if offset + next_data_len > payload.len()
        || payload[offset + next_data_len] != b'\r'
        || payload[offset + next_data_len + 1] != b'\n'
    {
        if strict {
            return None;
        }
        // 返回所有内容
        return Some((&payload[offset..], payload.len()));
    }

    // 完全合法
    Some((
        &payload[offset..offset + next_data_len],
        offset + next_data_len + 2,
    ))
}

// 命令为"set mykey myvalue"，实际封装为"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"
fn decode_asterisk(payload: &[u8], strict: bool) -> Option<(Vec<u8>, usize)> {
    let mut offset = 1; // 开头的 *

    // 提取请求参数个数/批量回复个数
    let (next_data_num, sub_offset) = decode_integer(&payload[offset..])?;

    if next_data_num <= 0 {
        // 无内容的多条批量回复: "*-1\r\n"
        // 空白内容的多条批量回复: "*0\r\n"
        return Some((
            payload[offset..offset + sub_offset - SEPARATOR_SIZE].to_vec(),
            offset + sub_offset,
        ));
    }
    offset += sub_offset;

    let mut ret_vec = Vec::new();
    let len = payload.len();

    for _ in 0..next_data_num {
        if let Some((sub_vec, sub_offset, _)) = decode(&payload[offset..], strict) {
            if sub_offset == 0 {
                if strict {
                    return None;
                }
                return Some((ret_vec, offset));
            }

            if !ret_vec.is_empty() {
                ret_vec.push(b' ');
            }
            ret_vec.extend_from_slice(sub_vec.as_slice());

            offset += sub_offset;
            if offset >= len {
                return Some((ret_vec, len));
            }
        }
    }
    Some((ret_vec, offset))
}

fn decode_str(payload: &[u8], limit: usize) -> Option<(&[u8], usize)> {
    let len = payload.len();
    let separator_pos = find_separator(payload).unwrap_or(len);

    if separator_pos > limit {
        return Some((
            // 截取数据后，并不会在末尾增加'...'提示
            &payload[..limit],
            limit,
        ));
    }

    Some((&payload[..separator_pos], separator_pos))
}

// 函数在入参为"$-1"或"-1"时都返回"-1", 使用第三个参数区分是否为错误回复
pub fn decode(payload: &[u8], strict: bool) -> Option<(Vec<u8>, usize, bool)> {
    if payload.len() < SEPARATOR_SIZE {
        return None;
    }

    match payload[0] {
        // 请求或多条批量回复
        b'*' => decode_asterisk(payload, strict).map(|(v, s)| (v, s, false)),
        // 状态回复,整数回复
        b'+' | b':' => decode_str(payload, 32).map(|(v, s)| (v.to_vec(), s, false)),
        // 错误回复
        b'-' => decode_str(payload, 256).map(|(v, s)| (v.to_vec(), s, true)),
        // 批量回复
        b'$' => decode_dollor(payload, strict).map(|(v, s)| (v.to_vec(), s, false)),
        _ => None,
    }
}

pub fn decode_error_code(context: &[u8]) -> Option<&[u8]> {
    for (i, ch) in context.iter().enumerate() {
        if *ch == b' ' || *ch == b'\n' {
            return Some(&context[..i]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode() {
        let payload = [b'*', b'-', b'1', b'\r', b'\n'];
        let (context, n, e) = decode(payload.as_slice(), true).unwrap();
        assert_eq!(context, "-1".as_bytes());
        assert_eq!(n, payload.len());
        assert_eq!(e, false);

        let payload = [
            b'*', b'3', b'\r', b'\n', b'$', b'3', b'\r', b'\n', b'S', b'E', b'T', b'\r', b'\n',
            b'$', b'5', b'\r', b'\n', b'm', b'y', b'k', b'e', b'y', b'\r', b'\n', b'$', b'7',
            b'\r', b'\n', b'm', b'y', b'v', b'a', b'l', b'u', b'e', b'\r', b'\n',
        ];

        let (context, n, e) = decode(payload.as_slice(), true).unwrap();
        assert_eq!(context, "SET mykey myvalue".as_bytes());
        assert_eq!(n, payload.len());
        assert_eq!(e, false);

        let payload = [b'$', b'0', b'\r', b'\n'];
        let (context, n, _) = decode(payload.as_slice(), true).unwrap();
        assert_eq!(context, "0".as_bytes());
        assert_eq!(n, payload.len());

        let payload = [b'$', b'-', b'1', b'\r', b'\n'];
        let (context, n, e) = decode(payload.as_slice(), false).unwrap();
        assert_eq!(context, "-1".as_bytes());
        assert_eq!(n, payload.len());
        assert_eq!(e, false);

        let payload = [b'$', b'9', b'\r', b'\n', b'1', b'2', b'3', b'4', b'5'];
        let (context, n, _) = decode(payload.as_slice(), false).unwrap();
        assert_eq!(context, "12345".as_bytes());
        assert_eq!(n, payload.len());

        let payload = [b'$', b'9', b'\r', b'\n', b'1', b'2', b'3', b'4', b'5'];
        assert_eq!(decode(payload.as_slice(), true), None);

        let payload = [b'-', b'1', b'\r', b'\n'];
        let (context, n, e) = decode(payload.as_slice(), true).unwrap();
        assert_eq!(context, "-1".as_bytes());
        assert_eq!(n, 2);
        assert_eq!(e, true);
    }
}
