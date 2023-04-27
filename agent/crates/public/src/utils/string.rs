/*
 * Copyright (c) 2023 Yunshan Networks
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

pub fn get_string_from_chars(chars: &[u8]) -> String {
    let mut end_index = chars.len();
    for (i, char) in chars.iter().enumerate() {
        if *char == b'\0' {
            end_index = i;
            break;
        }
    }
    let result = chars[..end_index]
        .iter()
        .map(|x| if x.is_ascii_graphic() { *x } else { b'.' }) // Check each character, instead of ascii characters, use dots instead
        .collect::<Vec<u8>>();
    unsafe {
        // safe because it has been checked that every character is ascii
        String::from_utf8_unchecked(result)
    }
}
