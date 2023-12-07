/*
 * Copyright (ch) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES Or CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::{
    cell::OnceCell,
    collections::HashMap,
    iter::{Enumerate, Peekable},
    slice::Iter,
};

use public::utils::hash::hash_to_u64;

use super::{forward, ObfuscateCache, BLANK_SPACE, QUESTION_MARK};

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Token {
    Keyword(Keyword),
    String(usize), // the end offset
    Separator(u8),
    Operator(Operator),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operator {
    ColonCast, // ::
    Ge,        // >=
    Gt,        // >
    Le,        // <=
    Lt,        // <
    Ne,        // <> or !=
    Regex,     // ~*

    At,                 // @
    Backtick,           // `
    Caret,              // ^
    Colon,              // :
    Dash,               // -
    Dot,                // .
    Equals,             // =
    ExclamationMark,    // !
    LeftCurlyBrace,     // {
    LeftSquareBracket,  // [
    Percent,            // %
    Pipe,               // |
    Plus,               // +
    PoundSign,          // #
    RightCurlyBrace,    // }
    RightSquareBracket, // ]
    Slash,              // /
    Star,               // *
    Tilde,              // ~

    // PostgreSQL specific Json operators
    JsonSelect,         // ->
    JsonSelectText,     // ->>
    JsonSelectPath,     // #>
    JsonSelectPathText, // #>>
    JsonContains,       // @>
    JsonContainsLeft,   // <@
    JsonKeyExists,      // ?
    JsonAnyKeysExist,   // ?|
    JsonAllKeysExist,   // ?&
    JsonDelete,         // #-
}

impl Operator {
    fn as_bytes(&self) -> &'static [u8] {
        match self {
            Operator::ColonCast => b"::",
            Operator::Ne => b"<>",
            Operator::Lt => b"<",
            Operator::Gt => b">",
            Operator::Le => b"<=",
            Operator::Ge => b">=",
            Operator::Regex => b"~*",
            Operator::Dash => b"-",
            Operator::ExclamationMark => b"!",
            Operator::Plus => b"+",
            Operator::PoundSign => b"#",
            Operator::Slash => b"/",
            Operator::Star => b"*",
            Operator::Equals => b"=",
            Operator::LeftSquareBracket => b"[",
            Operator::RightSquareBracket => b"]",
            Operator::Colon => b":",
            Operator::Caret => b"^",
            Operator::Percent => b"%",
            Operator::Pipe => b"|",
            Operator::Tilde => b"~",
            Operator::Backtick => b"`",
            Operator::At => b"@",
            Operator::LeftCurlyBrace => b"{",
            Operator::RightCurlyBrace => b"}",
            Operator::Dot => b".",
            Operator::JsonSelect => b"->",
            Operator::JsonSelectText => b"->>",
            Operator::JsonSelectPath => b"#>",
            Operator::JsonSelectPathText => b"#>>",
            Operator::JsonContains => b"@>",
            Operator::JsonContainsLeft => b"<@",
            Operator::JsonKeyExists => b"?",
            Operator::JsonAnyKeysExist => b"?|",
            Operator::JsonAllKeysExist => b"?&",
            Operator::JsonDelete => b"#-",
        }
    }
}

const MAX_KEYWORD_LENGTH: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Keyword {
    Alter,
    And,
    As,
    Begin,
    BooleanLiteralFalse,
    BooleanLiteralTrue,
    By,
    Commit,
    Create,
    Cross,
    Delete,
    Drop,
    False,
    From,
    Full,
    Grant,
    In,
    Inner,
    Insert,
    Into,
    Is,
    Join,
    Left,
    Like,
    Limit,
    Matched,
    Merge,
    Not,
    Offset,
    On,
    Or,
    Over,
    Output,
    Revoke,
    Right,
    Savepoint,
    Select,
    Set,
    Show,
    Then,
    Truncate,
    True,
    Union,
    Update,
    Use,
    Using,
    Values,
    Where,
    When,
}

impl Keyword {
    fn as_bytes(&self) -> &'static [u8] {
        match self {
            Keyword::Alter => b"ALTER",
            Keyword::And => b"AND",
            Keyword::As => b"AS",
            Keyword::Begin => b"BEGIN",
            Keyword::BooleanLiteralFalse => b"FALSE",
            Keyword::BooleanLiteralTrue => b"TRUE",
            Keyword::By => b"BY",
            Keyword::Commit => b"COMMIT",
            Keyword::Create => b"CREATE",
            Keyword::Cross => b"CROSS",
            Keyword::Delete => b"DELETE",
            Keyword::Drop => b"DROP",
            Keyword::False => b"FALSE",
            Keyword::From => b"FROM",
            Keyword::Full => b"FULL",
            Keyword::Grant => b"GRANT",
            Keyword::In => b"IN",
            Keyword::Inner => b"INNER",
            Keyword::Insert => b"INSERT",
            Keyword::Into => b"INTO",
            Keyword::Is => b"IS",
            Keyword::Join => b"JOIN",
            Keyword::Left => b"LEFT",
            Keyword::Like => b"LIKE",
            Keyword::Limit => b"LIMIT",
            Keyword::Matched => b"MATCHED",
            Keyword::Merge => b"MERGE",
            Keyword::Not => b"NOT",
            Keyword::Offset => b"OFFSET",
            Keyword::On => b"ON",
            Keyword::Or => b"OR",
            Keyword::Over => b"OVER",
            Keyword::Output => b"OUTPUT",
            Keyword::Revoke => b"REVOKE",
            Keyword::Right => b"RIGHT",
            Keyword::Savepoint => b"SAVEPOINT",
            Keyword::Select => b"SELECT",
            Keyword::Set => b"SET",
            Keyword::Show => b"SHOW",
            Keyword::Then => b"THEN",
            Keyword::Truncate => b"TRUNCATE",
            Keyword::True => b"TRUE",
            Keyword::Union => b"UNION",
            Keyword::Update => b"UPDATE",
            Keyword::Use => b"USE",
            Keyword::Using => b"USING",
            Keyword::Values => b"VALUES",
            Keyword::Where => b"WHERE",
            Keyword::When => b"WHEN",
        }
    }
}
thread_local! {
    static KEYWORDS: OnceCell<HashMap<&'static [u8], Keyword>> = OnceCell::new();
}

impl TryFrom<&[u8]> for Keyword {
    type Error = &'static str;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        KEYWORDS.with(|keys| {
            let map = keys.get_or_init(|| {
                let mut m = HashMap::new();
                m.insert(Keyword::Alter.as_bytes(), Keyword::Alter);
                m.insert(Keyword::And.as_bytes(), Keyword::And);
                m.insert(Keyword::As.as_bytes(), Keyword::As);
                m.insert(Keyword::Begin.as_bytes(), Keyword::Begin);
                m.insert(
                    Keyword::BooleanLiteralFalse.as_bytes(),
                    Keyword::BooleanLiteralFalse,
                );
                m.insert(
                    Keyword::BooleanLiteralTrue.as_bytes(),
                    Keyword::BooleanLiteralTrue,
                );
                m.insert(Keyword::By.as_bytes(), Keyword::By);
                m.insert(Keyword::Commit.as_bytes(), Keyword::Commit);
                m.insert(Keyword::Create.as_bytes(), Keyword::Create);
                m.insert(Keyword::Cross.as_bytes(), Keyword::Cross);
                m.insert(Keyword::Delete.as_bytes(), Keyword::Delete);
                m.insert(Keyword::Drop.as_bytes(), Keyword::Drop);
                m.insert(Keyword::False.as_bytes(), Keyword::False);
                m.insert(Keyword::From.as_bytes(), Keyword::From);
                m.insert(Keyword::Full.as_bytes(), Keyword::Full);
                m.insert(Keyword::Grant.as_bytes(), Keyword::Grant);
                m.insert(Keyword::In.as_bytes(), Keyword::In);
                m.insert(Keyword::Inner.as_bytes(), Keyword::Inner);
                m.insert(Keyword::Insert.as_bytes(), Keyword::Insert);
                m.insert(Keyword::Into.as_bytes(), Keyword::Into);
                m.insert(Keyword::Is.as_bytes(), Keyword::Is);
                m.insert(Keyword::Join.as_bytes(), Keyword::Join);
                m.insert(Keyword::Left.as_bytes(), Keyword::Left);
                m.insert(Keyword::Like.as_bytes(), Keyword::Like);
                m.insert(Keyword::Limit.as_bytes(), Keyword::Limit);
                m.insert(Keyword::Matched.as_bytes(), Keyword::Matched);
                m.insert(Keyword::Merge.as_bytes(), Keyword::Merge);
                m.insert(Keyword::Not.as_bytes(), Keyword::Not);
                m.insert(Keyword::Offset.as_bytes(), Keyword::Offset);
                m.insert(Keyword::On.as_bytes(), Keyword::On);
                m.insert(Keyword::Or.as_bytes(), Keyword::Or);
                m.insert(Keyword::Over.as_bytes(), Keyword::Over);
                m.insert(Keyword::Output.as_bytes(), Keyword::Output);
                m.insert(Keyword::Revoke.as_bytes(), Keyword::Revoke);
                m.insert(Keyword::Right.as_bytes(), Keyword::Right);
                m.insert(Keyword::Savepoint.as_bytes(), Keyword::Savepoint);
                m.insert(Keyword::Select.as_bytes(), Keyword::Select);
                m.insert(Keyword::Set.as_bytes(), Keyword::Set);
                m.insert(Keyword::Show.as_bytes(), Keyword::Show);
                m.insert(Keyword::Then.as_bytes(), Keyword::Then);
                m.insert(Keyword::Truncate.as_bytes(), Keyword::Truncate);
                m.insert(Keyword::True.as_bytes(), Keyword::True);
                m.insert(Keyword::Union.as_bytes(), Keyword::Union);
                m.insert(Keyword::Update.as_bytes(), Keyword::Update);
                m.insert(Keyword::Use.as_bytes(), Keyword::Use);
                m.insert(Keyword::Using.as_bytes(), Keyword::Using);
                m.insert(Keyword::Values.as_bytes(), Keyword::Values);
                m.insert(Keyword::Where.as_bytes(), Keyword::Where);
                m.insert(Keyword::When.as_bytes(), Keyword::When);
                m
            });
            map.get(value).ok_or("Failed to parse keyword").copied()
        })
    }
}

fn obfuscate(input: &[u8]) -> Vec<u8> {
    let length = input.len();
    let mut output = Vec::with_capacity(length);
    let mut iteration = input.iter().enumerate().peekable();
    let mut last_token = Token::Unknown;
    let mut last_keyword_is_set = false;
    let mut need_obfuscated = false; // if false, the original string can be returned directly without creating a new string
    let mut need_masked = false; // merge multiple question marks into one, for example, convert 'SELECT * FROM table WHERE id IN (1, 2, 3)' to 'SELECT * FROM table WHERE id IN (?)'
    let mut already_masked = false;
    let mut start = 0;
    while let Some(&(i, ch)) = iteration.peek() {
        let token = match ch {
            b'/' => {
                if input[i..].starts_with(b"//") {
                    Token::String(scan_single_line_comment(&mut iteration, length))
                } else if input[i..].starts_with(b"/*") {
                    Token::String(scan_multiline_comment(&mut iteration, length))
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::Slash)
                }
            }
            b'-' => {
                if input[i..].starts_with(b"->>") {
                    forward(&mut iteration, 3);
                    Token::Operator(Operator::JsonSelectText)
                } else if input[i..].starts_with(b"--") {
                    Token::String(scan_single_line_comment(&mut iteration, length))
                } else if input[i..].starts_with(b"->") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::JsonSelect)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::Dash)
                }
            }
            b'#' => {
                if input[i..].starts_with(b"#>>") {
                    forward(&mut iteration, 3);
                    Token::Operator(Operator::JsonSelectPathText)
                } else if input[i..].starts_with(b"#>") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::JsonSelectPath)
                } else if input[i..].starts_with(b"#-") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::JsonDelete)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::PoundSign)
                }
            }
            b'?' => {
                if input[i..].starts_with(b"?|") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::JsonAnyKeysExist)
                } else if input[i..].starts_with(b"?&") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::JsonAllKeysExist)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::JsonKeyExists)
                }
            }
            b':' => {
                if input[i..].starts_with(b"::") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::ColonCast)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::Colon)
                }
            }
            b'~' => {
                if input[i..].starts_with(b"~*") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::Regex)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::Tilde)
                }
            }
            b'"' | b'\'' => Token::String(scan_quoted_string(&mut iteration, length)),
            b'<' => {
                if input[i..].starts_with(b"<=") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::Le)
                } else if input[i..].starts_with(b"<>") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::Ne)
                } else if input[i..].starts_with(b"<@") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::JsonContainsLeft)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::Lt)
                }
            }
            b'!' => {
                if input[i..].starts_with(b"!~*") {
                    forward(&mut iteration, 3);
                    Token::Operator(Operator::Ne)
                } else if input[i..].starts_with(b"!=") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::Ne)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::ExclamationMark)
                }
            }
            b'@' => {
                if input[i..].starts_with(b"@>") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::JsonContains)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::At)
                }
            }
            b'>' => {
                if input[i..].starts_with(b">=") {
                    forward(&mut iteration, 2);
                    Token::Operator(Operator::Ge)
                } else {
                    forward(&mut iteration, 1);
                    Token::Operator(Operator::Gt)
                }
            }
            b';' | b',' | b'(' | b')' | b'\n' => {
                forward(&mut iteration, 1);
                Token::Separator(*ch)
            }
            b'+' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::Plus)
            }
            b'*' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::Star)
            }
            b'=' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::Equals)
            }
            b'[' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::LeftSquareBracket)
            }
            b']' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::RightSquareBracket)
            }
            b'^' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::Caret)
            }
            b'%' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::Percent)
            }
            b'|' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::Pipe)
            }
            b'`' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::Backtick)
            }
            b'{' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::LeftCurlyBrace)
            }
            b'}' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::RightCurlyBrace)
            }
            b'.' => {
                forward(&mut iteration, 1);
                Token::Operator(Operator::Dot)
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$' => {
                while let Some(_) = iteration.next_if(|&(_, ch)| {
                    ch.is_ascii_alphanumeric()
                        || *ch == b'_'
                        || *ch == b'.'
                        || *ch == b'$'
                        || *ch == b'*'
                }) {}
                let end = if let Some(&(i, _)) = iteration.peek() {
                    i
                } else {
                    length
                };

                if end - start > MAX_KEYWORD_LENGTH {
                    Token::String(end)
                } else if let Ok(v) = Keyword::try_from(unsafe {
                    // SAFETY:
                    // - input[start..end] have been checked for ascii characters
                    std::str::from_utf8_unchecked(&input[start..end])
                        .to_uppercase()
                        .as_bytes()
                }) {
                    Token::Keyword(v)
                } else {
                    Token::String(end)
                }
            }
            b' ' => {
                forward(&mut iteration, 1);
                start = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
                continue;
            }
            _ => {
                if need_obfuscated {
                    output.push(*ch);
                }
                forward(&mut iteration, 1);
                start = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
                continue;
            }
        };

        if matches!(token, Token::Operator(_))
            || token == Token::Keyword(Keyword::In)
            || token == Token::Keyword(Keyword::Values)
            || token == Token::Keyword(Keyword::Is)
            || token == Token::Keyword(Keyword::Like)
            || token == Token::Keyword(Keyword::Limit)
            || token == Token::Keyword(Keyword::Offset)
        {
            need_masked = true;
            already_masked = false;
            if !need_obfuscated {
                start = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
                // this token and its previous contents do not need to be confused, directly intercepted
                output.extend_from_slice(&input[..start]);
                need_obfuscated = true;
                last_token = token;
                continue;
            }
        } else if token == Token::Keyword(Keyword::As) {
            // the As keyword content is not displayed
            if !need_obfuscated {
                output.extend_from_slice(&input[..start]);
                need_obfuscated = true;
                start = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
                last_token = token;
                continue;
            }
        }
        match token {
            Token::String(end) => {
                if last_token == Token::Keyword(Keyword::As) {
                    last_token = token;
                    continue;
                }
                if !matches!(last_token, Token::Unknown)
                    && !matches!(last_token, Token::Separator(_))
                {
                    if need_obfuscated {
                        output.push(BLANK_SPACE);
                    }
                }
                if need_masked && !already_masked {
                    already_masked = true;
                    if need_obfuscated {
                        output.push(QUESTION_MARK);
                    }
                } else if !need_masked {
                    // if a number appears, the string needs to be obfuscated
                    if !need_obfuscated && has_digits(&input[start..end]) {
                        output.extend_from_slice(&input[..start]);
                        need_obfuscated = true;
                    }
                    if need_obfuscated {
                        output.extend_from_slice(&replace_digits(&input[start..end]));
                    }
                }
            }
            Token::Separator(s) => {
                if matches!(last_token, Token::Keyword(_)) && need_obfuscated {
                    output.push(BLANK_SPACE);
                }
                if need_masked
                    && ((*ch == b')' || *ch == b';') || (last_keyword_is_set && *ch == b','))
                {
                    need_masked = false;
                    already_masked = false;
                }
                if (!need_masked || !already_masked) && need_obfuscated {
                    output.push(s);
                }
            }
            Token::Keyword(ref k) => {
                if *k == Keyword::As {
                    last_token = token;
                    start = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
                    continue;
                } else if *k == Keyword::Set {
                    last_keyword_is_set = true;
                } else if *k != Keyword::Values
                    && *k != Keyword::In
                    && *k != Keyword::Is
                    && *k != Keyword::Like
                    && *k != Keyword::Limit
                    && *k != Keyword::Offset
                {
                    need_masked = false;
                    already_masked = false;
                    last_keyword_is_set = false;
                } else {
                    last_keyword_is_set = false;
                }

                if !matches!(last_token, Token::Unknown) && need_obfuscated {
                    output.push(BLANK_SPACE);
                }
                if need_obfuscated {
                    output.extend_from_slice(k.as_bytes());
                }
            }
            Token::Operator(ref o) => {
                if need_obfuscated {
                    if !matches!(last_token, Token::Operator(_))
                        && !matches!(last_token, Token::Separator(_))
                    {
                        output.push(BLANK_SPACE);
                    }
                    output.extend_from_slice(o.as_bytes());
                }
            }
            _ => {}
        }
        last_token = token;
        start = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
    }
    output
}

fn scan_quoted_string(iteration: &mut Peekable<Enumerate<Iter<'_, u8>>>, length: usize) -> usize {
    forward(iteration, 1); // consume the '"' or '\''
    while let Some(_) = iteration.next_if(|&(_, ch)| *ch != b'"' && *ch != b'\'') {}
    forward(iteration, 1); // consume the '"' or '\''
    iteration.peek().map(|(idx, _)| *idx).unwrap_or(length)
}

fn scan_single_line_comment(
    iteration: &mut Peekable<Enumerate<Iter<'_, u8>>>,
    length: usize,
) -> usize {
    forward(iteration, 2); // consume the "//"
    while let Some(_) = iteration.next_if(|&(_, ch)| *ch != b'\n') {}
    let off = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
    forward(iteration, 1); // consume the '\n'
    off
}

fn scan_multiline_comment(
    iteration: &mut Peekable<Enumerate<Iter<'_, u8>>>,
    length: usize,
) -> usize {
    forward(iteration, 2);
    let mut last_char_is_star = false;
    while let Some(_) = iteration.next_if(|&(_, ch)| {
        if *ch == b'*' {
            last_char_is_star = true;
        } else {
            last_char_is_star = false;
        }
        !last_char_is_star || *ch != b'/'
    }) {}
    forward(iteration, 1); // consume the '/'
    iteration.peek().map(|(idx, _)| *idx).unwrap_or(length)
}

pub fn attempt_obfuscation<'a>(
    obfuscate_cache: &Option<ObfuscateCache>,
    input: &[u8],
) -> Option<Vec<u8>> {
    let Some(cache) = obfuscate_cache else {
        return None;
    };

    let key = hash_to_u64(&input);
    if let Some(s) = cache.borrow_mut().get(&key) {
        return Some(s.clone());
    }

    let output = obfuscate(&input);
    if !output.is_empty() {
        let _ = cache.borrow_mut().put(key, output.clone());
        return Some(output);
    }
    None
}

fn has_digits(buffer: &[u8]) -> bool {
    for ch in buffer {
        if ch.is_ascii_digit() {
            return true;
        }
    }
    false
}

fn replace_digits(buffer: &[u8]) -> Vec<u8> {
    let mut scanning_digit = false;
    let mut filtered = Vec::with_capacity(buffer.len());
    for ch in buffer {
        if ch.is_ascii_digit() {
            if scanning_digit {
                continue;
            }
            scanning_digit = true;
            filtered.push(QUESTION_MARK);
            continue;
        }
        scanning_digit = false;
        filtered.push(*ch);
    }
    filtered
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, num::NonZeroUsize, rc::Rc};

    use lru::LruCache;

    use super::{super::OBFUSCATE_CACHE_SIZE, *};

    #[test]
    fn test_sql_obfuscate() {
        let obfuscate_cache = Some(Rc::new(RefCell::new(LruCache::new(
            NonZeroUsize::new(OBFUSCATE_CACHE_SIZE).unwrap(),
        ))));

        let test_cases = [
                (
                    "SELECT id FROM table;",
                    None,
                ),
                (
                    "DELETE FROM table WHERE id = 1;",
                    Some("DELETE FROM table WHERE id = ?;"),
                ),
                (
                    "UPDATE table SET column1 = value1, column2 = value2, column3 = value3 WHERE id = 1;",
                    Some("UPDATE table SET column? = ?,column? = ?,column? = ? WHERE id = ?;"),
                ),
                (
                    "INSERT INTO table (column1, column2, column3) VALUES (value1, value2, value3);",
                    Some("INSERT INTO table (column?,column?,column?) VALUES (?);"),
                ),
                (
                    "SELECT * FROM table WHERE name LIKE '%keyword%';",
                    Some("SELECT * FROM table WHERE name LIKE ?;"),
                ),
                (
                    "SELECT * FROM table WHERE id is Null;",
                    Some("SELECT * FROM table WHERE id IS ?;"),
                ),
                (
                    "SELECT * FROM table LIMIT 1 OFFSET 2;",
                    Some("SELECT * FROM table LIMIT ? OFFSET ?;"),
                ),
                (
                    "SELECT * FROM table123😊 WHERE id😊 = 123;",
                    Some("SELECT * FROM table?😊 WHERE id😊 = ?;"),
                ),
                (
                    "SELECT json_column ->'😊key' FROM ta123ble;",
                    Some("SELECT json_column -> ? FROM ta?ble;"),
                ),
                (
                    "SELECT * FROM table WHERE name ='Tom' OR name = \"Jerry\";",
                    Some("SELECT * FROM table WHERE name = ? OR name = ?;"),
                ),
                (
                    "SELECT * FROM table WHERE (age > 18 AND count < 10) OR (age <= 1 AND count >= 10) OR age != 100 OR count <> 100;",
                    Some("SELECT * FROM table WHERE (age > ? AND count < ?) OR (age <= ? AND count >= ?) OR age <> ? OR count <> ?;"),
                ),
                (
                    "SELECT * FROM table WHERE (id = 123 AND id NOT IN(1,2,3));",
                    Some("SELECT * FROM table WHERE (id = ? AND id NOT IN (?));"),
                ),
                (
                    "SELECT * FROM table where id = 1;-- some comment, 一些注释",
                    Some("SELECT * FROM table WHERE id = ?;-- some comment, 一些注释"),
                ),
                (
                    "SELECT * FROM table where id = 1;// some comment, 一些注释",
                    Some("SELECT * FROM table WHERE id = ?;// some comment, 一些注释"),
                ),
                (
                    r#"/* 这是一个多行注释*/ SELECT count(*) FROM table WHERE id = 100;"#,
                    Some(r#"/* 这是一个多行注释*/ SELECT count(*) FROM table WHERE id = ?;"#),
                ),
                (
                    "MERGE INTO Employees AS target USING EmployeeUpdates AS source ON (target.EmployeeID = source.EmployeeID) WHEN MATCHED THEN UPDATE SET target.Name = source.Name WHEN NOT MATCHED BY TARGET THEN INSERT (EmployeeID, Name) VALUES (source.EmployeeID, source.Name) WHEN NOT MATCHED BY SOURCE THEN DELETE OUTPUT $action, inserted.*, deleted.*;",
                    Some("MERGE INTO Employees  USING EmployeeUpdates ON (target.EmployeeID = ?) WHEN MATCHED THEN UPDATE SET target.Name = ? WHEN NOT MATCHED BY TARGET THEN INSERT (EmployeeID,Name) VALUES (?) WHEN NOT MATCHED BY SOURCE THEN DELETE OUTPUT $action,inserted.*,deleted.*;"),
                ),
                (
                    "SELECT CustomerID, CustomerName, City FROM Customers WHERE City = 'New York' UNION SELECT O.CustomerID, C.CustomerName, C.City FROM Orders O JOIN Customers C ON O.CustomerID = C.CustomerID WHERE C.City = 'New York';",
                    Some("SELECT CustomerID, CustomerName, City FROM Customers WHERE City = ? UNION SELECT O.CustomerID,C.CustomerName,C.City FROM Orders O JOIN Customers C ON O.CustomerID = ? WHERE C.City = ?;"),
                ),
                (
                    "SELECT CustomerID, CustomerName, City FROM Customers WHERE CustomerID IN (SELECT CustomerID FROM Orders WHERE CustomerID IN (SELECT CustomerID FROM Customers WHERE City = 'New York'));",
                    Some("SELECT CustomerID, CustomerName, City FROM Customers WHERE CustomerID IN ( SELECT CustomerID FROM Orders WHERE CustomerID IN ( SELECT CustomerID FROM Customers WHERE City = ?));"),
                ),
                (
                    "SELECT Orders.OrderID, Customers.CustomerName, Orders.OrderDate FROM Orders INNER JOIN Customers ON Orders.CustomerID = Customers.CustomerID WHERE Customers.Country = 'USA';",
                    Some("SELECT Orders.OrderID, Customers.CustomerName, Orders.OrderDate FROM Orders INNER JOIN Customers ON Orders.CustomerID = ? WHERE Customers.Country = ?;"),
                ),
                (
                    "SELECT Customers.CustomerName, Orders.OrderDate, (SELECT COUNT(*) FROM OrderDetails WHERE OrderDetails.OrderID = Orders.OrderID) AS TotalItems FROM Customers INNER JOIN Orders ON Customers.CustomerID = Orders.CustomerID WHERE Orders.OrderDate BETWEEN '2022-01-01' AND '2022-12-31';",
                    Some("SELECT Customers.CustomerName, Orders.OrderDate, (SELECT COUNT(*) FROM OrderDetails WHERE OrderDetails.OrderID = ?) FROM Customers INNER JOIN Orders ON Customers.CustomerID = ? WHERE Orders.OrderDate BETWEEN '?-?-?' AND '?-?-?';"),
                ),
                (
                    "SELECT CustomerName, OrderDate, TotalAmount FROM (SELECT Customers.CustomerName, Orders.OrderDate, SUM(OrderDetails.Quantity * OrderDetails.UnitPrice) OVER (PARTITION BY Customers.CustomerID) AS TotalAmount, ROW_NUMBER() OVER (PARTITION BY Customers.CustomerID ORDER BY Orders.OrderDate DESC) AS RowNum FROM Customers INNER JOIN Orders ON Customers.CustomerID = Orders.CustomerID INNER JOIN OrderDetails ON Orders.OrderID = OrderDetails.OrderID) AS Subquery WHERE RowNum = 1;",
                    Some("SELECT CustomerName, OrderDate, TotalAmount FROM (SELECT Customers.CustomerName, Orders.OrderDate, SUM(OrderDetails.Quantity * ?) OVER (PARTITION BY Customers.CustomerID),ROW_NUMBER() OVER (PARTITION BY Customers.CustomerID ORDER BY Orders.OrderDate DESC) FROM Customers INNER JOIN Orders ON Customers.CustomerID = ? INNER JOIN OrderDetails ON Orders.OrderID = ?) WHERE RowNum = ?;"),
                ),
            ];
        for (ti, tt) in test_cases.iter().enumerate() {
            assert_eq!(
                attempt_obfuscation(&obfuscate_cache, tt.0.as_bytes()),
                tt.1.map(|o| o.as_bytes().to_vec()),
                "{}",
                format!("Test case {}", ti)
            );
        }
    }
}
