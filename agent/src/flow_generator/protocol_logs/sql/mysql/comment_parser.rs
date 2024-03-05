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

pub(super) struct MysqlCommentParserIter<'a> {
    sql: &'a [u8],
}

impl<'a> MysqlCommentParserIter<'a> {
    pub(super) fn new(s: &'a str) -> Self {
        Self { sql: s.as_bytes() }
    }
}

enum ParserState {
    PlainText,
    // with quote type (' or ")
    Quoted(u8),
    // with start index
    MultilineComment(usize),
}

impl<'a> Iterator for MysqlCommentParserIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let mut state = ParserState::PlainText;
        let mut offset = 0;
        while let Some(c) = self.sql.get(offset) {
            match (&state, c) {
                (ParserState::PlainText, b'\'') | (ParserState::PlainText, b'"') => {
                    state = ParserState::Quoted(*c);
                    offset += 1;
                }
                // comment type "# comment" "-- comment" and "/* comment */"
                (ParserState::PlainText, b'#')
                | (ParserState::PlainText, b'-')
                | (ParserState::PlainText, b'/') => {
                    // line comment: find next \n or end of str
                    if *c == b'#' || (*c == b'-' && self.sql.get(offset + 1) == Some(&b'-')) {
                        let start = if *c == b'#' { offset + 1 } else { offset + 2 };
                        let comment = &self.sql[start..];
                        let end = comment
                            .iter()
                            .position(|b| *b == b'\n')
                            .unwrap_or(comment.len());
                        let comment = unsafe {
                            // SAFTY:
                            // 1. The contents in self.sql is from &str.to_bytes(), which is valid utf-8
                            // 2. Offset `end` is at char boundries
                            std::str::from_utf8_unchecked(&comment[..end])
                        };
                        self.sql = &self.sql[start + end..];
                        return Some(comment.trim());
                    } else if *c == b'/' && self.sql.get(offset + 1) == Some(&b'*') {
                        offset += 2;
                        state = ParserState::MultilineComment(offset);
                    } else {
                        offset += 1;
                    }
                }
                // escaped character (2B) in quoted text, skip the next character
                (ParserState::Quoted(_), b'\\') => {
                    // also check the next character (after '\') to be a valid ascii char
                    let is_ascii = self
                        .sql
                        .get(offset + 1)
                        .map(|c| c.is_ascii())
                        .unwrap_or(false);
                    if !is_ascii {
                        self.sql = &self.sql[self.sql.len()..];
                        return None;
                    }
                    offset += 2;
                }
                (ParserState::Quoted(q), _) if q == c => {
                    state = ParserState::PlainText;
                    offset += 1;
                }
                (ParserState::MultilineComment(start), b'*')
                    if self.sql.get(offset + 1) == Some(&b'/') =>
                {
                    let comment = unsafe {
                        // SAFTY:
                        // 1. The contents in self.sql is from &str.to_bytes(), which is valid utf-8
                        // 2. Offset `start` and `offset` are at char boundries
                        std::str::from_utf8_unchecked(&self.sql[*start..offset])
                    };
                    self.sql = &self.sql[offset + 2..];
                    return Some(comment.trim());
                }
                _ => offset += 1,
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::MysqlCommentParserIter;

    #[test]
    fn test() {
        let sql_list = [
            (
                "SELECT * FROM orders WHERE status = 'pending' # TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b",
                vec!["TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b"]
            ),
            (
                "SELECT * FROM customers WHERE age > 30 -- TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b",
                vec!["TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b"])
                ,
            (
                "/* TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b */\
                SELECT * FROM products WHERE price < 10",
                vec!["TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b"]
            ),
            (
                "SELECT /* TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b \\*/ *
                FROM orders
                WHERE customer_id IN (
                    SELECT customer_id
                    FROM customers
                    WHERE age > 30
                ) # This query returns orders for customers over 30",
            vec![r"TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b \","This query returns orders for customers over 30"]
            ),
            (
                "SELECT *
                FROM products
                WHERE category IN (
                    SELECT category
                    FROM categories
                    WHERE -- This subquery filters out inactive categories
                        is_active = 1 /* \\ i am escape \\ TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b */
                ) # This query returns products from active categories ",
                vec!["This subquery filters out inactive categories",
                    r"\ i am escape \ TraceID: 2c2f8a47b754de66b45e1f0a7be8af1b",
                    "This query returns products from active categories"]
            ),
            (
                "SELECT * FROM orders WHERE status = 'pending' # Trace ID: 2c2f8a47b754de66b45e1f0a7be8af1b",
                vec!["Trace ID: 2c2f8a47b754de66b45e1f0a7be8af1b"]),
            (
                "SELECT * FROM orders WHERE status = 'pending' # Traceid: 2c2f8a47b754de66b45e1f0a7be8af1b",
                vec!["Traceid: 2c2f8a47b754de66b45e1f0a7be8af1b"]
            ),
            (
                "SELECT * FROM orders WHERE status = 'pending' # traceid: 2c2f8a47b754de66b45e1f0a7be8af1b",
                vec!["traceid: 2c2f8a47b754de66b45e1f0a7be8af1b"]
            ),
            (
                "SELECT * FROM orders WHERE status = 'pending' # Traceid:2c2f8a47b754de66b45e1f0a7be8af1b",
                vec!["Traceid:2c2f8a47b754de66b45e1f0a7be8af1b"]
            ),
            (
                r"SELECT * FROM orders WHERE status = 'pen\'ding' # Traceid:2c2f8a47b754de66b45e1f0a7be8af1b",
                vec!["Traceid:2c2f8a47b754de66b45e1f0a7be8af1b"]
            ),
        ];

        for i in sql_list {
            let c: Vec<&str> = MysqlCommentParserIter::new(i.0).map(|s| s.trim()).collect();
            assert_eq!(i.1, c);
        }
    }
}
