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

enum SqlBlock {
    StringBlock(u8),
    MultiLineComment,
    EndComment,
}

impl SqlBlock {
    fn is_end_token(&self, t: &[u8]) -> bool {
        match self {
            SqlBlock::StringBlock(c) => t.len() == 1 && t[0] == *c,
            SqlBlock::MultiLineComment => t.len() == 2 && t == b"*/",
            _ => unreachable!(),
        }
    }

    fn token_len(&self) -> usize {
        match self {
            SqlBlock::StringBlock(_) => 1,
            SqlBlock::MultiLineComment => 2,
            SqlBlock::EndComment => unreachable!(),
        }
    }

    fn is_comment_block(&self) -> bool {
        match self {
            SqlBlock::StringBlock(_) => false,
            SqlBlock::MultiLineComment => true,
            SqlBlock::EndComment => true,
        }
    }

    // return (accept, ignore)
    fn escape_action(&self) -> (bool, bool) {
        match self {
            SqlBlock::StringBlock(_) => (true, false),
            SqlBlock::MultiLineComment => (false, true),
            SqlBlock::EndComment => unreachable!(),
        }
    }

    fn get_block(t: &[u8]) -> Option<Self> {
        if t.len() == 1 {
            if t == b"'" || t == b"\"" {
                return Some(SqlBlock::StringBlock(t[0]));
            }
            if t == b"#" {
                return Some(SqlBlock::EndComment);
            }
        }

        if t.len() == 2 {
            if t == b"/*" {
                return Some(SqlBlock::MultiLineComment);
            }

            if t == b"--" {
                return Some(SqlBlock::EndComment);
            }
        }

        return None;
    }
}

pub(super) struct MysqlCommentParserIter<'a> {
    sql: &'a str,
    offset: usize,
}

enum Error {
    End,
    UnexpectedEscape(usize),
}

impl<'a> MysqlCommentParserIter<'a> {
    pub(super) fn new(s: &'a str) -> Self {
        Self { sql: s, offset: 0 }
    }

    fn read_token(&mut self, accept_escape: bool, ignore_escape: bool) -> Result<&[u8], Error> {
        let sql_byte = self.sql.as_bytes();
        while self.offset < self.sql.len() {
            let c = sql_byte[self.offset];
            if c == b'\\' {
                if ignore_escape {
                    self.offset += 1;
                    continue;
                } else if accept_escape {
                    self.offset += 2;
                    continue;
                } else {
                    return Err(Error::UnexpectedEscape(self.offset));
                }
            }

            if c == b'\'' || c == b'"' || c == b'#' {
                self.offset += 1;
                return Ok(&sql_byte[self.offset - 1..self.offset]);
            }

            if self.offset + 1 < self.sql.len() {
                let c = &sql_byte[self.offset..self.offset + 2];
                if c == b"--" || c == b"/*" || c == b"*/" {
                    self.offset += 2;
                    return Ok(&sql_byte[self.offset - 2..self.offset]);
                }
            }

            self.offset += 1;
        }
        return Err(Error::End);
    }
}

impl<'a> Iterator for MysqlCommentParserIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read_token(false, false) {
            Ok(t) => {
                let Some(b) = SqlBlock::get_block(t) else {
                    return None;
                };
                let offset = self.offset;
                match b {
                    SqlBlock::StringBlock(_) | SqlBlock::MultiLineComment => {
                        let (escape_accept, escape_ignore) = b.escape_action();
                        while let Ok(t) = self.read_token(escape_accept, escape_ignore) {
                            if !b.is_end_token(t) {
                                continue;
                            }
                            if b.is_comment_block() {
                                return Some(&self.sql[offset..self.offset - b.token_len()]);
                            }
                            return self.next();
                        }
                        None
                    }

                    SqlBlock::EndComment => {
                        let c = &self.sql.as_bytes()[self.offset..];
                        let line_end = c.iter().position(|b| *b == b'\n').unwrap_or(c.len());
                        let r = Some(&self.sql[self.offset..self.offset + line_end]);
                        self.offset += line_end + 1;
                        r
                    }
                }
            }
            Err(_) => None,
        }
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
