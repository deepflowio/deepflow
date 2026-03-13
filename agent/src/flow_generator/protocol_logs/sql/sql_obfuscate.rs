/*
 * Copyright (ch) 2024 Yunshan Networks
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

use std::{borrow::Cow, fmt::Write, str};

use sqlparser::{
    dialect::GenericDialect,
    keywords::Keyword,
    tokenizer::{Token, Tokenizer, TokenizerError, Word},
};

use public::utils::hash::hash_to_u64;

use super::ObfuscateCache;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("tokenize failed")]
    TokenizeFailed(#[from] TokenizerError),
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Default)]
pub struct Obfuscator;

impl Obfuscator {
    fn is_operator(token: &Token) -> bool {
        match token {
            Token::DoubleEq
            | Token::Eq
            | Token::Neq
            | Token::Lt
            | Token::Gt
            | Token::LtEq
            | Token::GtEq => true,
            Token::Word(w) => match w.keyword {
                Keyword::IN | Keyword::IS | Keyword::LIKE => true,
                _ => false,
            },
            _ => false,
        }
    }

    fn is_before_obfuscated(token: &Token) -> bool {
        if Self::is_operator(token) {
            return true;
        }
        match token {
            Token::Word(w) => match w.keyword {
                Keyword::LIMIT | Keyword::OFFSET => true,
                Keyword::VALUES => true,
                Keyword::AS => true,
                _ => false,
            },
            _ => false,
        }
    }

    // write all tokens before the first obfuscated token to the output
    fn prepare_obfuscated(expected_len: usize, tokens: &[Token]) -> String {
        let mut obfuscated = String::with_capacity(expected_len);
        for token in tokens {
            let _ = write!(obfuscated, "{token}");
        }
        obfuscated
    }

    pub fn apply(sql: &str) -> Result<Cow<'_, str>> {
        let dialect = GenericDialect;
        let tokens = match Tokenizer::new(&dialect, sql)
            .with_unescape(false)
            .tokenize()
        {
            Ok(tokens) => tokens,
            Err(TokenizerError { location, .. }) => {
                // if sql is truncated, try again before error location, and append a phantom word token to the end
                let byte_offset = sql
                    .split_inclusive('\n')
                    .take(location.line.saturating_sub(1) as usize)
                    .map(|l| l.len())
                    .sum::<usize>()
                    + (location.column as usize).saturating_sub(1);
                let truncated = &sql[..byte_offset.min(sql.len())];
                let mut tokens = Tokenizer::new(&dialect, truncated)
                    .with_unescape(false)
                    .tokenize()?;
                tokens.push(Token::Word(Word {
                    value: "".to_string(),
                    quote_style: None,
                    keyword: Keyword::NoKeyword,
                }));
                tokens
            }
        };
        let mut obfuscated = None;

        let mut iter = tokens.iter().enumerate().peekable();
        while let Some((index, token)) = iter.next() {
            match token {
                Token::SingleQuotedString(_)
                | Token::DoubleQuotedString(_)
                | Token::Number(_, _) => {
                    let obfuscated = obfuscated.get_or_insert_with(|| {
                        Self::prepare_obfuscated(tokens.len() / 2, &tokens[..index])
                    });
                    let _ = write!(obfuscated, "?");
                }
                _ if Self::is_before_obfuscated(token) => {
                    let obfuscated = obfuscated.get_or_insert_with(|| {
                        Self::prepare_obfuscated(tokens.len() / 2, &tokens[..index])
                    });
                    let _ = write!(obfuscated, "{token}");
                    // consume any whitespaces
                    while let Some((_, token)) = iter.peek() {
                        if matches!(token, Token::Whitespace(_)) {
                            let _ = write!(obfuscated, "{token}");
                            iter.next();
                        } else {
                            break;
                        }
                    }
                    let Some((_, token)) = iter.next() else {
                        break;
                    };
                    match token {
                        Token::LParen => {
                            // handle parentheses
                            // consume iterator until the matching closing parenthesis
                            let mut parens = 1usize;
                            while let Some((_, token)) = iter.next() {
                                match token {
                                    Token::LParen => parens += 1,
                                    Token::RParen => parens = parens.saturating_sub(1),
                                    _ => {}
                                }
                                if parens == 0 {
                                    break;
                                }
                            }
                            let _ = write!(obfuscated, "(?)");
                        }
                        _ => {
                            // consume all valid tokens
                            // - word
                            // - number
                            // - signs
                            // - period
                            while let Some((_, token)) = iter.peek() {
                                match token {
                                    Token::Word(_) | Token::Period => {
                                        iter.next();
                                    }
                                    Token::Number(_, _)
                                    | Token::Plus
                                    | Token::Minus
                                    | Token::Mul
                                    | Token::Div
                                    | Token::DuckIntDiv
                                    | Token::Mod => {
                                        iter.next();
                                    }
                                    _ => break,
                                }
                            }
                            let _ = write!(obfuscated, "?");
                        }
                    }
                }
                _ => {
                    if let Some(obfuscated) = obfuscated.as_mut() {
                        let _ = write!(obfuscated, "{token}");
                    }
                }
            }
        }

        match obfuscated {
            Some(obfuscated) => Ok(Cow::Owned(obfuscated)),
            None => Ok(Cow::Borrowed(sql)),
        }
    }
}

#[derive(Default)]
pub struct CachedObfuscator {
    // if cache is not set, do not apply obfuscation
    cache: Option<ObfuscateCache>,
}

impl CachedObfuscator {
    pub fn new(cache: Option<ObfuscateCache>) -> Self {
        Self { cache }
    }

    pub fn apply<'a>(&self, sql: &'a str) -> Result<Cow<'a, str>> {
        let Some(cache) = self.cache.as_ref() else {
            return Ok(Cow::Borrowed(sql));
        };

        let key = hash_to_u64(&sql);
        if let Some(s) = cache.borrow_mut().get(&key) {
            return Ok(Cow::Owned(s.clone()));
        }
        let obfuscated = Obfuscator::apply(sql)?;
        if obfuscated != sql {
            cache.borrow_mut().put(key, obfuscated.to_string());
        }
        Ok(obfuscated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG_ESCAPED_SQL: &str = r#"UPDATE ai_chat_log_contents SET content='[{\"uuid\": \"23ee0e7b-768f-4bd8-87a2-5f37240d13da\", \"sceneId\": \"4538f15c-c04b-4bd2-a67e-fac3cb5a5466\", \"userMessage\": \"\\u7535\\u5546\\u7cfb\\u7edf\\u5728 05:00-05:10 \\u54cd\\u5e94\\u6162\", \"loading\": true, \"aiResponse\": {\"workflow\": {\"type\": \"RootCause\", \"data\": {\"query\": \"\\u7535\\u5546\\u7cfb\\u7edf\\u5728 05:00-05:10 \\u54cd\\u5e94\\u6162\", \"steps\": [{\"id\": \"59b0764d-69c6-401e-8577-a773b0160c22\", \"type\": \"scene_analysis\", \"title\": \"\", \"isComplete\": true, \"data\": {\"analysisDescription\": \"\\u7528\\u6237\\u53cd\\u9988\\u7535\\u5546\\u7cfb\\u7edf\\u57282025-08-05 05:00:00\\u81f32025-08-05 05:10:00\\u65f6\\u95f4\\u6bb5\\u5185\\u5b58\\u5728\\u54cd\\u5e94\\u6162\\u7684\\u6027\\u80fd\\u74f6\\u9888\\u95ee\\u9898\\uff0c\\u672a\\u6307\\u5b9a\\u5177\\u4f53\\u7684\\u5bf9\\u8c61\\u7c7b\\u578b\\uff0c\\u9ed8\\u8ba4\\u4e3aauto_instance\\u7c7b\\u578b\\u3002\", \"problemDescription\": {\"business_name\": \"\\u7535\\u5546\\u7cfb\\u7edf\", \"instance_name\": null, \"instance_type\": \"auto_instance\", \"problem_category\": \"bottleneck\", \"time_now\": \"2025-08-05 11:01:03\", \"time_range\": \"2025-08-05 05:00:00 - 2025-08-05 05:10:00\"}}}, {\"id\": \"5daf8ae6-31e2-41ec-8662-719d20bee895\","#;

    #[test]
    fn test_sql_obfuscate() {
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
                    "SELECT `id` FROM `database.table` WHERE id = 1;",
                    Some("SELECT `id` FROM `database.table` WHERE id = ?;"),
                ),
                (
                    "UPDATE table SET column1 = value1, column2 = value2, column3 = value3 WHERE id = 1;",
                    Some("UPDATE table SET column1 = ?, column2 = ?, column3 = ? WHERE id = ?;"),
                ),
                (
                    "INSERT INTO table (column1, column2, column3) VALUES (value1, value2, value3);",
                    Some("INSERT INTO table (column1, column2, column3) VALUES (?);"),
                ),
                (
                    "SELECT * FROM table WHERE name LIKE '%keyword%';",
                    Some("SELECT * FROM table WHERE name LIKE ?;"),
                ),
                (
                    "SELECT * FROM table WHERE id is Null;",
                    Some("SELECT * FROM table WHERE id is ?;"),
                ),
                (
                    "SELECT * FROM table LIMIT 1 OFFSET 2;",
                    Some("SELECT * FROM table LIMIT ? OFFSET ?;"),
                ),
                (
                    "SELECT * FROM table123😊 WHERE id😊 = 123;",
                    Some("SELECT * FROM table123😊 WHERE id😊 = ?;"),
                ),
                (
                    "SELECT json_column ->'😊key' FROM ta123ble;",
                    Some("SELECT json_column ->? FROM ta123ble;"),
                ),
                (
                    "SELECT * FROM table WHERE name ='Tom' OR name = \"Jerry\";",
                    Some("SELECT * FROM table WHERE name =? OR name = ?;"),
                ),
                (
                    "SELECT * FROM table WHERE (age > 18 AND count < 10) OR (age <= 1 AND count >= 10) OR age != 100 OR count <> 100;",
                    Some("SELECT * FROM table WHERE (age > ? AND count < ?) OR (age <= ? AND count >= ?) OR age <> ? OR count <> ?;"),
                ),
                (
                    "SELECT * FROM table WHERE (id = 123 AND id NOT IN(1,2,3));",
                    Some("SELECT * FROM table WHERE (id = ? AND id NOT IN(?));"),
                ),
                (
                    "SELECT * FROM table where id = 1;-- some comment, 一些注释",
                    Some("SELECT * FROM table where id = ?;-- some comment, 一些注释"),
                ),
                (
                    "SELECT * FROM table where id = 1;// some comment, 一些注释",
                    Some("SELECT * FROM table where id = ?;// some comment, 一些注释"),
                ),
                (
                    r#"/* 这是一个多行注释*/ SELECT count(*) FROM table WHERE id = 100;"#,
                    Some(r#"/* 这是一个多行注释*/ SELECT count(*) FROM table WHERE id = ?;"#),
                ),
                (
                    "MERGE INTO Employees AS target USING EmployeeUpdates AS source ON (target.EmployeeID = source.EmployeeID) WHEN MATCHED THEN UPDATE SET target.Name = source.Name WHEN NOT MATCHED BY TARGET THEN INSERT (EmployeeID, Name) VALUES (source.EmployeeID, source.Name) WHEN NOT MATCHED BY SOURCE THEN DELETE OUTPUT $action, inserted.*, deleted.*;",
                    Some("MERGE INTO Employees AS ? USING EmployeeUpdates AS ? ON (target.EmployeeID = ?) WHEN MATCHED THEN UPDATE SET target.Name = ? WHEN NOT MATCHED BY TARGET THEN INSERT (EmployeeID, Name) VALUES (?) WHEN NOT MATCHED BY SOURCE THEN DELETE OUTPUT $action, inserted.*, deleted.*;"),
                ),
                (
                    "SELECT CustomerID, CustomerName, City FROM Customers WHERE City = 'New York' UNION SELECT O.CustomerID, C.CustomerName, C.City FROM Orders O JOIN Customers C ON O.CustomerID = C.CustomerID WHERE C.City = 'New York';",
                    Some("SELECT CustomerID, CustomerName, City FROM Customers WHERE City = ? UNION SELECT O.CustomerID, C.CustomerName, C.City FROM Orders O JOIN Customers C ON O.CustomerID = ? WHERE C.City = ?;"),
                ),
                (
                    "SELECT CustomerID, CustomerName, City FROM Customers WHERE CustomerID IN (SELECT CustomerID FROM Orders WHERE CustomerID IN (SELECT CustomerID FROM Customers WHERE City = 'New York'));",
                    Some("SELECT CustomerID, CustomerName, City FROM Customers WHERE CustomerID IN (?);"),
                ),
                (
                    "SELECT Orders.OrderID, Customers.CustomerName, Orders.OrderDate FROM Orders INNER JOIN Customers ON Orders.CustomerID = Customers.CustomerID WHERE Customers.Country = 'USA';",
                    Some("SELECT Orders.OrderID, Customers.CustomerName, Orders.OrderDate FROM Orders INNER JOIN Customers ON Orders.CustomerID = ? WHERE Customers.Country = ?;"),
                ),
                (
                    "SELECT Customers.CustomerName, Orders.OrderDate, (SELECT COUNT(*) FROM OrderDetails WHERE OrderDetails.OrderID = Orders.OrderID) AS TotalItems FROM Customers INNER JOIN Orders ON Customers.CustomerID = Orders.CustomerID WHERE Orders.OrderDate BETWEEN '2022-01-01' AND '2022-12-31';",
                    Some("SELECT Customers.CustomerName, Orders.OrderDate, (SELECT COUNT(*) FROM OrderDetails WHERE OrderDetails.OrderID = ?) AS ? FROM Customers INNER JOIN Orders ON Customers.CustomerID = ? WHERE Orders.OrderDate BETWEEN ? AND ?;"),
                ),
                (
                    "SELECT CustomerName, OrderDate, TotalAmount FROM (SELECT Customers.CustomerName, Orders.OrderDate, SUM(OrderDetails.Quantity * OrderDetails.UnitPrice) OVER (PARTITION BY Customers.CustomerID) AS TotalAmount, ROW_NUMBER() OVER (PARTITION BY Customers.CustomerID ORDER BY Orders.OrderDate DESC) AS RowNum FROM Customers INNER JOIN Orders ON Customers.CustomerID = Orders.CustomerID INNER JOIN OrderDetails ON Orders.OrderID = OrderDetails.OrderID) AS Subquery WHERE RowNum = 1;",
                    Some("SELECT CustomerName, OrderDate, TotalAmount FROM (SELECT Customers.CustomerName, Orders.OrderDate, SUM(OrderDetails.Quantity * OrderDetails.UnitPrice) OVER (PARTITION BY Customers.CustomerID) AS ?, ROW_NUMBER() OVER (PARTITION BY Customers.CustomerID ORDER BY Orders.OrderDate DESC) AS ? FROM Customers INNER JOIN Orders ON Customers.CustomerID = ? INNER JOIN OrderDetails ON Orders.OrderID = ?) AS ? WHERE RowNum = ?;"),
                ),
                (
                    "select * from vm where (/*hello*/name = '40.211-sxdl-1060a');",
                    Some("select * from vm where (/*hello*/name = ?);"),
                ),
                (
                    "SELECT * FROM `process` WHERE `process`.`deleted_at` IS NULL",
                    Some("SELECT * FROM `process` WHERE `process`.`deleted_at` IS ?"),
                ),
                (
                    "CREATE TABLE 'quote''andunquote'''",
                    Some("CREATE TABLE ?"),
                ),
                (
                    LONG_ESCAPED_SQL,
                    Some("UPDATE ai_chat_log_contents SET content=?"),
                )
            ];
        for (input, expected) in test_cases.iter() {
            let result = Obfuscator::apply(input).unwrap();
            let expected = match expected.as_ref() {
                None => input,
                Some(expected) => *expected,
            };
            assert_eq!(result.as_ref(), expected, "testcase failed: `{input}`");
        }
    }

    #[test]
    fn multiple_line_truncated() {
        let input = r#"
SELECT *
FROM table
WHERE name = 'hell"#;
        let expected = r#"
SELECT *
FROM table
WHERE name = ?"#;
        let result = Obfuscator::apply(input).unwrap();
        assert_eq!(result, expected);
    }
}
