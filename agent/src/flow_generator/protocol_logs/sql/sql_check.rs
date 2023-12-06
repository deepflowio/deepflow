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

const COMMON_SQL_START: [&'static str; 19] = [
    //crud
    "SELECT",
    "PREPARE",
    "INSERT",
    "UPDATE",
    "DELETE",
    // table manipulate
    "SHOW",
    "CREATE",
    "DROP",
    "ALTER",
    //sql explain
    "EXPLAIN",
    //other
    "GRANT",
    "SET",
    "SAVEPOINT",
    "RELEASE",
    "DECLARE",
    "CALL",
    "FETCH",
    "IMPORT",
    "REVOKE",
];

pub(super) fn is_valid_sql(first: &str, keywords: &[&'static str]) -> bool {
    for i in COMMON_SQL_START.iter().chain(keywords.iter()) {
        if first.eq_ignore_ascii_case(i) {
            return true;
        }
    }
    false
}

/*
    pg sql start with:

    ABORT                      COMMIT                     END                        LOCK                       REVOKE                     TRUNCATE
    ALTER                      COPY                       EXECUTE                    MOVE                       ROLLBACK                   UNLISTEN
    ANALYZE                    CREATE                     EXPLAIN                    NOTIFY                     SAVEPOINT                  UPDATE
    BEGIN                      DEALLOCATE                 FETCH                      PREPARE                    SECURITY LABEL             VACUUM
    CALL                       DECLARE                    GRANT                      REASSIGN                   SELECT                     VALUES
    CHECKPOINT                 DELETE FROM                IMPORT                     REFRESH MATERIALIZED VIEW  SET                        WITH
    CLOSE                      DISCARD                    INSERT                     REINDEX                    SHOW
    CLUSTER                    DO                         LISTEN                     RELEASE                    START
    COMMENT                    DROP                       LOAD                       RESET                      TABLE
*/

// not all of pg sql start keyword. only log some necessary sql.
const POSTGRESQL_START: [&'static str; 16] = [
    "WITH",
    "EXECUTE",
    "DECLARE",
    "MATERIALIZED",
    "ABORT",
    "ANALYZE",
    "LOAD",
    "LOCK",
    "CHECKPOINT",
    "REFRESH",
    "REINDEX",
    "RESET",
    "START",
    "TABLE",
    "CLUSTER",
    "TRUNCATE",
];

pub(super) fn is_postgresql(sql: &String) -> bool {
    if let Some(first) = trim_head_comment_and_get_first_word(sql.as_str(), 12) {
        is_valid_sql(first, &POSTGRESQL_START)
    } else {
        false
    }
}

/*
    mysql start with(not all of the mysql start first keyword):

    SELECT
    INSERT
    UPDATE
    DELETE
    PREPARE
    SHOW
    CREATE
    DROP
    ALTER
    EXPLAIN
    GRANT
    FLUSH
    BEGIN
    COMMIT
    ROLLBACK
    ANALYZE
    USE
    SET
    LOCK
    UNLOCK
    STOP
    START
    XA
    RELEASE
    SAVEPOINT
    LOAD
    FETCH
    IMPORT
    DESC
*/

// not all of sql start first keyword. only log some necessary sql.
const MYSQL_START: [&'static str; 14] = [
    "XA", "FLUSH", "SHOW", "USE", "LOCK", "UNLOCK", "STOP", "START", "LOAD", "ANALYZE", "BEGIN",
    "COMMIT", "ROLLBACK", "DESC",
];

pub(super) fn is_mysql(sql: &String) -> bool {
    if let Some(first) = trim_head_comment_and_get_first_word(sql.as_str(), 8) {
        is_valid_sql(first, &MYSQL_START)
    } else {
        false
    }
}

/*
    strip the sql comment from head and return first word and upper it.
    sql comment include:
        common multiple-line comment wrap by /**/, such as `/* some comment */ select 1` .

        mysql nested comment wrap by /*! */, it act as sql string in mysql but common comment in other DBMS, for example
        `/*! select * id from table */` only execute in mysql (not include mariadb).

        mysql nested comment wrap by /*!${mysql_version} */ it act as sql string where mysql version equal or greater than ${mysql_version},
        otherwise it act as common comment, for example `/*!80027 select id from table */` will only execute in mysql version >= 8.0.27.

        reference: https://dev.mysql.com/doc/refman/5.6/en/comments.html
*/
pub(super) fn trim_head_comment_and_get_first_word(
    mut sql: &str,
    first_word_max_len: usize,
) -> Option<&str> {
    sql = sql.trim_start();
    // if start with /*, strip all comment block before sql string.
    while sql.starts_with("/*") {
        if !sql.is_char_boundary(2) {
            return None;
        }
        (_, sql) = sql.split_at(2);

        if let Some(idx) = sql.find("*/") {
            if !sql.is_char_boundary(idx + 2) {
                return None;
            }
            (_, sql) = sql.split_at(idx + 2);
            sql = sql.trim_start();
        } else {
            return None;
        }
    }

    if let Some(idx) = sql.find(|c: char| !c.is_alphabetic()) {
        if idx <= first_word_max_len && idx != 0 {
            let (sub_sql, _) = sql.split_at(idx);
            return Some(sub_sql);
        }
    } else if sql.len() <= first_word_max_len {
        // if not have word boundary, assume as single word
        return Some(sql);
    }
    None
}

#[cfg(test)]
mod test_sql_check {
    use crate::flow_generator::protocol_logs::sql::sql_check::{
        is_valid_sql, trim_head_comment_and_get_first_word,
    };

    #[test]
    fn test_trim_head_comment_and_get_first_word() {
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"sEleCt 1", 6).unwrap(),
            &["SELECT"],
        ));
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"sEleCt 1", 7).unwrap(),
            &["SELECT"]
        ));
        assert_eq!(trim_head_comment_and_get_first_word(r"sEleCt 1", 5), None);
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"/* i am comment */SelecT 1", 6).unwrap(),
            &["SELECT"]
        ));
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"/* i am comment */ SelecT 1", 6).unwrap(),
            &["SELECT",]
        ));
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(
                r"/* i am comment */ /*i am comment*/ SelecT 1",
                6
            )
            .unwrap(),
            &["SELECT"]
        ));
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"/* i am comment */ /*i am comment*/SelecT 1", 6)
                .unwrap(),
            &["SELECT"]
        ));
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"/* i am comment * /*/ SelecT 1", 6).unwrap(),
            &["SELECT"]
        ));
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"/* i am comment *  /**/  /**  */ SelecT 1", 6)
                .unwrap(),
            &["SELECT"]
        ));
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"/* unable to parse */SelecT", 6).unwrap(),
            &["SELECT"]
        ));
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(r"/* able to parse */SelecT ", 6).unwrap(),
            &["SELECT"]
        ));
        assert_eq!(
            trim_head_comment_and_get_first_word(r"/* not a comment * / SelecT 1", 6),
            None
        );
        assert_eq!(
            trim_head_comment_and_get_first_word(r"/ * not a comment */ SelecT 1", 6),
            None
        );
        assert!(is_valid_sql(
            trim_head_comment_and_get_first_word(
                r"/* i am comment /* */ syntax error /* i am comment */ SelecT 1",
                6
            )
            .unwrap(),
            &["SYNTAX"]
        ));
        assert_eq!(
            trim_head_comment_and_get_first_word(
                r"/* i am comment /* */ -- syntax error /* i am comment */ SelecT 1",
                6
            ),
            None
        );
        assert_eq!(
            trim_head_comment_and_get_first_word(r"/ * not a comment *\/ SelecT 1", 6),
            None
        );
        assert_eq!(
            trim_head_comment_and_get_first_word(r"/ * not a comment  /*/*  */ SelecT 1", 6),
            None
        );
    }
}
