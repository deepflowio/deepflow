/*
 * Copyright (c) 2022 Yunshan Networks
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

mod mysql;
mod postgre_convert;
mod postgresql;
mod redis;

pub use mysql::{MysqlHeader, MysqlInfo, MysqlLog};
pub use postgresql::{PostgreInfo, PostgresqlLog};
pub use redis::{decode, RedisInfo, RedisLog};

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

// not full of pg sql start. only log some necessary sql.
const POSTGRESQL_START: [&'static str; 33] = [
    //crud
    "SELECT",
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
    // other
    "GRANT",
    "WITH",
    "EXECUTE",
    "SET",
    "DECLARE",
    "MATERIALIZED",
    "SAVEPOINT",
    "CHECKPOINT",
    "ABORT",
    "ANALYZE",
    "CALL",
    "FETCH",
    "IMPORT",
    "LOAD",
    "LOCK",
    "PREPARE",
    "REFRESH",
    "REINDEX",
    "RELEASE",
    "RESET",
    "REVOKE",
    "START",
    "TABLE",
    "TRUNCATE",
];

pub fn is_postgresql(sql: &String) -> bool {
    let upper = sql.trim_start().to_ascii_uppercase();
    for i in POSTGRESQL_START.iter() {
        if upper.starts_with(i) {
            return true;
        }
    }
    false
}
