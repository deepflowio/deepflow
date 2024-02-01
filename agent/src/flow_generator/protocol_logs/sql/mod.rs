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

use std::{
    cell::RefCell,
    iter::{Enumerate, Peekable},
    rc::Rc,
    slice::Iter,
};

use lru::LruCache;

mod mongo;
mod mysql;
mod oracle;
mod postgre_convert;
mod postgresql;
mod redis;
mod sql_check;
mod sql_obfuscate;

pub use mongo::{MongoDBInfo, MongoDBLog};
pub use mysql::{MysqlInfo, MysqlLog};
pub use oracle::{OracleInfo, OracleLog};
pub use postgresql::{PostgreInfo, PostgresqlLog};
pub use redis::{RedisInfo, RedisLog};

pub type ObfuscateCache = Rc<RefCell<LruCache<u64, Vec<u8>>>>;

pub const OBFUSCATE_CACHE_SIZE: usize = 8192;
pub const QUESTION_MARK: u8 = b'?';
pub const BLANK_SPACE: u8 = b' ';

pub fn forward(iteration: &mut Peekable<Enumerate<Iter<'_, u8>>>, n: usize) {
    for _ in 0..n {
        if iteration.next().is_none() {
            return;
        }
    }
}
