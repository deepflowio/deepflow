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
pub use public_derive_internals::types::PrioField;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum PrioStrings {
    Single(PrioField<String>),
    Multiple(HashMap<String, u8>),
}

impl Default for PrioStrings {
    fn default() -> Self {
        Self::Multiple(Default::default())
    }
}

impl Serialize for PrioStrings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Single(field) => field.serialize(serializer),
            Self::Multiple(_) => {
                let r = self.clone().into_sorted_vec();
                r.serialize(serializer)
            }
        }
    }
}

impl PrioStrings {
    pub fn new(multi: bool) -> Self {
        if multi {
            Self::Multiple(HashMap::new())
        } else {
            Self::Single(PrioField::default())
        }
    }

    pub fn is_default(&self) -> bool {
        match self {
            Self::Single(field) => field.is_default(),
            Self::Multiple(m) => m.is_empty(),
        }
    }

    pub fn push(&mut self, prio: u8, value: Cow<str>) {
        match self {
            Self::Single(field) if prio < field.prio() => {
                *field = PrioField::new(prio, value.into_owned())
            }
            Self::Multiple(m) => {
                if let Some(p) = m.get_mut(value.as_ref()) {
                    *p = prio.min(*p);
                } else {
                    m.insert(value.into_owned(), prio);
                }
            }
            _ => (),
        }
    }

    pub fn first(&self) -> Option<&String> {
        if self.is_default() {
            return None;
        }
        match self {
            Self::Single(field) => Some(field.get()),
            Self::Multiple(m) => m.iter().min_by_key(|(_, p)| *p).map(|(k, _)| k),
        }
    }

    pub fn merge(&mut self, other: PrioStrings) {
        match other {
            Self::Single(f) => {
                self.push(f.prio(), Cow::Owned(f.into_inner()));
            }
            Self::Multiple(m) => {
                for (k, p) in m {
                    self.push(p, Cow::Owned(k));
                }
            }
        }
    }

    pub fn into_sorted_vec(self) -> Vec<String> {
        match self {
            Self::Single(field) => vec![field.into_inner()],
            Self::Multiple(m) => {
                let mut strings = m.into_iter().collect::<Vec<_>>();
                // smaller is higher priority, sort by ascending order
                strings.sort_unstable_by_key(|(_, p)| *p);
                strings.into_iter().map(|(k, _)| k).collect()
            }
        }
    }
}
