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

use std::fmt;

use serde::Serialize;

pub struct PrioField<T> {
    prio: u8,
    field: T,
}

impl<T> PrioField<T> {
    pub fn new(prio: u8, field: T) -> Self {
        Self { prio, field }
    }

    pub fn into_inner(self) -> T {
        self.field
    }

    pub fn prio(&self) -> u8 {
        self.prio
    }

    pub fn get(&self) -> &T {
        &self.field
    }

    pub fn set(&mut self, prio: u8, field: T) {
        if prio < self.prio {
            self.prio = prio;
            self.field = field;
        }
    }

    pub fn set_with<F>(&mut self, prio: u8, f: F)
    where
        F: FnOnce() -> T,
    {
        if prio < self.prio {
            self.prio = prio;
            self.field = f();
        }
    }
}

impl<T: Clone> Clone for PrioField<T> {
    fn clone(&self) -> Self {
        Self {
            prio: self.prio,
            field: self.field.clone(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for PrioField<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrioField {{ prio: {}, field: {:?} }}",
            self.prio, self.field
        )
    }
}

impl<T: Default + PartialEq> PrioField<T> {
    pub fn is_default(&self) -> bool {
        self.field == T::default()
    }
}

impl<T: Default> Default for PrioField<T> {
    fn default() -> Self {
        Self {
            prio: u8::MAX,
            field: T::default(),
        }
    }
}

impl<T: PartialEq> PartialEq for PrioField<T> {
    fn eq(&self, other: &Self) -> bool {
        self.prio == other.prio && self.field == other.field
    }
}

impl<T: Eq> Eq for PrioField<T> {}

impl<T: Serialize> Serialize for PrioField<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.field.serialize(serializer)
    }
}
