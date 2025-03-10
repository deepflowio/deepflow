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

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::hash::Hash;
use std::mem;
use std::ops::RangeBounds;
use std::ptr;

use ahash::AHashMap;

pub struct ChronoMap<T, K, V>
where
    T: Clone + Eq + Ord,
    K: Clone + PartialEq + Eq + Hash,
{
    entries: AHashMap<K, *mut Node<T, K, V>>,
    timeline: VecDeque<*mut TimeHead<T, K, V>>,
}

struct TimeHead<T, K, V>
where
    T: Eq + Ord,
{
    time: T,
    next: *mut Node<T, K, V>,
}

impl<T: Eq + Ord, K, V> PartialEq for TimeHead<T, K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl<T: Eq + Ord, K, V> Eq for TimeHead<T, K, V> {}

impl<T: Eq + Ord, K, V> Ord for TimeHead<T, K, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.time.cmp(&other.time)
    }
}

impl<T: Eq + Ord, K, V> PartialOrd for TimeHead<T, K, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct Node<T: Eq + Ord, K, V> {
    key: K,
    value: V,

    // time chain
    head: *mut TimeHead<T, K, V>,
    prev: *mut Node<T, K, V>,
    next: *mut Node<T, K, V>,
}

impl<T, K, V> ChronoMap<T, K, V>
where
    T: Clone + Eq + Ord,
    K: Clone + PartialEq + Eq + Hash,
{
    pub fn new() -> Self {
        Self {
            entries: AHashMap::new(),
            timeline: VecDeque::new(),
        }
    }

    pub fn with_capacity(entry_cap: usize, time_cap: usize) -> Self {
        Self {
            entries: AHashMap::with_capacity(entry_cap),
            timeline: VecDeque::with_capacity(time_cap),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn shrink_to(&mut self, entry_cap: usize, time_cap: usize) {
        self.entries.shrink_to(entry_cap);
        self.timeline.shrink_to(time_cap);
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let Some(node) = self.entries.get(key) else {
            return None;
        };
        // SAFTY:
        // - node is valid for reads
        // - node is aligned
        unsafe { Some(&(**node).value) }
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let Some(node) = self.entries.get_mut(key) else {
            return None;
        };
        // SAFTY:
        // - node is valid for reads and writes
        // - node is aligned
        unsafe { Some(&mut (**node).value) }
    }

    pub fn insert(&mut self, time: T, key: K, mut value: V) -> Option<V> {
        if let Some(node) = self.entries.get_mut(&key) {
            // SAFTY:
            // - The nodes are allocated with Box::into_raw
            // - The nodes are always in a time chain, which means head will never be null
            unsafe {
                if (*(**node).head).time != time {
                    Self::remove_from_time_chain(Some(&mut self.timeline), *node);
                    let head = Self::find_or_create_time_chain(&mut self.timeline, time);
                    Self::insert_into_time_chain(head, *node);
                }
                mem::swap(&mut (**node).value, &mut value);
            }
            return Some(value);
        }
        let head = Self::find_or_create_time_chain(&mut self.timeline, time);
        let node = Box::into_raw(Box::new(Node {
            key: key.clone(),
            value,
            head: ptr::null_mut(),
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
        }));
        self.entries.insert(key, node);
        unsafe {
            // SAFTY:
            // - The node are allocated with Box::into_raw
            Self::insert_into_time_chain(head, node);
        }
        None
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let Some(node) = self.entries.remove(key) else {
            return None;
        };
        unsafe {
            // SAFTY:
            // - The nodes are allocated with Box::into_raw
            Self::remove_from_time_chain(Some(&mut self.timeline), node);
            let node = Box::from_raw(node);
            Some(node.value)
        }
    }

    // remove the first item in the first timeline
    pub fn remove_oldest(&mut self) -> Option<V> {
        let Some(head) = self.timeline.front_mut() else {
            return None;
        };
        // SAFTY:
        // - Make sure head.next is never null by removing the head if it's empty
        unsafe {
            let node = (**head).next;
            self.entries.remove(&(*node).key);
            Self::remove_from_time_chain(Some(&mut self.timeline), node);
            let node = Box::from_raw(node);
            Some(node.value)
        }
    }

    // push time window to T, handles all values in nodes with time <= T with F
    // if F returns Some(new_time) and new_time > T, the node will be moved to the new time,
    // otherwise, the node will be removed
    pub fn forward_time<F>(&mut self, time: T, mut callback: F)
    where
        F: FnMut(&mut V) -> Option<T>,
    {
        unsafe {
            // SAFTY:
            // - Timeline head pointers and node pointers are aligned and not null
            // - Box::from_raw are called with pointers from Box::into_raw
            if self.timeline.is_empty() || (*self.timeline[0]).time > time {
                return;
            }
            let max_index = match self
                .timeline
                .binary_search_by_key(&&time, |th| &(**th).time)
            {
                Ok(index) => index,
                Err(index) => index - 1, // self.timeline[0].time < time is checked, index will be larger than 1
            };
            for _ in 0..=max_index {
                let head = self.timeline.pop_front().unwrap();
                let ref_head = &mut *head;
                let mut node = ref_head.next;
                while !node.is_null() {
                    let ref_node = &mut *node;
                    let new_time = callback(&mut ref_node.value);
                    let next = ref_node.next;
                    Self::remove_from_time_chain(None, node);
                    match new_time {
                        Some(nt) if nt > time => {
                            let new_head = Self::find_or_create_time_chain(&mut self.timeline, nt);
                            Self::insert_into_time_chain(new_head, node);
                        }
                        _ => {
                            // SAFTY:
                            // - The nodes are allocated with Box::into_raw
                            mem::drop(Box::from_raw(self.entries.remove(&ref_node.key).unwrap()));
                        }
                    }
                    node = next;
                }
                // free this chain after removing all nodes from it
                let _ = Box::from_raw(head);
            }
        }
    }

    pub fn move_to_time<Q>(&mut self, key: &Q, time: T)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let Some(node) = self.entries.get_mut(key) else {
            return;
        };
        unsafe {
            // SAFTY:
            // - The nodes are allocated with Box::into_raw
            // - The nodes are always in a time chain, which means head will never be null
            if (*(**node).head).time == time {
                return;
            }
            Self::remove_from_time_chain(Some(&mut self.timeline), *node);
            let head = Self::find_or_create_time_chain(&mut self.timeline, time);
            Self::insert_into_time_chain(head, *node);
        }
    }

    pub fn drain<R>(&mut self, range: R) -> Drain<'_, T, K, V>
    where
        R: RangeBounds<T>,
    {
        let mut drained: Vec<*mut TimeHead<T, K, V>> = vec![];
        self.timeline.retain(|head| {
            // SAFTY:
            // - The time heads are allocated with Box::into_raw and not null
            unsafe {
                if range.contains(&(**head).time) {
                    drained.push(*head);
                    false
                } else {
                    true
                }
            }
        });
        // chain timelines in range into a single linked list for draining
        // nodes in self.entries are not removed until Drain is consumed or dropped
        let mut chain: *mut Node<T, K, V> = ptr::null_mut();
        let mut tail: *mut Node<T, K, V> = ptr::null_mut();
        for head in drained.into_iter() {
            // SAFTY:
            // - The time heads are allocated with Box::into_raw and not null
            unsafe {
                let head = Box::from_raw(head);
                if chain.is_null() {
                    chain = head.next;
                    tail = head.next;
                } else {
                    (*tail).next = head.next;
                }
                while !(*tail).next.is_null() {
                    tail = (*tail).next;
                }
            }
            // the headers are freed here
        }
        Drain {
            entries: &mut self.entries,
            chain,
        }
    }

    // SAFTY: node should be non-null and aligned
    unsafe fn insert_into_time_chain(head: *mut TimeHead<T, K, V>, node: *mut Node<T, K, V>) {
        let ref_head = &mut *head;
        let ref_node = &mut *node;
        if !ref_head.next.is_null() {
            (*ref_head.next).prev = node;
        }
        ref_node.head = head;
        ref_node.prev = ptr::null_mut();
        ref_node.next = ref_head.next;
        ref_head.next = node;
    }

    // Remove a node from its time chain
    // If timeline is provided, the process will also check if the time chain is empty after removal
    // and remove the time chain from timeline if it's empty
    //
    // SAFTY: node should be non-null and aligned
    unsafe fn remove_from_time_chain(
        timeline: Option<&mut VecDeque<*mut TimeHead<T, K, V>>>,
        node: *mut Node<T, K, V>,
    ) {
        let node = &mut *node;
        let head = node.head;
        if node.prev.is_null() {
            // node is the head of the time chain
            (*node.head).next = node.next;
        } else {
            (*node.prev).next = node.next;
        }
        if !node.next.is_null() {
            (*node.next).prev = node.prev;
        }
        node.head = ptr::null_mut();
        node.prev = ptr::null_mut();
        node.next = ptr::null_mut();

        // remove time chain if timeline is provided and time chain is empty after removal
        if let Some(tl) = timeline {
            let ref_head = &mut *head;
            if !ref_head.next.is_null() {
                return;
            }
            match tl.binary_search_by_key(&&ref_head.time, |h| &(**h).time) {
                Ok(index) => {
                    let head = tl.remove(index).unwrap();
                    let _ = Box::from_raw(head);
                }
                Err(_) => unreachable!(),
            }
        }
    }

    fn find_or_create_time_chain(
        timeline: &mut VecDeque<*mut TimeHead<T, K, V>>,
        time: T,
    ) -> *mut TimeHead<T, K, V> {
        match timeline.binary_search_by_key(&&time, |th| unsafe {
            // SAFTY:
            // - The time heads are allocated with Box::into_raw
            // - Not null
            &(**th).time
        }) {
            Ok(index) => timeline[index],
            Err(index) => {
                timeline.insert(
                    index,
                    Box::into_raw(Box::new(TimeHead {
                        time,
                        next: ptr::null_mut(),
                    })),
                );
                timeline[index]
            }
        }
    }
}

impl<T, K, V> Drop for ChronoMap<T, K, V>
where
    T: Clone + Eq + Ord,
    K: Clone + PartialEq + Eq + Hash,
{
    fn drop(&mut self) {
        // SAFTY:
        // - Timeline heads and entry nodes are allocated with Box::into_raw
        unsafe {
            for head in self.timeline.drain(..) {
                let _ = Box::from_raw(head);
            }
            for (_, node) in self.entries.drain() {
                let _ = Box::from_raw(node);
            }
        }
    }
}

pub struct Drain<'a, T, K, V>
where
    T: Clone + Eq + Ord,
    K: Clone + PartialEq + Eq + Hash,
{
    entries: &'a mut AHashMap<K, *mut Node<T, K, V>>,
    chain: *mut Node<T, K, V>,
}

impl<'a, T, K, V> Iterator for Drain<'a, T, K, V>
where
    T: Clone + Eq + Ord,
    K: Clone + PartialEq + Eq + Hash,
{
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        if self.chain.is_null() {
            return None;
        }
        // SAFTY:
        // - The nodes are allocated with Box::into_raw
        unsafe {
            let node = self.chain;
            let ref_node = &mut *node;
            self.chain = ref_node.next;
            self.entries.remove(&ref_node.key);
            Some(Box::from_raw(node).value)
        }
    }
}

impl<'a, T, K, V> Drop for Drain<'a, T, K, V>
where
    T: Clone + Eq + Ord,
    K: Clone + PartialEq + Eq + Hash,
{
    fn drop(&mut self) {
        // drop all nodes in the chain and remove them from entries
        // SAFTY:
        // - The nodes are allocated with Box::into_raw
        unsafe {
            let mut node = self.chain;
            while !node.is_null() {
                let ref_node = &mut *node;
                let next = ref_node.next;
                self.entries.remove(&ref_node.key);
                let _ = Box::from_raw(node);
                node = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct TestValue {
        value: u32,
        timeout: u64,
    }

    #[test]
    fn simple_operations() {
        let mut m = ChronoMap::new();
        m.insert(
            42,
            "tcp",
            TestValue {
                value: 10,
                timeout: 15,
            },
        );
        m.insert(
            42,
            "udp",
            TestValue {
                value: 32,
                timeout: 120,
            },
        );
        assert_eq!(
            m.get(&"tcp"),
            Some(&TestValue {
                value: 10,
                timeout: 15
            })
        );
        assert_eq!(
            m.get(&"udp"),
            Some(&TestValue {
                value: 32,
                timeout: 120
            })
        );

        m.remove(&"tcp");
        assert_eq!(m.get(&"tcp"), None);

        m.drain(..);
        assert!(m.is_empty());

        let mut values = vec![];

        m.insert(
            42,
            "tcp",
            TestValue {
                value: 10,
                timeout: 15,
            },
        );
        m.insert(
            52,
            "udp",
            TestValue {
                value: 32,
                timeout: 120,
            },
        );
        m.move_to_time(&"tcp", 62);

        values.clear();
        m.forward_time(50, |v| {
            values.push(v.value);
            None
        });
        assert!(values.is_empty());

        values.clear();
        m.forward_time(62, |v| {
            values.push(v.value);
            Some(62 + v.timeout)
        });
        assert_eq!(values, vec![32, 10]);

        values.clear();
        m.forward_time(77, |v| {
            values.push(v.value);
            None
        });
        assert_eq!(values, vec![10]);

        values.clear();
        m.forward_time(181, |v| {
            values.push(v.value);
            None
        });
        assert!(values.is_empty());

        values.clear();
        m.forward_time(182, |v| {
            values.push(v.value);
            None
        });
        assert_eq!(values, vec![32]);
    }

    #[test]
    fn insertions() {
        let mut m = ChronoMap::new();

        m.insert(42, "key0", Box::new(0));
        //        key0
        //         |
        //         v
        // 42 -> Box(0)
        unsafe {
            let head = m.timeline[0];
            assert_eq!((*head).time, 42);
            let value = &*m.entries["key0"];
            assert_eq!(value.head, head);
            assert_eq!(value.prev, ptr::null_mut());
            assert_eq!(value.next, ptr::null_mut());
        }

        m.insert(42, "key1", Box::new(1));
        m.insert(3, "key2", Box::new(2));
        //        key2     key1      key0
        //         |        |         |
        //         v        |         |
        // 3  -> Box(2)     v         v
        // 42 ----------> Box(1) -> Box(0)
        unsafe {
            let head = m.timeline[0];
            assert_eq!((*head).time, 3);
            let value = &*m.entries["key2"];
            assert_eq!(value.head, head);
            assert_eq!(value.prev, ptr::null_mut());
            assert_eq!(value.next, ptr::null_mut());
            let head = m.timeline[1];
            assert_eq!((*head).time, 42);
            let addr1 = m.entries["key1"];
            let value1 = &*addr1;
            let addr0 = m.entries["key0"];
            let value0 = &*addr0;
            assert_eq!(value1.head, head);
            assert_eq!(value1.prev, ptr::null_mut());
            assert_eq!(value1.next, addr0);
            assert_eq!(value0.head, head);
            assert_eq!(value0.prev, addr1);
            assert_eq!(value0.next, ptr::null_mut());
        }

        assert_eq!(m.insert(42, "key2", Box::new(2)), Some(Box::new(2)));
        //        key2      key1      key0
        //         |         |         |
        //         v         v         v
        // 42 -> Box(2) -> Box(1) -> Box(0)
        assert_eq!(m.timeline.len(), 1);
        unsafe {
            let head = m.timeline[0];
            assert_eq!((*head).time, 42);
            let addr2 = m.entries["key2"];
            let value2 = &*addr2;
            let addr1 = m.entries["key1"];
            let value1 = &*addr1;
            let addr0 = m.entries["key0"];
            let value0 = &*addr0;
            assert_eq!(value2.head, head);
            assert_eq!(value2.prev, ptr::null_mut());
            assert_eq!(value2.next, addr1);
            assert_eq!(value1.head, head);
            assert_eq!(value1.prev, addr2);
            assert_eq!(value1.next, addr0);
            assert_eq!(value0.head, head);
            assert_eq!(value0.prev, addr1);
            assert_eq!(value0.next, ptr::null_mut());
        }
    }

    #[test]
    fn removals() {
        let mut m = ChronoMap::new();
        for i in 0..10 {
            m.insert(42, format!("key{}", i), Box::new(i));
        }
        // a single chain from key9 to key0
        assert_eq!(m.timeline.len(), 1);

        // to test remove_oldest
        m.insert(30, "remove_oldest".to_string(), Box::new(10));

        // remove time chain head node
        assert_eq!(m.remove("key9"), Some(Box::new(9)));
        unsafe {
            let head = m.timeline[1];
            assert_eq!((*head).time, 42);
            let node = (*head).next;
            assert_eq!(node, m.entries["key8"]);
            assert_eq!((*node).prev, ptr::null_mut());
        }

        // remove tail
        assert_eq!(m.remove("key0"), Some(Box::new(0)));
        unsafe {
            let value1 = &*m.entries["key1"];
            assert_eq!(value1.next, ptr::null_mut());
        }

        // remove middle
        assert_eq!(m.remove("key5"), Some(Box::new(5)));
        unsafe {
            let addr6 = m.entries["key6"];
            let value6 = &*addr6;
            let addr4 = m.entries["key4"];
            let value4 = &*addr4;
            assert_eq!(value6.next, addr4);
            assert_eq!(value4.prev, addr6);
        }

        // remove oldest
        assert_eq!(m.remove_oldest(), Some(Box::new(10)));
        assert_eq!(m.timeline.len(), 1);

        // remove all in any order
        let order = vec![5, 4, 7, 8, 1, 3, 2, 5, 6, 9];
        for i in order {
            m.remove(&format!("key{}", i));
        }
        assert!(m.is_empty());
        assert!(m.timeline.is_empty());
    }

    #[test]
    fn forward_time() {
        let mut m = ChronoMap::new();

        m.insert(42, "key0", Box::new(0));
        m.insert(42, "key1", Box::new(1));
        m.insert(3, "key2", Box::new(2));
        //        key2     key1      key0
        //         |        |         |
        //         v        |         |
        // 3  -> Box(2)     v         v
        // 42 ----------> Box(1) -> Box(0)

        m.forward_time(32, |v| {
            *v.as_mut() += 1;
            Some(40)
        });
        //        key2     key1      key0
        //         |        |         |
        //         v        |         |
        // 40 -> Box(3)     v         v
        // 42 ----------> Box(1) -> Box(0)
        assert_eq!(m.timeline.len(), 2);
        unsafe {
            let head = m.timeline[0];
            assert_eq!((*head).time, 40);
            let value = &*m.entries["key2"];
            assert_eq!(value.value, Box::new(3));
        }

        m.forward_time(42, |v| match v.as_ref() {
            3 => Some(50),
            1 => None,
            0 => Some(50),
            _ => unreachable!(),
        });
        //          key0      key2
        //           |         |
        //           v         v
        // 50 ---> Box(0) -> Box(3)
        assert_eq!(m.timeline.len(), 1);
        unsafe {
            let head = m.timeline[0];
            assert_eq!((*head).time, 50);
            let addr0 = m.entries["key0"];
            let value0 = &*addr0;
            let addr2 = m.entries["key2"];
            let value2 = &*addr2;
            assert_eq!(value0.head, head);
            assert_eq!(value0.prev, ptr::null_mut());
            assert_eq!(value0.next, addr2);
            assert_eq!(value2.head, head);
            assert_eq!(value2.prev, addr0);
            assert_eq!(value2.next, ptr::null_mut());
        }

        m.forward_time(100, |_| None);
        assert!(m.is_empty());
    }

    #[test]
    fn move_to_time() {
        let mut m = ChronoMap::new();

        m.insert(42, "key0", Box::new(0));
        m.insert(42, "key1", Box::new(1));
        m.insert(3, "key2", Box::new(2));
        //        key2     key1      key0
        //         |        |         |
        //         v        |         |
        // 3  -> Box(2)     v         v
        // 42 ----------> Box(1) -> Box(0)

        m.move_to_time("key0", 52);
        //        key2     key1      key0
        //         |        |         |
        //         v        |         |
        // 3  -> Box(2)     v         |
        // 42 ----------> Box(1)      v
        // 52 --------------------> Box(0)
        assert_eq!(m.timeline.len(), 3);
        unsafe {
            let head2 = m.timeline[0];
            let head1 = m.timeline[1];
            let head0 = m.timeline[2];
            assert_eq!((*head2).time, 3);
            assert_eq!((*head1).time, 42);
            assert_eq!((*head0).time, 52);

            let addr2 = m.entries["key2"];
            let value2 = &*addr2;
            assert_eq!(value2.head, head2);
            assert_eq!(value2.prev, ptr::null_mut());
            assert_eq!(value2.next, ptr::null_mut());
            assert_eq!((*head2).next, addr2);

            let addr1 = m.entries["key1"];
            let value1 = &*addr1;
            assert_eq!(value1.head, head1);
            assert_eq!(value1.prev, ptr::null_mut());
            assert_eq!(value1.next, ptr::null_mut());
            assert_eq!((*head1).next, addr1);

            let addr0 = m.entries["key0"];
            let value0 = &*addr0;
            assert_eq!(value0.head, head0);
            assert_eq!(value0.prev, ptr::null_mut());
            assert_eq!(value0.next, ptr::null_mut());
            assert_eq!((*head0).next, addr0);
        }

        m.move_to_time("key0", 100);
        m.move_to_time("key1", 100);
        m.move_to_time("key2", 100);
        //        key2     key1      key0
        //         |         |         |
        //         v         v         v
        // 100 -> Box(2) -> Box(1) -> Box(0)
        assert_eq!(m.timeline.len(), 1);
        unsafe {
            let head = m.timeline[0];
            assert_eq!((*head).time, 100);
            let addr2 = m.entries["key2"];
            let value2 = &*addr2;
            let addr1 = m.entries["key1"];
            let value1 = &*addr1;
            let addr0 = m.entries["key0"];
            let value0 = &*addr0;
            assert_eq!(value2.head, head);
            assert_eq!(value2.prev, ptr::null_mut());
            assert_eq!(value2.next, addr1);
            assert_eq!(value1.head, head);
            assert_eq!(value1.prev, addr2);
            assert_eq!(value1.next, addr0);
            assert_eq!(value0.head, head);
            assert_eq!(value0.prev, addr1);
            assert_eq!(value0.next, ptr::null_mut());
        }
    }

    #[test]
    fn drain() {
        let mut m = ChronoMap::new();
        for i in 0..10 {
            m.insert(42, format!("key42-{}", i), i);
            m.insert(62, format!("key62-{}", i), i);
            m.insert(52, format!("key52-{}", i), 9 - i);
        }
        let v = m.drain(42..53).collect::<Vec<_>>();
        assert_eq!(
            v,
            vec![9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
    }
}
