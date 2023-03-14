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

use std::cell::RefCell;
use std::rc::Rc;

pub trait Poolable {
    fn set_pool_index(&self, index: usize);
    fn get_pool_index(&self) -> usize;
}

const BLOCK_SIZE_SHIFT: usize = 10;
const BLOCK_SIZE: usize = 1 << BLOCK_SIZE_SHIFT;

pub struct ObjectsPool<T> {
    objects: Vec<Rc<RefCell<T>>>,
    init: fn() -> T,
    in_use: usize,
    capacity: usize,
    max_capacity: usize,
}

impl<T: Poolable> ObjectsPool<T> {
    pub fn with_capacity(capacity: usize, init: fn() -> T) -> Self {
        assert!(capacity >= BLOCK_SIZE || capacity == 0);
        let capacity = if capacity > 0 {
            capacity.next_power_of_two()
        } else {
            capacity
        };
        Self {
            objects: vec![],
            in_use: 0,
            init,
            capacity: 0,
            max_capacity: capacity,
        }
    }

    fn inner_get(&mut self) -> Rc<RefCell<T>> {
        let index = self.in_use;
        let item = self.objects[index].clone();
        self.in_use += 1;
        item.borrow().set_pool_index(index);

        item
    }

    pub fn get(&mut self) -> Rc<RefCell<T>> {
        if self.in_use >= self.capacity {
            if self.max_capacity != 0 && self.capacity > self.max_capacity {
                panic!("ObjectPool capacity will be exceed.");
            }
            for _ in 0..BLOCK_SIZE {
                self.objects.push(Rc::new(RefCell::new((self.init)())));
            }
            self.capacity += BLOCK_SIZE;
        }

        self.inner_get()
    }

    pub fn put(&mut self, item: Rc<RefCell<T>>) {
        self.in_use -= 1;

        let index = item.borrow().get_pool_index();
        if index != self.in_use {
            self.objects[self.in_use].borrow().set_pool_index(index);
            self.objects.swap(index, self.in_use);
        }

        if self.in_use & 1 << 12 == 0 {
            let adjust_capacity = self.in_use + self.in_use / 10;
            if self.capacity > adjust_capacity {
                self.capacity = adjust_capacity;
                self.objects.drain(adjust_capacity..);
            }
        }
    }

    pub fn counter(&self) -> (usize, usize) {
        (self.capacity, self.in_use)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Node {
        pool_index: RefCell<usize>,
        id: usize,
    }

    impl Poolable for Node {
        fn set_pool_index(&self, index: usize) {
            *self.pool_index.borrow_mut() = index;
        }

        fn get_pool_index(&self) -> usize {
            *self.pool_index.borrow()
        }
    }

    #[test]
    fn test_normal() {
        let mut pool: ObjectsPool<Node> = ObjectsPool::with_capacity(1024, || Node {
            pool_index: RefCell::new(0),
            id: 0,
        });
        let mut items = vec![];
        for i in 0..5 {
            let item = pool.get();
            item.borrow_mut().id = i;
            items.push(Some(item));
        }

        let item = pool.get();
        item.borrow_mut().id = 5;
        pool.put(item);
        assert_eq!(pool.in_use, 5);
        let ids = items
            .iter()
            .map(|x| x.as_ref().unwrap().borrow().id)
            .collect::<Vec<usize>>();
        assert_eq!(vec![0, 1, 2, 3, 4], ids);

        pool.put(items[0].take().unwrap()); // objects: [4, 1, 2, 3, 0] in_use: 4
        pool.put(items[2].take().unwrap()); // objects: [4, 1, 3, 2, 0] in_use: 3
        pool.put(items[4].take().unwrap()); // objects: [3, 1, 4, 2, 0] in_use: 2
        assert_eq!(1, items[1].as_ref().unwrap().borrow().get_pool_index());
        assert_eq!(0, items[3].as_ref().unwrap().borrow().get_pool_index());
        assert_eq!(2, pool.in_use);
        pool.put(items[1].take().unwrap()); // objects: [3, 1, 4, 2, 0] in_use: 1
        assert_eq!(0, items[3].as_ref().unwrap().borrow().get_pool_index());
        assert_eq!(1, pool.in_use);
    }
}
