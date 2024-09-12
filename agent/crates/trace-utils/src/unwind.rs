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

pub mod dwarf;
pub mod maps;

use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::collections::{hash_map::Entry, HashMap, HashSet, VecDeque};
use std::fs;
use std::hash::Hasher;
use std::mem;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::slice;

use ahash::AHasher;
use libc::{__u64, c_int, c_void};
use log::{debug, trace, warn};
use object::{
    elf::{self, FileHeader64},
    read::elf::FileHeader,
};

use dwarf::UnwindEntry;
use maps::MemoryArea;

#[derive(Default)]
pub struct UnwindTable {
    id_gen: IdGenerator,
    object_cache: HashMap<u64, ObjectInfo>,
    shard_rc: HashMap<u32, usize>,

    process_shard_list_map_fd: i32,
    unwind_entry_shard_map_fd: i32,
}

impl UnwindTable {
    // libraries with unwind entries larger than this margin will be
    // stored in separated shards
    const SHARD_THRESHOLD: usize = UNWIND_ENTRIES_PER_SHARD * 90 / 100;

    pub unsafe fn new(process_shard_list_map_fd: i32, unwind_entry_shard_map_fd: i32) -> Self {
        Self {
            process_shard_list_map_fd,
            unwind_entry_shard_map_fd,
            ..Default::default()
        }
    }

    pub fn load(&mut self, pid: u32) {
        let mm = match maps::get_memory_mappings(pid) {
            Ok(m) => m,
            Err(e) => {
                debug!("failed loading maps for process#{pid}: {e}");
                return;
            }
        };
        trace!("load dwarf entries for process#{pid}");

        let mut shard_list = ProcessShardList::default();
        let mut shard: Option<BoxedShard> = None;
        let mut shard_count = 0;

        let base_path: PathBuf = ["/proc", &pid.to_string(), "root"].iter().collect();
        for m in mm {
            if m.path.chars().next() == Some('[') {
                trace!("ignore file {}", m.path);
                continue;
            }
            let mut path = base_path.clone();
            path.push(&m.path[1..]);
            let data = match fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    debug!("load file {} failed: {e}", path.display());
                    continue;
                }
            };

            let mut hasher = AHasher::default();
            hasher.write(&data);
            let digest = hasher.finish();
            if let Some(obj) = self.object_cache.get_mut(&digest) {
                trace!(
                    "object {} found in cache, use loaded shards",
                    path.display()
                );
                obj.pids.push(pid);
                for s in obj.shards.iter() {
                    if shard_list.len as usize >= UNWIND_SHARDS_PER_PROCESS {
                        warn!(
                            "process#{pid} unwind shard list full, cannot add entries for {}",
                            m.path
                        );
                        break;
                    }
                    shard_list.entries[shard_list.len as usize] = *s;
                    // offset is 0 iff object is not PIC/PIE, otherwise set offset according to proc maps
                    if shard_list.entries[shard_list.len as usize].offset != 0 {
                        shard_list.entries[shard_list.len as usize].offset = m.m_start;
                    }
                    shard_list.len += 1;
                }
                continue;
            }

            // for binaries compiled without "-fPIE" or "-pie", the symbols will not get relocated
            // so shard offset should be set to 0
            let is_pic = match FileHeader64::<object::Endianness>::parse(&*data) {
                Ok(header) => match header.endian() {
                    Ok(endian) => header.e_type(endian) != elf::ET_EXEC,
                    Err(e) => {
                        debug!(
                            "read elf header endian for process#{pid} in {} failed: {e}",
                            path.display()
                        );
                        continue;
                    }
                },
                Err(e) => {
                    debug!(
                        "read elf header for process#{pid} in {} failed: {e}",
                        path.display()
                    );
                    continue;
                }
            };
            trace!("object {} is_pic={is_pic}", path.display());

            trace!("load object {} dwarf entries", path.display());
            let entries = match dwarf::read_unwind_entries(&data) {
                Ok(ue) if ue.is_empty() => {
                    debug!("process#{pid} in {} has no unwind entries", path.display());
                    continue;
                }
                Ok(ue) => ue,
                Err(e) => {
                    debug!(
                        "read unwind entries for process#{pid} in {} failed: {e}",
                        path.display()
                    );
                    continue;
                }
            };
            let max_pc = entries.iter().last().map(|e| e.pc).unwrap_or_default();

            if entries.len() >= Self::SHARD_THRESHOLD {
                trace!(
                    "load object {} with {} entries into multiple shards",
                    path.display(),
                    entries.len()
                );
                let object_info =
                    self.split_into_shards(pid, &m, &entries, max_pc, &mut shard_list, is_pic);
                shard_count += object_info.shards.len();
                self.object_cache.insert(digest, object_info);
                continue;
            }

            match shard.as_ref().map(|b| b.as_ref()) {
                Some(s) if s.len as usize + entries.len() > UNWIND_ENTRIES_PER_SHARD => {
                    trace!(
                        "finish shard#{} because {} + {} > {}",
                        s.id,
                        s.len,
                        entries.len(),
                        UNWIND_ENTRIES_PER_SHARD
                    );
                    let boxed_shard = shard.take().unwrap();
                    let s = boxed_shard.as_ref();
                    self.update_unwind_entry_shard(s.id, s);
                }
                _ => (),
            }
            if shard.is_none() {
                let shard_id = self.id_gen.acquire();
                trace!("create shard#{shard_id} for unwind entries");
                shard.replace(BoxedShard::new(shard_id));
                shard_count += 1;
            }

            let shard = shard.as_mut().unwrap().as_mut();
            trace!(
                "load object {} into shard#{} with {} entries",
                path.display(),
                shard.id,
                entries.len()
            );
            (&mut shard.entries[shard.len as usize..(shard.len as usize + entries.len())])
                .copy_from_slice(&entries);
            shard.len += entries.len() as u32;

            if shard_list.len as usize >= UNWIND_SHARDS_PER_PROCESS {
                warn!(
                    "process#{pid} unwind shard list full, cannot add entries for {}",
                    path.display()
                );
                break;
            }
            let shard_info = &mut shard_list.entries[shard_list.len as usize];
            shard_info.id = shard.id;
            shard_info.offset = if is_pic { m.m_start } else { 0 };
            shard_info.pc_min = entries[0].pc;
            shard_info.pc_max = max_pc;
            shard_info.entry_start = shard.len as u16 - entries.len() as u16;
            shard_info.entry_end = shard.len as u16;

            self.object_cache.insert(
                digest,
                ObjectInfo {
                    pids: vec![pid],
                    shards: vec![shard_info.clone()],
                },
            );
            *self.shard_rc.entry(shard.id).or_insert(0) += 1;
            trace!(
                "increase shard#{} ref count to {}",
                shard.id,
                self.shard_rc.get(&shard.id).unwrap()
            );
            shard_list.len += 1;
        }
        if let Some(bs) = shard.take() {
            let s = bs.as_ref();
            trace!("finish shard#{} with {} entries", s.id, s.len);
            self.update_unwind_entry_shard(s.id, s);
        }

        if shard_list.len == 0 {
            trace!("no dwarf entry shards loaded for process#{pid}");
            return;
        }

        if log::log_enabled!(log::Level::Debug) {
            let mut shard_ids = HashSet::new();
            for i in 0..shard_list.len {
                shard_ids.insert(shard_list.entries[i as usize].id);
            }
            debug!(
                "process#{pid} loaded {shard_count} and reused {} dwarf entry shards",
                shard_ids.len() - shard_count
            );
        }
        // sort the shard list by offset + pc_min to enable binary search in ebpf program
        (&mut shard_list.entries[..shard_list.len as usize])
            .sort_unstable_by_key(|e| e.offset + e.pc_min);
        self.update_process_shard_list(pid, &shard_list);
    }

    pub fn unload(&mut self, pid: u32) {
        trace!("unload dwarf entries for process#{pid}");
        let mut shards_to_remove = vec![];
        let mut found_process = false;
        self.object_cache.retain(|_, obj| {
            match obj.pids.iter().position(|p| *p == pid) {
                None => true,
                Some(index) => {
                    found_process = true;
                    obj.pids.swap_remove(index);
                    if !obj.pids.is_empty() {
                        return true;
                    }
                    // the object is no longer used by any process
                    // check shard reference count
                    for shard in obj.shards.iter() {
                        match self.shard_rc.entry(shard.id) {
                            Entry::Occupied(mut v) => {
                                if *v.get() <= 1 {
                                    trace!("remove shard#{}", shard.id);
                                    v.remove();
                                    shards_to_remove.push(shard.id);
                                } else {
                                    *v.get_mut() -= 1;
                                    trace!("reduce shard#{} ref count to {}", shard.id, *v.get());
                                }
                            }
                            _ => {
                                // unlikely to happen
                                trace!("remove shard#{}", shard.id);
                                shards_to_remove.push(shard.id);
                            }
                        }
                    }
                    false
                }
            }
        });
        if found_process {
            for id in shards_to_remove.iter() {
                self.delete_unwind_entry_shard(*id);
                self.id_gen.release(*id);
            }
            debug!(
                "process#{pid} unloaded {} dwarf entry shards",
                shards_to_remove.len()
            );
            self.delete_process_shard_list(pid);
        }
    }

    pub fn unload_all(&mut self) {
        trace!("unload all dwarf entries");

        let shards: Vec<u32> = self.shard_rc.drain().map(|(id, _)| id).collect();
        for id in shards.iter() {
            self.delete_unwind_entry_shard(*id);
            self.id_gen.release(*id);
        }

        let processes: HashSet<u32> = self
            .object_cache
            .drain()
            .flat_map(|(_, obj)| obj.pids.into_iter())
            .collect();
        for pid in processes.iter() {
            self.delete_process_shard_list(*pid);
        }

        debug!(
            "unloaded {} dwarf entry shards for {} processes",
            shards.len(),
            processes.len(),
        );
    }

    fn split_into_shards(
        &mut self,
        pid: u32,
        m: &MemoryArea,
        entries: &[UnwindEntry],
        max_pc: u64,
        shard_list: &mut ProcessShardList,
        is_pic: bool,
    ) -> ObjectInfo {
        let mut object_info = ObjectInfo {
            pids: vec![pid],
            ..Default::default()
        };
        let mut first_shard = true;
        let mut boxed_shard = BoxedShard::new(0);
        for chunk in entries.chunks(UNWIND_ENTRIES_PER_SHARD) {
            let shard_id = self.id_gen.acquire();
            trace!(
                "load object into shard#{shard_id} with {} entries",
                chunk.len()
            );

            let shard = boxed_shard.as_mut();
            shard.id = shard_id;
            shard.len = chunk.len() as u32;
            (&mut shard.entries[..shard.len as usize]).copy_from_slice(chunk);

            self.update_unwind_entry_shard(shard_id, shard);

            if shard_list.len as usize >= UNWIND_SHARDS_PER_PROCESS {
                warn!(
                    "process#{pid} unwind shard list full, cannot add entries for {}",
                    m.path
                );
                break;
            }
            let shard_info = &mut shard_list.entries[shard_list.len as usize];
            shard_info.id = shard_id;
            shard_info.offset = if is_pic { m.m_start } else { 0 };
            shard_info.pc_min = chunk[0].pc;
            shard_info.pc_max = max_pc;
            shard_info.entry_start = 0;
            shard_info.entry_end = chunk.len() as u16;
            if !first_shard {
                // set max pc of last shard to min pc of this shard
                shard_info.pc_max = chunk[0].pc;
            }

            object_info.shards.push(shard_info.clone());
            *self.shard_rc.entry(shard.id).or_insert(0) += 1;
            trace!(
                "increase shard#{} ref count to {}",
                shard.id,
                self.shard_rc.get(&shard.id).unwrap()
            );
            shard_list.len += 1;

            first_shard = false;
        }
        object_info
    }

    fn update_process_shard_list(&self, pid: u32, list: &ProcessShardList) {
        trace!("update process#{pid} process shard list");
        unsafe {
            let value = slice::from_raw_parts(
                list as *const ProcessShardList as *const u8,
                mem::size_of::<ProcessShardList>(),
            );
            let ret = bpf_update_elem(
                self.process_shard_list_map_fd,
                &pid as *const u32 as *const c_void,
                value as *const [u8] as *const c_void,
                BPF_ANY,
            );
            if ret != 0 {
                match *libc::__errno_location() {
                    libc::E2BIG => warn!("update process#{pid} shard list failed: try increasing dwarf_process_map_size"),
                    libc::ENOMEM => warn!("update process#{pid} shard list failed: cannot allocate memory"),
                    _ => warn!("update process#{pid} shard list failed: bpf_update_elem() returned {}", *libc::__errno_location()),
                }
            }
        }
    }

    fn delete_process_shard_list(&self, pid: u32) {
        trace!("delete process#{pid} process shard list");
        unsafe {
            let ret = bpf_delete_elem(
                self.process_shard_list_map_fd,
                &pid as *const u32 as *const c_void,
            );
            if ret != 0 {
                let errno = libc::__errno_location();
                // ignoring non exist error
                if *errno != libc::ENOENT {
                    warn!(
                        "delete process#{pid} shard list failed: bpf_delete_elem() returned {}",
                        *libc::__errno_location()
                    );
                }
            }
        }
    }

    fn update_unwind_entry_shard(&self, shard_id: u32, shard: &UnwindEntryShard) {
        trace!("update shard#{shard_id}");
        unsafe {
            let value = slice::from_raw_parts(
                shard as *const UnwindEntryShard as *const u8,
                mem::size_of::<UnwindEntryShard>(),
            );
            let ret = bpf_update_elem(
                self.unwind_entry_shard_map_fd,
                &shard_id as *const u32 as *const c_void,
                value as *const [u8] as *const c_void,
                BPF_ANY,
            );
            if ret != 0 {
                match *libc::__errno_location() {
                    libc::E2BIG => {
                        warn!("update shard#{shard_id} failed: try increasing dwarf_shard_map_size")
                    }
                    libc::ENOMEM => warn!("update shard#{shard_id} failed: cannot allocate memory"),
                    _ => warn!(
                        "update shard#{shard_id} failed: bpf_update_elem() returned {}",
                        *libc::__errno_location()
                    ),
                }
            }
        }
    }

    fn delete_unwind_entry_shard(&self, shard_id: u32) {
        trace!("delete shard#{shard_id}");
        unsafe {
            let ret = bpf_delete_elem(
                self.unwind_entry_shard_map_fd,
                &shard_id as *const u32 as *const c_void,
            );
            if ret != 0 {
                let errno = libc::__errno_location();
                // ignoring non exist error
                if *errno != libc::ENOENT {
                    warn!(
                        "delete shard#{shard_id} failed: bpf_delete_elem() returned {}",
                        *libc::__errno_location()
                    );
                }
            }
        }
    }
}

const BPF_ANY: __u64 = 0;
extern "C" {
    fn bpf_update_elem(fd: c_int, key: *const c_void, value: *const c_void, flags: __u64) -> c_int;
    fn bpf_delete_elem(fd: c_int, key: *const c_void) -> c_int;
}

#[derive(Default)]
struct IdGenerator {
    max_id: u32,
    available: VecDeque<u32>,
}

impl IdGenerator {
    fn acquire(&mut self) -> u32 {
        if let Some(id) = self.available.pop_front() {
            return id;
        }
        self.max_id += 1;
        self.max_id - 1
    }

    fn release(&mut self, id: u32) {
        self.available.push_back(id);
    }
}

#[derive(Debug, Default)]
struct ObjectInfo {
    shards: Vec<ShardInfo>,
    pids: Vec<u32>,
}

pub const UNWIND_SHARDS_PER_PROCESS: usize = 256;

// UnwindEntryShard is a value type of bpf map entry
// Calling bpf_update_elem with a struct larger than 1MB seems to cause ENOMEM error on kernel 5.10
// The size of UnwindEntryShard is:
//     4B (id) + 4B (len) + 65535 * 16B (UnwindEntry) = 1048568B < 1048576B = 1MB
pub const UNWIND_ENTRIES_PER_SHARD: usize = 65535;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShardInfo {
    pub id: u32,
    // entry index is larger than UNWIND_ENTRIES_PER_SHARD
    pub entry_start: u16,
    pub entry_end: u16,
    pub offset: u64,
    pub pc_min: u64,
    pub pc_max: u64,
}

impl Default for ShardInfo {
    fn default() -> Self {
        Self {
            id: 0,
            entry_start: 0,
            entry_end: UNWIND_ENTRIES_PER_SHARD as u16,
            offset: 0,
            pc_min: u64::MAX,
            pc_max: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ProcessShardList {
    pub len: u8,
    pub entries: [ShardInfo; UNWIND_SHARDS_PER_PROCESS],
}

impl Default for ProcessShardList {
    fn default() -> Self {
        Self {
            len: 0,
            entries: [ShardInfo::default(); UNWIND_SHARDS_PER_PROCESS],
        }
    }
}

/*
 * This struct has size of 1M, do not allocate it on stack
 */
#[repr(C)]
#[derive(Clone, Debug)]
pub struct UnwindEntryShard {
    pub id: u32,
    pub len: u32,
    pub entries: [UnwindEntry; UNWIND_ENTRIES_PER_SHARD],
}

struct BoxedShard(NonNull<UnwindEntryShard>);

impl BoxedShard {
    fn new(id: u32) -> Self {
        // creating UnwindEntryShard with `new` or `default` still use stack
        // allocate with Allocater API to avoid this
        unsafe {
            let layout = Layout::new::<UnwindEntryShard>();
            let ptr = alloc(layout);
            if ptr.is_null() {
                handle_alloc_error(layout);
            }
            let ptr = ptr as *mut UnwindEntryShard;
            (*ptr).id = id;
            (*ptr).len = 0;
            // entries array do not require initializing
            Self(NonNull::new_unchecked(ptr as *mut UnwindEntryShard))
        }
    }
}

impl Drop for BoxedShard {
    fn drop(&mut self) {
        unsafe {
            let layout = Layout::new::<UnwindEntryShard>();
            dealloc(self.0.as_ptr() as *mut u8, layout);
        }
    }
}

impl AsRef<UnwindEntryShard> for BoxedShard {
    fn as_ref(&self) -> &UnwindEntryShard {
        unsafe { self.0.as_ref() }
    }
}

impl AsMut<UnwindEntryShard> for BoxedShard {
    fn as_mut(&mut self) -> &mut UnwindEntryShard {
        unsafe { self.0.as_mut() }
    }
}
