use std::path::PathBuf;

use libbpf_rs::{query, MapFlags, MapHandle};

use profile::dwarf::{ShardInfoList, UnwindEntryShard, ENTRIES_PER_SHARD};

pub fn main() {
    let mut args = std::env::args();
    let Some(pid) = args.nth(1).and_then(|p| p.parse::<u32>().ok()) else {
        eprintln!("no pid");
        return;
    };
    let mut pyrt_address = None;
    println!("populate unwind table for process#{pid}");
    let mut maps = profile::process::get_executable_memory_areas(pid).unwrap();
    let mut all_entries = vec![];
    let mut total_entries = 0;
    for m_area in maps.drain(..) {
        if m_area.path == "/usr/bin/python3.10" {
            pyrt_address = Some(m_area.m_start + 0x5a1ac0 + 568);
        }
        let mut path: PathBuf = ["/proc", &pid.to_string(), "root"].iter().collect();
        path.push(&m_area.path[1..]);
        if let Ok(mut entries) = profile::dwarf::read_unwind_entries(&path) {
            total_entries += entries.len();
            entries
                .iter_mut()
                .for_each(|entry| entry.pc += m_area.m_start);
            all_entries.extend(entries);
        }
    }

    let mut shards = vec![];
    let mut shard_id = 0;
    let mut shard_info_list = ShardInfoList::default();
    while !all_entries.is_empty() {
        let mut shard = UnwindEntryShard::default();
        for (i, entry) in all_entries
            .drain(..all_entries.len().min(ENTRIES_PER_SHARD))
            .enumerate()
        {
            shard.len += 1;
            shard.entries[i] = entry;
        }
        let info = &mut shard_info_list.info[shard_id];
        info.id = shard_id as i32;
        info.pc_min = shard.entries[0].pc;
        info.pc_max = all_entries.get(0).map(|e| e.pc).unwrap_or(u64::MAX);
        shards.push(shard);
        shard_id += 1;
    }

    let Some(pyrt_address) = pyrt_address else {
        eprintln!("no thread state address found");
        return;
    };
    println!("{total_entries} entries updated in {} shards", shards.len());

    for m in query::MapInfoIter::default() {
        if m.name.as_c_str() == c"__dwarf_shard_t" {
            println!("update shard map#{}", m.id);
            let handle = MapHandle::from_map_id(m.id).unwrap();
            handle
                .update(
                    &pid.to_le_bytes(),
                    shard_info_list.as_slice(),
                    MapFlags::ANY,
                )
                .unwrap();
        } else if m.name.as_c_str() == c"__dwarf_unwind_" {
            println!("update unwind map#{}", m.id);
            let handle = MapHandle::from_map_id(m.id).unwrap();
            for (i, shard) in shards.iter().enumerate() {
                handle
                    .update(&(i as u32).to_le_bytes(), shard.as_slice(), MapFlags::ANY)
                    .unwrap();
            }
        } else if m.name.as_c_str() == c"__python_tstate" {
            println!("update tstate map#{} to {pyrt_address}", m.id);
            let handle = MapHandle::from_map_id(m.id).unwrap();
            handle
                .update(&[0; 4], &pyrt_address.to_le_bytes(), MapFlags::ANY)
                .unwrap();
        }
    }
}
