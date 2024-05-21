use std::path::PathBuf;

pub fn main() {
    let mut args = std::env::args();
    let Some(pid) = args.nth(1).and_then(|p| p.parse::<u32>().ok()) else {
        println!("no pid");
        return;
    };
    let Some(pc) = args.next().and_then(|p| u64::from_str_radix(&p, 16).ok()) else {
        println!("no pc");
        return;
    };
    println!("find {:016x} for process#{pid}", pc);
    for entry in profile::process::get_executable_memory_areas(pid).unwrap() {
        if pc >= entry.m_start && pc < entry.m_end {
            println!("pc {:016x} is in {}", pc, entry);
            let mut path: PathBuf = ["/proc", &pid.to_string(), "root"].iter().collect();
            path.push(&entry.path[1..]);
            if let Ok(entries) = profile::dwarf::read_unwind_entries(path) {
                let index =
                    match entries.binary_search_by_key(&(pc - entry.m_start), |entry| entry.pc) {
                        Ok(index) => index,
                        Err(index) => index - 1,
                    };
                if let Some(entry) = entries.get(index) {
                    println!("{}", entry);
                }
            }
            return;
        }
    }
}
