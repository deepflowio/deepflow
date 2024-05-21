use std::fmt;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;

#[derive(Debug)]
pub struct MemoryArea {
    pub m_start: u64,
    pub m_end: u64,
    pub path: String,
}

impl fmt::Display for MemoryArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({:016x}-{:016x} {}",
            self.m_start, self.m_end, self.path
        )
    }
}

pub fn get_executable_memory_areas(pid: u32) -> io::Result<Vec<MemoryArea>> {
    let path: PathBuf = ["/proc", &pid.to_string(), "maps"].iter().collect();
    let reader = io::BufReader::new(File::open(&path)?);

    let mut areas = vec![];
    let mut last_area: Option<MemoryArea> = None;
    let mut last_executable = false;
    for line in reader.lines() {
        let line = line?;
        let mut segs = line.split_whitespace();
        let addrs = segs.next();
        let perms = segs.next();
        let Some(path) = segs.nth(3) else {
            continue;
        };
        let mut addrs = addrs
            .unwrap()
            .splitn(2, "-")
            .map(|addr| u64::from_str_radix(addr, 16));
        let Some(Ok(m_start)) = addrs.next() else {
            continue;
        };
        let Some(Ok(m_end)) = addrs.next() else {
            continue;
        };
        let perms = perms.unwrap();
        match last_area.as_mut() {
            Some(area) if area.path == path => {
                last_executable |= perms.contains('x');
                area.m_start = area.m_start.min(m_start);
                area.m_end = area.m_end.max(m_end);
            }
            _ => {
                if last_executable {
                    areas.push(last_area.take().unwrap());
                }
                last_area.replace(MemoryArea {
                    m_start,
                    m_end,
                    path: path.to_owned(),
                });
                last_executable = perms.contains('x');
            }
        }
    }
    Ok(areas)
}
