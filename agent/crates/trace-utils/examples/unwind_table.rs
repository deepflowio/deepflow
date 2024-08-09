use trace_utils::unwind::dwarf::read_unwind_entries;

use std::fs;

use log::info;

fn main() {
    env_logger::init();
    let filename = std::env::args().nth(1).unwrap();
    info!("read {filename}");
    let contents = fs::read(filename).unwrap();
    read_unwind_entries(&contents);
}
