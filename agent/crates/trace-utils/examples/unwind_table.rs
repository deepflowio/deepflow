use trace_utils::unwind::UnwindTable;

use log::info;

fn main() {
    env_logger::init();
    let pid: u32 = std::env::args()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap();
    info!("read process#{pid}");
    unsafe {
        let mut table = UnwindTable::new(0, 0);
        table.load(pid);
    }
}
