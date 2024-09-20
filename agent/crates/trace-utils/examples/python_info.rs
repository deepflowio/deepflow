use trace_utils::unwind::python;

use log::info;

fn main() {
    env_logger::init();
    let pid: u32 = std::env::args()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap();
    match python::InterpreterInfo::new(pid) {
        Ok(v) => {
            info!(
                "process#{pid} is Python {}, ThreadState address: 0x{:x}",
                v.version, v.thread_address
            );
        }
        Err(e) => info!("process#{pid} is not Python: {e}"),
    }
}
