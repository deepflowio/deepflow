pub mod ebpf_collector;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ebpf init error.")]
    EbpfInitError,
    #[error("ebpf running error.")]
    EbpfRunningError,
    #[error("l7 parse error.")]
    EbpfL7ParseError,
    #[error("l7 get log info error.")]
    EbpfL7GetLogInfoError,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub use ebpf_collector::EbpfCollector;

/* example

```
use trident::common::protocol_logs::AppProtoLogsData;
use trident::ebpf_collector::ebpf_collector::EbpfCollector;
use trident::utils::queue::bounded;

fn main() {
    let (s, r, _) = bounded::<Box<AppProtoLogsData>>(1024);
    let mut collector = EbpfCollector::new(s).unwrap();

    collector.start();

    loop {
        if let Ok(msg) = r.recv(None) {
            println!("{}", msg);
        }
    }
}
```

 */
