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
pub mod bpf;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod header;
pub mod options;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod tpacket;

pub use bpf::*;
pub use options::{OptSocketType, OptTpacketVersion, Options};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use tpacket::Tpacket;

/* example

```
   let mut opts: Options = Default::default();
   opts.version = options::OptTpacketVersion::TpacketVersion2;
   let mut socket = Tpacket::new(opts).unwrap();
   println!("af_packet init ok.");
   let mut last: u64 = 0;
   let mut flags = false;

   println!(
       "2: {:?} 3: {:?}",
       options::OptTpacketVersion::TpacketVersion2 as u32,
       options::OptTpacketVersion::TpacketVersion3 as u32
   );
   if let Err(e) = socket.set_bpf(CString::new("arp").unwrap()) {
       println!("set bpf error: {}", e);
       return;
   }
   loop {
       if let Some(packet) = socket.read() {
           let now = packet.timestamp.as_secs();
           if now - last >= 1 {
               last = now;
               flags = true;
           }
           println!("{:?}", packet.data);
       }
       if flags {
           let stats = socket.get_socket_stats();
           println!("{:?} {:?}", last, stats);
           flags = false;
       }
   }
```

 */
