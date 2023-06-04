/*
 * Copyright (c) 2023 Yunshan Networks
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

use std::path::Path;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use vhost::{
    vhost_user::{Listener, Slave},
    VhostBackend,
    VhostUserMemoryRegionInfo,
    VringConfigData,
};
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock, VringT};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vm_memory::{FileOffset, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap};
use virtio_bindings::bindings::virtio_config::{
    VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1,
};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_bindings::virtio_net::*;
use virtio_queue::{QueueOwnedT, Queue};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GM<B> = GuestMemoryAtomic<GuestMemoryMmap<B>>;

struct DummyVhostBackend {
    events: u64,
    event_idx: bool,
    acked_features: u64,
    mem: Option<GM<()>>,
    exit_event: EventFd,
}

impl DummyVhostBackend {
    fn new() -> Self {
        Self {
            events: 0,
            event_idx: false,
            acked_features: 0,
            exit_event: EventFd::new(EFD_NONBLOCK).unwrap(),
            mem: None,
        }
    }
}

impl DummyVhostBackend {
    fn process_queue(&mut self, vring: &VringRwLock) -> Result<(), bool> {
        // TODO
        Ok(())
    }
}

impl VhostUserBackendMut<VringRwLock, ()> for DummyVhostBackend {
    fn num_queues(&self) -> usize {
        println!("num_queues");
        2
    }

    fn max_queue_size(&self) -> usize {
        println!("max_queue_size");

        4096
    }

    fn features(&self) -> u64 {
        println!("features");


        1 << VIRTIO_NET_F_GUEST_CSUM
             | 1 << VIRTIO_NET_F_CSUM
             | 1 << VIRTIO_NET_F_GUEST_TSO4
             | 1 << VIRTIO_NET_F_GUEST_TSO6
             | 1 << VIRTIO_NET_F_GUEST_ECN
             | 1 << VIRTIO_NET_F_GUEST_UFO
             | 1 << VIRTIO_NET_F_HOST_TSO4
             | 1 << VIRTIO_NET_F_HOST_TSO6
             | 1 << VIRTIO_NET_F_HOST_ECN
             | 1 << VIRTIO_NET_F_HOST_UFO
             | 1 << VIRTIO_NET_F_CTRL_VQ
             | 1 << VIRTIO_NET_F_MQ
             | 1 << VIRTIO_NET_F_MAC
             | 1 << VIRTIO_NET_F_MTU
             | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
             | 1 << VIRTIO_F_VERSION_1
             | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()

        // 1 << VIRTIO_F_VERSION_1
        //     | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
        //     | 1 << VIRTIO_RING_F_INDIRECT_DESC
        //     | 1 << VIRTIO_RING_F_EVENT_IDX
        //     | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> vhost::vhost_user::VhostUserProtocolFeatures {
        println!("protocol_features");
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
    }

    fn set_event_idx(&mut self, enabled: bool) {
        println!("set_event_idx");

        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GM<()>) -> std::io::Result<()> {
        println!("update_memory");
        self.mem = Some(mem);
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        println!("exit_event");

        self.exit_event.try_clone().ok()
    }

    fn handle_event(
            &mut self,
            device_event: u16,
            evset: EventSet,
            vrings: &[VringRwLock],
            thread_id: usize,
        ) -> std::io::Result<bool> {
        if evset != EventSet::IN {
            return Ok(false);
        }
        match device_event {
            0 => {
                let vring = &vrings[0];
                if self.event_idx {
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_queue(vring);
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    } 
                } else {
                    self.process_queue(vring);
                }
            }
            _ => {
                println!("xxxxxxxxx unsupport {}", device_event);
            }
        }
        Ok(false)
    }

}
pub struct VHost {
    backend: Arc<Mutex<DummyVhostBackend>>,
    daemon: VhostUserDaemon<Arc<Mutex<DummyVhostBackend>>, VringRwLock>
    // listener: Listener,
    // master: Option<Master>,
    // queue: Option<Queue>,
}

impl VHost {
    pub fn new(path: String) -> VHost {
        let mem = GuestMemoryAtomic::new(GuestMemoryMmap::<()>::new());
        let backend = Arc::new(Mutex::new(DummyVhostBackend::new()));
        let listener = Listener::new(path, false).unwrap();
        let mut daemon = VhostUserDaemon::new(
            "Deepflow Agent Vhost Server".to_string(),
            backend.clone(),
            mem).unwrap();
        let epoll_handers= daemon.

        daemon.start(listener).unwrap();
        VHost {
            backend,
            daemon,
        }
    }

    fn reset(&mut self) {
        // let stream = self.listener.accept().unwrap();
        // if stream.is_none() {
        //     return;
        // }
        // let master = Master::from_stream(stream.unwrap(), 1);

    }

    fn recv(&mut self) {


    }
}
