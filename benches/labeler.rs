use std::rc::Rc;
use std::str::FromStr;
use std::time::Instant;

use cidr_utils::cidr::IpCidr;
use criterion::*;

use trident::_Cidr as Cidr;
use trident::_Labeler as Labeler;
use trident::_LookupKey as LookupKey;
use trident::_MacAddr as MacAddr;
use trident::{_IpNet as IpNet, _PlatformData as PlatformData};

fn bench_labeler(c: &mut Criterion) {
    c.bench_function("labeler", |b| {
        b.iter_custom(|iters| {
            let mut labeler: Labeler = Default::default();
            let mut cidr_list: Vec<Rc<Cidr>> = Vec::new();
            let mut iface_list: Vec<Rc<PlatformData>> = Vec::new();

            let interface: PlatformData = PlatformData {
                mac: 0x112233445566,
                ips: vec![IpNet {
                    raw_ip: "192.168.0.200".parse().unwrap(),
                    ..Default::default()
                }],
                epc_id: 10,
                ..Default::default()
            };
            iface_list.push(Rc::new(interface));

            for i in 0..100 {
                let ip = "192.168.".to_string().as_str().to_owned()
                    + ((i >> 8) & 0xff).to_string().as_str()
                    + ".".to_string().as_str()
                    + (i & 0xff).to_string().as_str()
                    + "/32".to_string().as_str();
                let cidr: Cidr = Cidr {
                    ip_net: IpCidr::from_str(&ip).unwrap(),
                    epc_id: 10,
                    ..Default::default()
                };

                cidr_list.push(Rc::new(cidr));
            }
            labeler.update_cidr_table(&cidr_list);
            labeler.update_interface_table(&iface_list);

            let key: LookupKey = LookupKey {
                src_mac: MacAddr::from_str("11:22:33:44:55:66").unwrap(),
                src_ip: "192.168.0.100".parse().unwrap(),
                dst_ip: "192.168.0.200".parse().unwrap(),
                ..Default::default()
            };

            let start = Instant::now();
            for _ in 0..iters {
                labeler.get_endpoint_data(&key);
            }
            start.elapsed()
        })
    });
}

criterion_group!(benches, bench_labeler);
criterion_main!(benches);
