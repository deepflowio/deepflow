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

use std::time::Instant;

use criterion::*;

use deepflow_agent::common::TapTyper;

fn bench_tap_typer(c: &mut Criterion) {
    c.bench_function("get_tap_type_by_vlan", |b| {
        let tap_typer = TapTyper::new();

        b.iter_custom(|iters| {
            let start = Instant::now();
            for i in 0..iters {
                let _ = tap_typer.get_tap_type_by_vlan((i & 4095) as u16);
            }
            start.elapsed()
        })
    });
}

criterion_group!(benches, bench_tap_typer);
criterion_main!(benches);
