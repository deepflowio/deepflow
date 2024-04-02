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

use std::error::Error;
use std::process::Command;

fn generate_protobuf() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .build_server(false)
        .out_dir("src/proto")
        .compile(
            &[
                "../../../message/common.proto",
                "../../../message/trident.proto",
                "../../../message/metric.proto",
                "../../../message/flow_log.proto",
                "../../../message/stats.proto",
                "../../../message/k8s_event.proto",
            ],
            &["../../../message"],
        )?;
    tonic_build::configure()
        .build_server(false)
        .out_dir("src/proto/integration")
        .compile(
            &["../../../message/opentelemetry/opentelemetry/proto/trace/v1/trace.proto"],
            &["../../../message/opentelemetry"],
        )?;

    // FIXME: Wait for the rustfmt ignore attribute to be removed in stable rust support
    Command::new("cargo")
        .args(["fmt", "--", "src/proto/*.rs", "src/proto/integration/*.rs"])
        .spawn()?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    generate_protobuf()?;
    Ok(())
}
