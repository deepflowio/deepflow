/*
 * Copyright (c) 2022 Yunshan Networks
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

use std::process::exit;

use log::error;
use nix::sys::signal::{self, SaFlags, Signal};

extern "C" fn handle_sigsegv(s: i32) {
    for i in Signal::iterator() {
        if i as i32 == s {
            error!("terminated by signal {:?}", i);
            exit(1);
        }
    }
    error!("terminated by unknown signal {}", s);
    exit(1);
}

pub fn disable_coredump_by_hook_signal() {
    let sig_action = signal::SigAction::new(
        signal::SigHandler::Handler(handle_sigsegv),
        SaFlags::SA_SIGINFO,
        signal::SigSet::empty(),
    );

    unsafe {
        // hook all the signal which will generate coredump
        let _ = signal::sigaction(signal::SIGSEGV, &sig_action);
        let _ = signal::sigaction(signal::SIGABRT, &sig_action);
        let _ = signal::sigaction(signal::SIGTRAP, &sig_action);
        let _ = signal::sigaction(signal::SIGFPE, &sig_action);
        let _ = signal::sigaction(signal::SIGXCPU, &sig_action);
        let _ = signal::sigaction(signal::SIGXFSZ, &sig_action);
        let _ = signal::sigaction(signal::SIGSYS, &sig_action);
    }
}
