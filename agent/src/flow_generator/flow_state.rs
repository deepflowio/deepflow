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

use std::mem::{self, MaybeUninit};
use std::rc::Rc;

use super::FlowTimeout;

use crate::common::{enums::TcpFlags, Timestamp};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FlowState {
    #[default]
    Raw,
    Opening1,
    Opening2,
    Established,
    ClosingTx1,
    ClosingTx2,
    ClosingRx1,
    ClosingRx2,
    Closed,
    Reset,
    Exception,

    ServerReset,
    ServerCandidateQueueLack,
    ClientL4PortReuse,
    Syn1,
    SynAck1,
    EstablishReset,
    OpeningRst,

    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateValue {
    pub timeout: Timestamp,
    pub state: FlowState,
    pub closed: bool,
}

impl StateValue {
    pub fn new(timeout: Timestamp, state: FlowState, closed: bool) -> Self {
        Self {
            timeout,
            state,
            closed,
        }
    }
}

impl Default for StateValue {
    fn default() -> Self {
        Self {
            timeout: Timestamp::default(),
            state: FlowState::Raw,
            closed: false,
        }
    }
}

type StateEntry = Option<Rc<StateValue>>;
const N_FLAGS: usize = TcpFlags::MASK.bits() as usize + 1;
const N_STATES: usize = FlowState::Max as usize;

pub struct StateMachine([[StateEntry; N_FLAGS]; N_STATES]);

impl Default for StateMachine {
    fn default() -> Self {
        // Initializing with unsafe because:
        // 1. [StateEntry; N_FLAGS] is not possible because Rc is not Copy
        // 2. [T; N] implements Default for N <= 32, but N_FLAGS is 64
        unsafe {
            let mut arr: [[MaybeUninit<StateEntry>; N_FLAGS]; N_STATES] = {
                let arr: MaybeUninit<[[StateEntry; N_FLAGS]; N_STATES]> = MaybeUninit::uninit();
                mem::transmute(arr)
            };

            for flag_arr in arr.iter_mut() {
                for state in flag_arr.iter_mut() {
                    state.write(None);
                }
            }

            StateMachine(mem::transmute(arr))
        }
    }
}

impl StateMachine {
    pub fn new_master(t: &FlowTimeout) -> Self {
        let mut wrapped = StateMachine::default();
        let m = &mut wrapped.0;

        // for FlowState::Raw
        let s = Rc::new(StateValue::new(t.opening, FlowState::Opening1, false));
        m[FlowState::Raw as usize][TcpFlags::SYN.bits() as usize] = Some(s);

        // FIN(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::Raw as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Raw as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Raw as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closing, FlowState::Reset, false));
        m[FlowState::Raw as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Raw as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Raw as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(
            t.established,
            FlowState::Established,
            false,
        ));
        m[FlowState::Raw as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Raw as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Raw as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::Opening1
        let s = Rc::new(StateValue::new(t.opening, FlowState::Opening1, false));
        m[FlowState::Opening1 as usize][TcpFlags::SYN.bits() as usize] = Some(s);

        // FIN(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::Opening1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // RST(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::EstablishReset, false));
        m[FlowState::Opening1 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // 有ACK(正)
        let s = Rc::new(StateValue::new(
            t.established,
            FlowState::Established,
            false,
        ));
        m[FlowState::Opening1 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::Opening2
        let s = Rc::new(StateValue::new(t.opening, FlowState::Opening2, false));
        m[FlowState::Opening2 as usize][TcpFlags::SYN.bits() as usize] = Some(s);

        // FIN(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::Opening2 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // 有RST(正)
        let s = Rc::new(StateValue::new(t.opening_rst, FlowState::OpeningRst, false));
        m[FlowState::Opening2 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // 有ACK(正)
        let s = Rc::new(StateValue::new(
            t.established,
            FlowState::Established,
            false,
        ));
        m[FlowState::Opening2 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::Established
        let s = Rc::new(StateValue::new(
            t.established,
            FlowState::Established,
            false,
        ));
        m[FlowState::Established as usize][TcpFlags::SYN.bits() as usize] = Some(s);

        // 有FIN(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::Established as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Established as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Established as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // 有RST(正、反一致)
        let s = Rc::new(StateValue::new(t.established_rst, FlowState::Reset, false));
        m[FlowState::Established as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Established as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Established as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // 有ACK
        let s = Rc::new(StateValue::new(
            t.established,
            FlowState::Established,
            false,
        ));
        m[FlowState::Established as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Established as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Established as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::ClosingTx1
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::ClosingTx1 as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        // 有FIN(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::ClosingTx1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closing, FlowState::Reset, false));
        m[FlowState::ClosingTx1 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::ClosingTx1 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::ClosingTx2
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx2, false));
        m[FlowState::ClosingTx2 as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx2 as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx2, false));
        m[FlowState::ClosingTx2 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx2 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx2 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closed_fin, FlowState::Reset, false));
        m[FlowState::ClosingTx2 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx2 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx2 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // ACK(正)
        let s = Rc::new(StateValue::new(t.closed_fin, FlowState::Closed, false));
        m[FlowState::ClosingTx2 as usize][TcpFlags::ACK.bits() as usize] = Some(s);

        // for FlowState::ClosingRx1
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::ClosingRx1 as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        // FIN(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx2, false));
        m[FlowState::ClosingRx1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closing, FlowState::Reset, false));
        m[FlowState::ClosingRx1 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::ClosingRx1 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::ClosingRx2
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx2, false));
        m[FlowState::ClosingRx2 as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx2 as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        // FIN(正，反一致)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx2, false));
        m[FlowState::ClosingRx2 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx2 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx2 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closed_fin, FlowState::Reset, false));
        m[FlowState::ClosingRx2 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx2 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx2 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // ACK(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx2, false));
        m[FlowState::ClosingRx2 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx2 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx2 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::Closed
        let s = Rc::new(StateValue::new(t.closed_fin, FlowState::Closed, false));
        m[FlowState::Closed as usize][TcpFlags::ACK.bits() as usize] = Some(s);

        // for FlowState::Reset
        let s = Rc::new(StateValue::new(t.exception, FlowState::Reset, false));
        m[FlowState::Reset as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::Reset as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.exception, FlowState::Reset, false));
        m[FlowState::Reset as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Reset as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Reset as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.exception, FlowState::Reset, false));
        m[FlowState::Reset as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Reset as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Reset as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.exception, FlowState::Reset, false));
        m[FlowState::Reset as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Reset as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Reset as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::EXCEPTION

        // for FlowState::Syn1
        let s = Rc::new(StateValue::new(t.opening, FlowState::Opening1, false));
        m[FlowState::Syn1 as usize][TcpFlags::SYN.bits() as usize] = Some(s);

        // RST(正)
        let s = Rc::new(StateValue::new(
            t.closing,
            FlowState::ClientL4PortReuse,
            false,
        ));
        m[FlowState::Syn1 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // ACK(正)
        let s = Rc::new(StateValue::new(
            t.established,
            FlowState::Established,
            false,
        ));
        m[FlowState::Syn1 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // FIN(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::Syn1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // for FlowState::ClientL4PortReuse
        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::ClientL4PortReuse,
            false,
        ));
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::ClientL4PortReuse,
            false,
        ));
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::FIN_ACK.bits() as usize] =
            Some(s.clone());
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::ClientL4PortReuse,
            false,
        ));
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::RST_ACK.bits() as usize] =
            Some(s.clone());
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::ClientL4PortReuse,
            false,
        ));
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::PSH_ACK.bits() as usize] =
            Some(s.clone());
        m[FlowState::ClientL4PortReuse as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::SynAck1
        let s = Rc::new(StateValue::new(
            t.established,
            FlowState::Established,
            false,
        ));
        m[FlowState::SynAck1 as usize][TcpFlags::SYN.bits() as usize] = Some(s);

        // FIN(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx1, false));
        m[FlowState::SynAck1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // RST(正)
        let s = Rc::new(StateValue::new(t.closing, FlowState::Reset, false));
        m[FlowState::SynAck1 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // ACK(正)
        let s = Rc::new(StateValue::new(t.established, FlowState::SynAck1, false));
        m[FlowState::SynAck1 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::ServerCandidateQueueLack
        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::ServerCandidateQueueLack,
            false,
        ));
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::SYN.bits() as usize] =
            Some(s.clone());
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::SYN_ACK.bits() as usize] =
            Some(s);

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::ServerCandidateQueueLack,
            false,
        ));
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::FIN.bits() as usize] =
            Some(s.clone());
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::FIN_ACK.bits() as usize] =
            Some(s.clone());
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] =
            Some(s);

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::ServerCandidateQueueLack,
            false,
        ));
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::RST.bits() as usize] =
            Some(s.clone());
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::RST_ACK.bits() as usize] =
            Some(s.clone());
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::RST_PSH_ACK.bits() as usize] =
            Some(s);

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::ServerCandidateQueueLack,
            false,
        ));
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::ACK.bits() as usize] =
            Some(s.clone());
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::PSH_ACK.bits() as usize] =
            Some(s.clone());
        m[FlowState::ServerCandidateQueueLack as usize][TcpFlags::PSH_ACK_URG.bits() as usize] =
            Some(s);

        // for FlowState::ServerReset
        let s = Rc::new(StateValue::new(t.exception, FlowState::ServerReset, false));
        m[FlowState::ServerReset as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::ServerReset as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.exception, FlowState::ServerReset, false));
        m[FlowState::ServerReset as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::ServerReset as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ServerReset as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.exception, FlowState::ServerReset, false));
        m[FlowState::ServerReset as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::ServerReset as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ServerReset as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.exception, FlowState::ServerReset, false));
        m[FlowState::ServerReset as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ServerReset as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ServerReset as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::EstablishReset
        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::EstablishReset,
            false,
        ));
        m[FlowState::EstablishReset as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::EstablishReset as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::EstablishReset,
            false,
        ));
        m[FlowState::EstablishReset as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::EstablishReset as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::EstablishReset as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::EstablishReset,
            false,
        ));
        m[FlowState::EstablishReset as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::EstablishReset as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::EstablishReset as usize][TcpFlags::RST_PSH_ACK.bits() as usize] =
            Some(s.clone());

        let s = Rc::new(StateValue::new(
            t.exception,
            FlowState::EstablishReset,
            false,
        ));
        m[FlowState::EstablishReset as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::EstablishReset as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::EstablishReset as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::OpeningRst
        let s = Rc::new(StateValue::new(t.opening_rst, FlowState::OpeningRst, false));
        m[FlowState::OpeningRst as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        wrapped
    }

    pub fn new_slave(t: &FlowTimeout) -> Self {
        let mut wrapped = StateMachine::default();
        let m = &mut wrapped.0;

        // for FlowState::Raw
        // SYN/ACK(反)
        let s = Rc::new(StateValue::new(t.opening, FlowState::Opening2, false));
        m[FlowState::Raw as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        // FIN(反)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::Raw as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Raw as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Raw as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // for FlowState::Opening1
        let s = Rc::new(StateValue::new(t.opening, FlowState::Opening2, false));
        m[FlowState::Opening1 as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        // ACK(反)
        let s = Rc::new(StateValue::new(t.opening, FlowState::Syn1, false));
        m[FlowState::Opening1 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // RST(反)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ServerReset, false));
        m[FlowState::Opening1 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // FIN(反)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::Opening1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // for FlowState::Opening2
        let s = Rc::new(StateValue::new(t.opening, FlowState::Opening2, false));
        m[FlowState::Opening2 as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::Opening2 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // RST(反)
        let s = Rc::new(StateValue::new(t.closing, FlowState::EstablishReset, false));
        m[FlowState::Opening2 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Opening2 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // for FlowState::Established
        // SYN/ACK
        let s = Rc::new(StateValue::new(t.established, FlowState::SynAck1, false));
        m[FlowState::Established as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s.clone());

        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::Established as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Established as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Established as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // for FlowState::ClosingTx1
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx2, false));
        m[FlowState::ClosingTx1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // for FlowState::ClosingTx2
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingTx2, false));
        m[FlowState::ClosingTx2 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx2 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingTx2 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::ClosingRx1
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::ClosingRx1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::ClosingRx1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // for FlowState::ClosingRx2
        let s = Rc::new(StateValue::new(t.closed_fin, FlowState::Closed, false));
        m[FlowState::ClosingRx2 as usize][TcpFlags::ACK.bits() as usize] = Some(s);

        // for FlowState::Closed
        let s = Rc::new(StateValue::new(t.closed_fin, FlowState::Closed, false));
        m[FlowState::Closed as usize][TcpFlags::ACK.bits() as usize] = Some(s);

        // for FlowState::Reset

        // for FlowState::EXCEPTION

        // for FlowState::Syn1
        // SYN/ACK
        let s = Rc::new(StateValue::new(t.opening, FlowState::Opening2, false));
        m[FlowState::Syn1 as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        // 有ACK(反)
        let s = Rc::new(StateValue::new(t.opening, FlowState::Syn1, false));
        m[FlowState::Syn1 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // 有FIN(反)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::Syn1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // RST(反)
        let s = Rc::new(StateValue::new(t.closing, FlowState::EstablishReset, false));
        m[FlowState::Syn1 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::Syn1 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // for FlowState::SynAck1
        // SYN/ACK
        let s = Rc::new(StateValue::new(t.established, FlowState::SynAck1, false));
        m[FlowState::SynAck1 as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s);

        // 有FIN(反)
        let s = Rc::new(StateValue::new(t.closing, FlowState::ClosingRx1, false));
        m[FlowState::SynAck1 as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s);

        // RST(反)
        let s = Rc::new(StateValue::new(
            t.established_rst,
            FlowState::ServerCandidateQueueLack,
            false,
        ));
        m[FlowState::SynAck1 as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s);

        // ACK(反)
        let s = Rc::new(StateValue::new(
            t.established,
            FlowState::Established,
            false,
        ));
        m[FlowState::SynAck1 as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::SynAck1 as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        // for FlowState::ServerReset

        // for FlowState::ClientL4PortReuse

        // for FlowState::ServerCandidateQueueLack

        // for FlowState::OpeningRst
        let s = Rc::new(StateValue::new(t.opening_rst, FlowState::OpeningRst, false));
        m[FlowState::OpeningRst as usize][TcpFlags::SYN.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::SYN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::FIN.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::FIN_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::FIN_PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::RST.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::RST_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::RST_PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::PSH_ACK.bits() as usize] = Some(s.clone());
        m[FlowState::OpeningRst as usize][TcpFlags::PSH_ACK_URG.bits() as usize] = Some(s);

        wrapped
    }

    pub fn get(&self, state: FlowState, flags: TcpFlags) -> Option<&StateValue> {
        self.0[state as usize][(flags.bits() & TcpFlags::MASK.bits()) as usize]
            .as_ref()
            .map(Rc::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::AsRef;
    use std::fmt;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::sync::Arc;

    use super::*;

    use crate::common::endpoint::{
        EndpointData, EndpointDataPov, EndpointInfo, EPC_FROM_DEEPFLOW, EPC_FROM_INTERNET,
    };
    use crate::common::flow::{CloseType, PacketDirection};
    use crate::config::RuntimeConfig;
    use crate::flow_generator::flow_map::{Config, _new_flow_map_and_receiver};
    use crate::flow_generator::flow_node::FlowNode;
    use crate::flow_generator::{FlowTimeout, TcpTimeout};
    use crate::flow_generator::{FLOW_METRICS_PEER_DST, FLOW_METRICS_PEER_SRC, TIME_UNIT};
    use crate::rpc::get_timestamp;
    use crate::utils::test::Capture;
    use public::proto::common::TridentType;

    use packet_sequence_block::PacketSequenceBlock;

    const FILE_DIR: &'static str = "resources/test/flow_generator";

    #[test]
    fn state_machine_initialize() {
        let mut m: StateMachine = Default::default();
        for flag_arr in m.0.iter_mut() {
            for state in flag_arr.iter_mut() {
                assert!(state.is_none());
                *state = Some(Rc::new(StateValue::default()));
                assert!(state.is_some());
            }
        }
    }

    #[test]
    fn simple_get_state() {
        let flow_timeout: FlowTimeout = TcpTimeout::default().into();
        let m = StateMachine::new_master(&flow_timeout);
        assert_eq!(
            *m.get(FlowState::ClientL4PortReuse, TcpFlags::FIN_ACK)
                .unwrap(),
            StateValue::new(flow_timeout.exception, FlowState::ClientL4PortReuse, false,)
        );
    }

    #[test]
    fn test_closed_ack() {
        let packets = vec![
            (TcpFlags::SYN, PacketDirection::ClientToServer),
            (TcpFlags::SYN_ACK, PacketDirection::ServerToClient),
            (TcpFlags::ACK, PacketDirection::ClientToServer),
            (TcpFlags::PSH_ACK, PacketDirection::ClientToServer),
            (TcpFlags::PSH_ACK, PacketDirection::ServerToClient),
            (TcpFlags::FIN_ACK, PacketDirection::ServerToClient),
            (TcpFlags::FIN_ACK, PacketDirection::ClientToServer),
            (TcpFlags::ACK, PacketDirection::ServerToClient),
            (TcpFlags::ACK, PacketDirection::ClientToServer),
        ];

        let (_, mut flow_map, _) = _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut flow_node = FlowNode {
            timestamp_key: get_timestamp(0).as_nanos() as u64,

            tagged_flow: Default::default(),
            min_arrived_time: Timestamp::ZERO,
            recent_time: Timestamp::ZERO,
            timeout: Timestamp::ZERO,
            flow_state: FlowState::Raw,
            meta_flow_log: None,
            policy_data_cache: Default::default(),
            endpoint_data_cache: {
                let data = EndpointData {
                    src_info: EndpointInfo {
                        real_ip: Ipv4Addr::UNSPECIFIED.into(),
                        l2_epc_id: 0,
                        l3_epc_id: 0,
                        l2_end: false,
                        l3_end: false,
                        is_device: false,
                        is_vip_interface: false,
                        is_vip: false,
                        is_local_mac: false,
                        is_local_ip: false,
                    },
                    dst_info: EndpointInfo {
                        real_ip: Ipv4Addr::UNSPECIFIED.into(),
                        l2_epc_id: 0,
                        l3_epc_id: 0,
                        l2_end: false,
                        l3_end: false,
                        is_device: false,
                        is_vip_interface: false,
                        is_vip: false,
                        is_local_mac: false,
                        is_local_ip: false,
                    },
                };
                Some(EndpointDataPov::new(Arc::new(data)))
            },
            residual_request: 0,
            next_tcp_seq0: 0,
            next_tcp_seq1: 0,
            packet_in_tick: false,
            policy_in_tick: [false; 2],
            packet_sequence_block: Some(Box::new(PacketSequenceBlock::default())), // Enterprise Edition Feature: packet-sequence
        };

        let peers = &mut flow_node.tagged_flow.flow.flow_metrics_peers;
        peers[FLOW_METRICS_PEER_SRC].total_packet_count = 1;
        peers[FLOW_METRICS_PEER_DST].total_packet_count = 1;

        let config = (&RuntimeConfig::default()).into();
        for (flags, direction) in packets {
            let _ = flow_map.update_flow_state_machine(&config, &mut flow_node, flags, direction);
        }
        assert_eq!(flow_node.flow_state, FlowState::Closed);
        let _ = flow_map.update_flow_state_machine(
            &config,
            &mut flow_node,
            TcpFlags::PSH_ACK,
            PacketDirection::ClientToServer,
        );
        assert_eq!(flow_node.flow_state, FlowState::Exception);
    }

    #[test]
    fn state_machine() {
        let (_, mut flow_map, _) = _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut flow_node = FlowNode {
            timestamp_key: get_timestamp(0).as_nanos() as u64,

            tagged_flow: Default::default(),
            min_arrived_time: Timestamp::ZERO,
            recent_time: Timestamp::ZERO,
            timeout: Timestamp::ZERO,
            flow_state: FlowState::Raw,
            meta_flow_log: None,
            policy_data_cache: Default::default(),
            endpoint_data_cache: {
                let data = EndpointData {
                    src_info: EndpointInfo {
                        real_ip: Ipv4Addr::UNSPECIFIED.into(),
                        l2_epc_id: 0,
                        l3_epc_id: 0,
                        l2_end: false,
                        l3_end: false,
                        is_device: false,
                        is_vip_interface: false,
                        is_vip: false,
                        is_local_mac: false,
                        is_local_ip: false,
                    },
                    dst_info: EndpointInfo {
                        real_ip: Ipv4Addr::UNSPECIFIED.into(),
                        l2_epc_id: 0,
                        l3_epc_id: 0,
                        l2_end: false,
                        l3_end: false,
                        is_device: false,
                        is_vip_interface: false,
                        is_vip: false,
                        is_local_mac: false,
                        is_local_ip: false,
                    },
                };
                Some(EndpointDataPov::new(Arc::new(data)))
            },
            residual_request: 0,
            next_tcp_seq0: 0,
            next_tcp_seq1: 0,
            packet_in_tick: false,
            policy_in_tick: [false; 2],
            packet_sequence_block: Some(Box::new(PacketSequenceBlock::default())), // Enterprise Edition Feature: packet-sequence
        };

        let peers = &mut flow_node.tagged_flow.flow.flow_metrics_peers;
        peers[FLOW_METRICS_PEER_SRC].total_packet_count = 1;
        peers[FLOW_METRICS_PEER_DST].total_packet_count = 1;

        let config = (&RuntimeConfig::default()).into();
        for data in init_test_case() {
            flow_node.flow_state = data.cur_state;
            let closed = flow_map.update_flow_state_machine(
                &config,
                &mut flow_node,
                data.tcp_flags,
                data.pkt_dir,
            );
            assert!(
                closed == data.closed
                    && flow_node.flow_state == data.next_state
                    && flow_node.timeout == data.timeout,
                "{} actual result: [next_state: {:?}, timeout: {:?}, closed: {}]",
                data,
                flow_node.flow_state,
                flow_node.timeout,
                closed,
            );
        }
    }

    fn state_machine_helper<P: AsRef<Path>>(pcap_file: P, expect_close_type: CloseType) {
        let (module_config, mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);

        let capture = Capture::load_pcap(pcap_file, None);
        let packets = capture.as_meta_packets();
        let delta = packets.first().unwrap().lookup_key.timestamp;
        let mut last_timestamp = Timestamp::ZERO;
        let ep = EndpointDataPov::new(Arc::new(EndpointData {
            src_info: EndpointInfo {
                real_ip: Ipv4Addr::UNSPECIFIED.into(),
                l2_epc_id: EPC_FROM_DEEPFLOW,
                l3_epc_id: 1,
                l2_end: false,
                l3_end: false,
                is_device: false,
                is_vip_interface: false,
                is_vip: false,
                is_local_mac: false,
                is_local_ip: false,
            },
            dst_info: EndpointInfo {
                real_ip: Ipv4Addr::UNSPECIFIED.into(),
                l2_epc_id: EPC_FROM_DEEPFLOW,
                l3_epc_id: EPC_FROM_INTERNET,
                l2_end: false,
                l3_end: false,
                is_device: false,
                is_vip_interface: false,
                is_vip: false,
                is_local_mac: false,
                is_local_ip: false,
            },
        }));
        let config = Config {
            flow: &module_config.flow,
            log_parser: &module_config.log_parser,
            collector: &module_config.collector,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            ebpf: None,
        };
        for mut pkt in packets {
            pkt.endpoint_data.replace(ep.clone());

            pkt.lookup_key.timestamp = (pkt.lookup_key.timestamp - delta) + get_timestamp(0);
            last_timestamp = pkt.lookup_key.timestamp;
            flow_map.inject_meta_packet(&config, &mut pkt);
        }

        flow_map.inject_flush_ticker(&config, last_timestamp.into());
        flow_map.inject_flush_ticker(&config, (last_timestamp + Timestamp::from_secs(600)).into());

        let mut tagged_flows = vec![];
        // 如果不设置超时，队列就会永远等待
        while let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            tagged_flows.push(tagged_flow);
        }
        assert!(
            tagged_flows.len() > 0,
            "cannot receive tagged flow from flow_map"
        );
        if let Some(tagged_flow) = tagged_flows.pop() {
            assert_eq!(tagged_flow.flow.close_type, expect_close_type)
        }
    }

    #[test]
    fn syn_repeat() {
        state_machine_helper(
            Path::new(FILE_DIR).join("tcp-one-syn.pcap"),
            CloseType::ClientSynRepeat,
        )
    }

    #[test]
    fn syn_ack_repeat() {
        state_machine_helper(
            Path::new(FILE_DIR).join("tcp-n-syn-ack.pcap"),
            CloseType::ServerSynAckRepeat,
        )
    }

    #[test]
    fn client_source_port_reuse() {
        state_machine_helper(
            Path::new(FILE_DIR).join("syn-1.pcap"),
            CloseType::ClientSourcePortReuse,
        );
        state_machine_helper(
            Path::new(FILE_DIR).join("l4-source-port-reuse.pcap"),
            CloseType::ClientSourcePortReuse,
        );
    }

    #[test]
    fn server_reset() {
        state_machine_helper(
            Path::new(FILE_DIR).join("server-reset.pcap"),
            CloseType::ServerReset,
        )
    }

    #[test]
    fn server_queue_lack() {
        state_machine_helper(
            Path::new(FILE_DIR).join("server-queue-lack.pcap"),
            CloseType::ServerQueueLack,
        )
    }

    #[test]
    fn opening_reset() {
        state_machine_helper(
            Path::new(FILE_DIR).join("client-syn-try-lack.pcap"),
            CloseType::TcpFinClientRst,
        );
    }

    #[test]
    fn client_establish_reset() {
        state_machine_helper(
            Path::new(FILE_DIR).join("server-no-response.pcap"),
            CloseType::ClientEstablishReset,
        );
    }

    #[test]
    fn server_establish_reset() {
        state_machine_helper(
            Path::new(FILE_DIR).join("client-no-response.pcap"),
            CloseType::ServerEstablishReset,
        )
    }

    struct TestData {
        // input
        pub cur_state: FlowState,
        pub tcp_flags: TcpFlags,
        pub pkt_dir: PacketDirection,

        // expected output
        pub next_state: FlowState,
        pub timeout: Timestamp,
        pub closed: bool,
    }

    impl fmt::Display for TestData {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "current flow: [state: {:?}]; packet [tcp_flags: {}, direction: {:?}]\n",
                self.cur_state, self.tcp_flags, self.pkt_dir
            )?;
            write!(
                f,
                "expected result: [state: {:?}, timeout: {:?}, closed: {}\n",
                self.next_state, self.timeout, self.closed
            )
        }
    }

    fn init_test_case() -> Vec<TestData> {
        let ack_flags = vec![TcpFlags::ACK, TcpFlags::PSH_ACK, TcpFlags::PSH_ACK_URG];
        let fin_flags = vec![TcpFlags::FIN, TcpFlags::FIN_ACK, TcpFlags::FIN_PSH_ACK];
        let rst_flags = vec![TcpFlags::RST, TcpFlags::RST_ACK, TcpFlags::RST_PSH_ACK];
        let directions = vec![
            PacketDirection::ClientToServer,
            PacketDirection::ServerToClient,
        ];
        let flow_timeout: FlowTimeout = TcpTimeout::default().into();

        let mut cases = vec![];

        // FlowState::Raw
        let cur_state = FlowState::Raw;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::Opening1,
            timeout: flow_timeout.opening,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.closing,
                    closed: false,
                });
            }
        }
        for &tcp_flags in ack_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Established,
                    timeout: flow_timeout.established,
                    closed: false,
                });
            }
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::Opening2,
            timeout: flow_timeout.opening,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }

        // FlowState::Opening1
        let cur_state = FlowState::Opening1;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::Opening1,
            timeout: flow_timeout.opening,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::EstablishReset,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::Established,
                timeout: flow_timeout.established,
                closed: false,
            });
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::Opening2,
            timeout: flow_timeout.opening,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ServerReset,
                timeout: flow_timeout.opening,
                closed: false,
            });
        }
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::Syn1,
                timeout: flow_timeout.opening,
                closed: false,
            });
        }

        // FlowState::Opening2
        let cur_state = FlowState::Opening2;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::Opening2,
            timeout: flow_timeout.opening,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::OpeningRst,
                timeout: flow_timeout.opening_rst,
                closed: false,
            });
        }
        for &tcp_flags in ack_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Established,
                    timeout: flow_timeout.established,
                    closed: false,
                });
            }
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::Opening2,
            timeout: flow_timeout.opening,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::EstablishReset,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }

        // FlowState::Established
        let cur_state = FlowState::Established;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::Established,
            timeout: flow_timeout.established,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.established_rst,
                    closed: false,
                });
            }
        }
        for &tcp_flags in ack_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Established,
                    timeout: flow_timeout.established,
                    closed: false,
                });
            }
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::SynAck1,
            timeout: flow_timeout.established,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }

        // FlowState::ClosingTx1
        let cur_state = FlowState::ClosingTx1;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::ClosingTx1,
            timeout: flow_timeout.closing,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.closing,
                    closed: false,
                });
            }
        }
        for &tcp_flags in ack_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ClosingTx1,
                    timeout: flow_timeout.closing,
                    closed: false,
                });
            }
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::ClosingTx1,
            timeout: flow_timeout.closing,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx2,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }

        // FlowState::ClosingTx2
        let cur_state = FlowState::ClosingTx2;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::ClosingTx2,
            timeout: flow_timeout.closing,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ClosingTx2,
                    timeout: flow_timeout.closing,
                    closed: false,
                });
            }
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.closed_fin,
                    closed: false,
                });
            }
        }
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::ACK,
            pkt_dir,
            next_state: FlowState::Closed,
            timeout: flow_timeout.closed_fin,
            closed: false,
        });

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::ClosingTx2,
            timeout: flow_timeout.closing,
            closed: false,
        });
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx2,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }

        // FlowState::ClosingRx1
        let cur_state = FlowState::ClosingRx1;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::ClosingRx1,
            timeout: flow_timeout.closing,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx2,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.closing,
                    closed: false,
                });
            }
        }
        for &tcp_flags in ack_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ClosingRx1,
                    timeout: flow_timeout.closing,
                    closed: false,
                });
            }
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::ClosingRx1,
            timeout: flow_timeout.closing,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }

        // FlowState::ClosingRx2
        let cur_state = FlowState::ClosingRx2;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::ClosingRx2,
            timeout: flow_timeout.closing,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ClosingRx2,
                    timeout: flow_timeout.closing,
                    closed: false,
                });
            }
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.closed_fin,
                    closed: false,
                });
            }
        }
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx2,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::ClosingRx2,
            timeout: flow_timeout.closing,
            closed: false,
        });
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::ACK,
            pkt_dir,
            next_state: FlowState::Closed,
            timeout: flow_timeout.closed_fin,
            closed: false,
        });

        // FlowState::Reset
        let cur_state = FlowState::Reset;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::Reset,
            timeout: flow_timeout.exception,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }
        for &tcp_flags in ack_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::Reset,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }

        // FlowState::Syn1
        let cur_state = FlowState::Syn1;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::Opening1,
            timeout: flow_timeout.opening,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClientL4PortReuse,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::Established,
                timeout: flow_timeout.established,
                closed: false,
            });
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::Opening2,
            timeout: flow_timeout.opening,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::EstablishReset,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::Syn1,
                timeout: flow_timeout.opening,
                closed: false,
            });
        }

        // FlowState::ClientL4PortReuse
        let cur_state = FlowState::ClientL4PortReuse;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::ClientL4PortReuse,
            timeout: flow_timeout.exception,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ClientL4PortReuse,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClientL4PortReuse,
                timeout: flow_timeout.exception,
                closed: false,
            });
        }
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClientL4PortReuse,
                timeout: flow_timeout.exception,
                closed: false,
            });
        }

        // FlowState::SynAck1
        let cur_state = FlowState::SynAck1;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::Established,
            timeout: flow_timeout.established,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingTx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::Reset,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::SynAck1,
                timeout: flow_timeout.established,
                closed: false,
            });
        }

        let pkt_dir = PacketDirection::ServerToClient;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN_ACK,
            pkt_dir,
            next_state: FlowState::SynAck1,
            timeout: flow_timeout.established,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ClosingRx1,
                timeout: flow_timeout.closing,
                closed: false,
            });
        }
        for &tcp_flags in rst_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::ServerCandidateQueueLack,
                timeout: flow_timeout.established_rst,
                closed: false,
            });
        }
        for &tcp_flags in ack_flags.iter() {
            cases.push(TestData {
                cur_state,
                tcp_flags,
                pkt_dir,
                next_state: FlowState::Established,
                timeout: flow_timeout.established,
                closed: false,
            });
        }

        // FlowState::ServerCandidateQueueLack
        let cur_state = FlowState::ServerCandidateQueueLack;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::ServerCandidateQueueLack,
            timeout: flow_timeout.exception,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ServerCandidateQueueLack,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ServerCandidateQueueLack,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }
        for &tcp_flags in ack_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ServerCandidateQueueLack,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }

        // FlowState::ServerReset
        let cur_state = FlowState::ServerReset;
        let pkt_dir = PacketDirection::ClientToServer;
        cases.push(TestData {
            cur_state,
            tcp_flags: TcpFlags::SYN,
            pkt_dir,
            next_state: FlowState::ServerReset,
            timeout: flow_timeout.exception,
            closed: false,
        });
        for &tcp_flags in fin_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ServerReset,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }
        for &tcp_flags in rst_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ServerReset,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }
        for &tcp_flags in ack_flags.iter() {
            for &pkt_dir in directions.iter() {
                cases.push(TestData {
                    cur_state,
                    tcp_flags,
                    pkt_dir,
                    next_state: FlowState::ServerReset,
                    timeout: flow_timeout.exception,
                    closed: false,
                });
            }
        }

        cases
    }
}
