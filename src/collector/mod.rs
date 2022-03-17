pub(crate) mod acc_flow;
mod consts;
pub(crate) mod quadruple_generator;

use bitflags::bitflags;

bitflags! {
    pub struct MetricsType: u32 {
        const SECOND = 1;
        const MINUTE = 1<<1;
   }
}
