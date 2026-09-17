use std::ptr;

use libc::c_int;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpOptionTracingStats {
    pub map_update_failed: u64,
    pub map_delete_failed: u64,
    pub map_lookup_missed: u64,
    pub task_tgid_read_failed: u64,
    pub reserve_failed: u64,
    pub store_failed: u64,
    bpf_generation: u64,
}

impl TcpOptionTracingStats {
    pub fn delta_since(self, previous: Self) -> Self {
        if self.bpf_generation != previous.bpf_generation {
            return self;
        }

        Self {
            map_update_failed: self
                .map_update_failed
                .saturating_sub(previous.map_update_failed),
            map_delete_failed: self
                .map_delete_failed
                .saturating_sub(previous.map_delete_failed),
            map_lookup_missed: self
                .map_lookup_missed
                .saturating_sub(previous.map_lookup_missed),
            task_tgid_read_failed: self
                .task_tgid_read_failed
                .saturating_sub(previous.task_tgid_read_failed),
            reserve_failed: self.reserve_failed.saturating_sub(previous.reserve_failed),
            store_failed: self.store_failed.saturating_sub(previous.store_failed),
            bpf_generation: self.bpf_generation,
        }
    }
}

extern "C" {
    fn tcp_option_tracing_get_stats(stats: *mut TcpOptionTracingStats) -> c_int;
}

pub fn stats() -> Result<TcpOptionTracingStats, c_int> {
    let mut stats = TcpOptionTracingStats::default();
    let code = unsafe { tcp_option_tracing_get_stats(ptr::from_mut(&mut stats)) };
    if code == 0 {
        Ok(stats)
    } else {
        Err(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cumulative_stats_are_reported_as_interval_deltas() {
        let previous = TcpOptionTracingStats {
            reserve_failed: 2,
            bpf_generation: 1,
            ..Default::default()
        };
        let current = TcpOptionTracingStats {
            reserve_failed: 5,
            bpf_generation: 1,
            ..Default::default()
        };

        assert_eq!(
            current.delta_since(previous),
            TcpOptionTracingStats {
                reserve_failed: 3,
                bpf_generation: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn a_new_bpf_instance_starts_a_new_stats_interval() {
        let previous = TcpOptionTracingStats {
            reserve_failed: 5,
            bpf_generation: 1,
            ..Default::default()
        };
        let current = TcpOptionTracingStats {
            reserve_failed: 7,
            bpf_generation: 2,
            ..Default::default()
        };

        assert_eq!(
            current.delta_since(previous),
            TcpOptionTracingStats {
                reserve_failed: 7,
                bpf_generation: 2,
                ..Default::default()
            }
        );
    }
}
