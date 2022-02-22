use std::time::Duration;

pub const TIMEOUT_OTHERS: Duration = Duration::from_secs(5);
pub const TIMEOUT_ESTABLISHED: Duration = Duration::from_secs(300);
pub const TIMEOUT_CLOSING: Duration = Duration::from_secs(35);

pub struct TcpTimeout {
    pub established: Duration,
    pub closing_rst: Duration,
    pub others: Duration,
}

impl Default for TcpTimeout {
    fn default() -> Self {
        Self {
            established: TIMEOUT_ESTABLISHED,
            closing_rst: TIMEOUT_CLOSING,
            others: TIMEOUT_OTHERS,
        }
    }
}

pub struct FlowTimeout {
    pub opening: Duration,
    pub established: Duration,
    pub closing: Duration,
    pub established_rst: Duration,
    pub exception: Duration,
    pub closed_fin: Duration,
    pub single_direction: Duration,

    pub min: Duration,
    pub max: Duration, // time window
}

impl From<TcpTimeout> for FlowTimeout {
    fn from(t: TcpTimeout) -> Self {
        let mut ft = Self {
            opening: t.others,
            established: t.established,
            closing: t.others,
            established_rst: t.closing_rst,
            exception: t.others,
            closed_fin: Duration::from_secs(0),
            single_direction: t.others,
            min: Duration::from_secs(0),
            max: Duration::from_secs(0),
        };
        ft.update_min_max();
        ft
    }
}

impl FlowTimeout {
    fn update_min_max(&mut self) {
        self.min = self
            .opening
            .min(self.established)
            .min(self.closing)
            .min(self.established_rst)
            .min(self.exception)
            .min(self.closed_fin)
            .min(self.single_direction);
        self.max = self
            .opening
            .max(self.established)
            .max(self.closing)
            .max(self.established_rst)
            .max(self.exception)
            .max(self.closed_fin)
            .max(self.single_direction);
    }
}
