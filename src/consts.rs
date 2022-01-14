pub const DROPLET_PORT: u16 = 20033;

#[derive(Debug)]
pub enum TapType {
    Any = 0,
    IspMin = 1,
    Tor = 3,
    Max = 256,
}

impl TapType {
    #[allow(non_upper_case_globals)]
    pub const Min: TapType = TapType::IspMin;
}
