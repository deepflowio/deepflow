pub fn read_u16_be(bs: &[u8]) -> u16 {
    assert!(bs.len() >= 2);
    u16::from_be_bytes(*<&[u8; 2]>::try_from(&bs[..2]).unwrap())
}
