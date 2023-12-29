use std::collections::HashSet;

pub fn get_expected_headers() -> HashSet<Vec<u8>> {
    let mut hash_set = HashSet::new();
    hash_set.insert(b":method".to_vec());
    hash_set.insert(b":status".to_vec());
    hash_set.insert(b"host".to_vec());
    hash_set.insert(b":authority".to_vec());
    hash_set.insert(b":path".to_vec());
    hash_set.insert(b"content-type".to_vec());
    hash_set.insert(b"content-length".to_vec());
    hash_set.insert(b"user-agent".to_vec());
    hash_set.insert(b"referer".to_vec());
    hash_set
}
