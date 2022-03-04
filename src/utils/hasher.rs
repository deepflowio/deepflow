use std::hash::{BuildHasher, Hasher};

// Jenkins Wiki： https://en.wikipedia.org/wiki/Jenkins_hash_function
// 64位算法： https://blog.csdn.net/yueyedeai/article/details/17025265
// 32位算法： http://burtleburtle.net/bob/hash/integer.html

// Jenkins哈希的两个关键特性是：
//   1.雪崩性（更改输入参数的任何一位，就将引起输出有一半以上的位发生变化）
//   2.可逆性
#[derive(Default)]
pub struct Jenkins64Hasher(u64);

impl Jenkins64Hasher {
    fn jenkins(mut hash: u64) -> u64 {
        hash = hash
            .overflowing_shl(21)
            .0
            .overflowing_sub(hash)
            .0
            .overflowing_sub(1)
            .0;
        hash = hash ^ hash.overflowing_shr(24).0;
        hash = hash
            .overflowing_add(hash.overflowing_shl(3).0)
            .0
            .overflowing_add(hash.overflowing_shl(8).0)
            .0;
        hash = hash ^ hash.overflowing_shr(14).0;
        hash = hash
            .overflowing_add(hash.overflowing_shl(2).0)
            .0
            .overflowing_add(hash.overflowing_shl(4).0)
            .0;
        hash = hash ^ hash.overflowing_shr(28).0;
        hash = hash.overflowing_add(hash.overflowing_shl(31).0).0;

        hash
    }
}

impl BuildHasher for Jenkins64Hasher {
    type Hasher = Self;
    fn build_hasher(&self) -> Self::Hasher {
        Jenkins64Hasher(0)
    }
}

impl Hasher for Jenkins64Hasher {
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            if chunk.len() != 8 {
                // last bytes slice
                let mut byte_u64 = [0u8; 8];
                byte_u64[..chunk.len()].copy_from_slice(chunk);
                self.0 ^= Self::jenkins(u64::from_le_bytes(byte_u64));
                return;
            }
            let key = bytes
                .get(..8)
                .and_then(|s| <&[u8; 8]>::try_from(s).ok())
                .map(|s| u64::from_le_bytes(*s))
                .unwrap();
            self.0 ^= Self::jenkins(key)
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_jenkins64() {
        assert_eq!(
            Jenkins64Hasher::jenkins(1281291242888) ^ Jenkins64Hasher::jenkins(122345676892),
            17281198411619148719
        );
    }
}
