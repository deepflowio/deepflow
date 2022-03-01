use std::hash::{self, Hash, Hasher};

const BLOCK_SIZE_BITS: usize = 8;
const BLOCK_SIZE: usize = 1 << BLOCK_SIZE_BITS;
const BLOCK_SIZE_MASK: usize = BLOCK_SIZE - 1;

struct IdMapNode<const N: usize> {
	key: [u8; N],
	hash: Option<u32>,
	value: u32,

	next: Option<u32>,
	slot: Option<u32>,
}

impl<const N: usize> Hash for IdMapNode<N> {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.key.hash(state);
	}
}

impl<const N: usize> PartialEq for IdMapNode<N> {
	fn eq(&self, other: &Self) -> bool {
		self.key == other.key
	}
}

impl<const N: usize> Eq for IdMapNode<N> {}

type IdMapNodeBlock<const N: usize> = [IdMapNode<N>; BLOCK_SIZE];

pub struct IdMap<const N: usize> {
	id: String,

	// 存储map节点，以矩阵的方式组织，提升内存申请释放效率
	buffer: Vec<IdMapNodeBlock<N>>,

	slot_head: Vec<Option<u32>>,
	size: usize,
	width: usize,

	hash_slot_bits: u32,
}

impl<const N: usize> IdMap<N> {
	pub fn new_no_stats(id: String, hash_slots: u32) -> Self {
		assert!(hash_slots < 1<<30, "hash_slots is too large");
		let hash_slots = hash_slots.next_power_of_two() as usize;
		IdMap {
			id,
			buffer: vec![],
			slot_head: vec![None; hash_slots],
			size: 0,
			width: 0,
			hash_slot_bits: (hash_slots as f32).log2() as u32,
		}
	}

	pub fn id(&self) -> &str {
		&self.id
	}

	pub fn key_size() -> usize {
		N
	}

	pub fn size(&self) -> usize {
		self.size
	}

	pub fn width(&self) -> usize {
		self.width
	}
}

#[cfg(test)]
mod tests {

	/*
	extern crate test;

	use std::collections::HashMap;
	use test::{Bencher, black_box};

	#[bench]
	fn bench_u192_id_map(bencher: &mut Bencher) {
		const n: usize = 1024;
		let mut keys = [[0u8; 24]; n];
		for i in (0..n).step_by(4) {
			keys[i][4..12].copy_from_slice(&(i as u64).to_ne_bytes());
			keys[i][16..].copy_from_slice(&((i as u64) << 1).to_ne_bytes());
			keys[i + 1][4..12].copy_from_slice(&((i as u64) << 1).to_ne_bytes());
			keys[i + 1][16..].copy_from_slice(&(i as u64).to_ne_bytes());
			keys[i + 2][4..12].copy_from_slice(&(!(i as u64)).to_ne_bytes());
			keys[i + 2][16..].copy_from_slice(&(!((i as u64) << 1)).to_ne_bytes());
			keys[i + 3][4..12].copy_from_slice(&(!((i as u64) << 1)).to_ne_bytes());
			keys[i + 3][16..].copy_from_slice(&(!i as u64).to_ne_bytes());
		}
		bencher.iter(|| {
			let mut m = HashMap::new();
			for (i, v) in keys.iter().enumerate() {
				let vv: [u8; 24] = v.clone();
				m.insert(vv, i << 2);
			}
		});
	}
	*/
}