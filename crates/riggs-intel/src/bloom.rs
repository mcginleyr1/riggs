use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
    count: usize,
}

impl BloomFilter {
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let n = expected_items.max(1) as f64;
        let p = false_positive_rate.clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);

        let ln2 = std::f64::consts::LN_2;
        let m = (-(n * p.ln()) / (ln2 * ln2)).ceil() as usize;
        let m = m.max(64);
        let k = ((m as f64 / n) * ln2).ceil() as u32;
        let k = k.max(1);

        let words = m.div_ceil(64);

        Self {
            bits: vec![0u64; words],
            num_bits: m,
            num_hashes: k,
            count: 0,
        }
    }

    pub fn insert(&mut self, item: &[u8]) {
        let (h1, h2) = self.double_hash(item);
        for i in 0..self.num_hashes {
            let idx = self.bit_index(h1, h2, i);
            let word = idx / 64;
            let bit = idx % 64;
            self.bits[word] |= 1u64 << bit;
        }
        self.count += 1;
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        let (h1, h2) = self.double_hash(item);
        for i in 0..self.num_hashes {
            let idx = self.bit_index(h1, h2, i);
            let word = idx / 64;
            let bit = idx % 64;
            if self.bits[word] & (1u64 << bit) == 0 {
                return false;
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn clear(&mut self) {
        self.bits.fill(0);
        self.count = 0;
    }

    fn double_hash(&self, item: &[u8]) -> (u64, u64) {
        let mut h1 = DefaultHasher::new();
        item.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        // Seed the second hash differently by hashing the item with a prefix
        0xDEAD_BEEF_u64.hash(&mut h2);
        item.hash(&mut h2);
        let hash2 = h2.finish();

        (hash1, hash2)
    }

    fn bit_index(&self, h1: u64, h2: u64, i: u32) -> usize {
        let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (combined % self.num_bits as u64) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserted_items_are_found() {
        let mut bf = BloomFilter::new(1000, 0.01);
        bf.insert(b"hello");
        bf.insert(b"world");
        assert!(bf.contains(b"hello"));
        assert!(bf.contains(b"world"));
        assert_eq!(bf.len(), 2);
    }

    #[test]
    fn missing_items_usually_not_found() {
        let mut bf = BloomFilter::new(1000, 0.01);
        for i in 0..100u32 {
            bf.insert(&i.to_le_bytes());
        }
        let mut false_positives = 0;
        for i in 1000..2000u32 {
            if bf.contains(&i.to_le_bytes()) {
                false_positives += 1;
            }
        }
        assert!(false_positives < 50, "too many false positives: {false_positives}");
    }

    #[test]
    fn clear_resets_filter() {
        let mut bf = BloomFilter::new(100, 0.01);
        bf.insert(b"test");
        assert_eq!(bf.len(), 1);
        bf.clear();
        assert_eq!(bf.len(), 0);
        assert!(!bf.contains(b"test"));
    }
}
