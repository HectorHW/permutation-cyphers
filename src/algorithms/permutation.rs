use std::{collections::HashSet, mem::MaybeUninit};

use crate::cyphers::{BlockEncrypt, Blocky, IndexEncrypt};

#[derive(Clone, Debug)]
pub struct SimplePermutation {
    indices: Vec<usize>,
}

impl SimplePermutation {
    pub fn try_from(indices: Vec<usize>) -> Option<Self> {
        let expected = (0..indices.len()).collect::<HashSet<_>>();
        let provided = indices.clone().into_iter().collect::<HashSet<_>>();
        if expected != provided {
            None
        } else {
            Some(SimplePermutation { indices })
        }
    }

    pub(crate) fn inverse(indices: &[usize]) -> Vec<usize> {
        let mut inverse = vec![0; indices.len()];
        for (i, &forward_index) in indices.iter().enumerate() {
            inverse[forward_index] = i;
        }
        inverse
    }

    pub(crate) fn run<T>(data: Vec<T>, indices: &[usize]) -> Vec<T> {
        assert_eq!(indices.len(), data.len());
        let mut items: Vec<MaybeUninit<T>> = std::iter::repeat_with(|| MaybeUninit::uninit())
            .take(data.len())
            .collect();

        for (&target_idx, data) in indices.iter().zip(data.into_iter()) {
            items[target_idx].write(data);
        }

        items
            .into_iter()
            //this is safe because all indices are present in permutation
            // => all indices are written exactly once
            .map(|item| unsafe { item.assume_init() })
            .collect()
    }

    pub fn trivial(size: usize) -> Self {
        Self::try_from((0..size).collect()).unwrap()
    }
}

impl Blocky for SimplePermutation {
    fn get_block_size(&self) -> usize {
        self.indices.len()
    }
}

impl IndexEncrypt for SimplePermutation {
    fn encrypt_indices(&self, data: Vec<usize>) -> Vec<usize> {
        Self::run(data, &self.indices)
    }
}

impl<T: Clone> BlockEncrypt<T> for SimplePermutation {
    fn encrypt_block(&self, data: Vec<T>) -> Vec<T> {
        Self::run(data, &self.indices)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        algorithms::{decode::PermutationBlockDecoder, permutation::SimplePermutation},
        cyphers::{BlockDecrypt, BlockEncrypt},
    };

    #[test]
    fn permutation() {
        let permutation = SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap();

        let cypher = PermutationBlockDecoder::new(permutation);

        let original_data = (1..=4).collect::<Vec<_>>();

        let encrypted = cypher.encrypt_block(original_data.clone());

        assert_eq!(encrypted, vec![3, 4, 2, 1]);

        let decrypted = cypher.decrypt_block(encrypted);
        assert_eq!(decrypted, original_data);
    }
}
