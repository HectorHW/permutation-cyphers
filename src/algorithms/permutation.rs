use std::collections::HashSet;

use crate::algorithms::cyphers::{BlockEncrypt, Blocky, IndexEncrypt};

#[derive(Clone, Debug)]
pub struct SimplePermutation {
    pub(super) indices: Vec<usize>,
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
    fn encrypt_indices(&self) -> Vec<usize> {
        self.indices.clone()
    }
}

impl BlockEncrypt for SimplePermutation {}

#[cfg(test)]
mod test {
    use std::vec;

    use crate::{
        algorithms::cyphers::{BlockDecrypt, BlockEncrypt, IndexEncrypt},
        algorithms::{decode::PermutationBlockDecoder, permutation::SimplePermutation},
    };

    #[test]
    fn permutation() {
        let permutation = SimplePermutation::try_from(vec![1, 3, 0, 2]).unwrap();

        let cypher = PermutationBlockDecoder::new(permutation);

        assert_eq!(cypher.encrypt_indices(), vec![1, 3, 0, 2]);

        let original_data = "abcd".chars().collect::<Vec<_>>();

        let encrypted = cypher.encrypt_block(original_data.clone());

        assert_eq!(encrypted, "cadb".chars().collect::<Vec<_>>());

        let decrypted = cypher.decrypt_block(encrypted);
        assert_eq!(decrypted, original_data);
    }
}
