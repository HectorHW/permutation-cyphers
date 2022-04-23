use crate::algorithms::cyphers::{BlockEncrypt, Blocky, IndexEncrypt};

use super::permutation::SimplePermutation;

#[derive(Clone, Debug)]
pub struct VerticalPermutation {
    pub(super) rows: usize,
    pub(super) columns: usize,
    pub(super) permutation: SimplePermutation,
}

impl VerticalPermutation {
    pub fn new(rows: usize, columns: usize, permutation: SimplePermutation) -> Self {
        assert_ne!(rows, 0);
        assert_ne!(columns, 0);
        assert_eq!(permutation.get_block_size(), columns);

        Self {
            rows,
            columns,
            permutation,
        }
    }

    pub fn run<T: Clone>(&self, data: Vec<T>) -> Vec<T> {
        assert_eq!(data.len(), self.get_block_size());

        let mut vectors: Vec<Vec<T>> = std::iter::repeat_with(|| Vec::with_capacity(self.rows))
            .take(self.columns)
            .collect();

        for (i, item) in data.into_iter().enumerate() {
            let column_index = i % self.columns;
            vectors[column_index].push(item);
        }

        let blocks = self.permutation.encrypt_block(vectors);
        blocks.into_iter().flatten().collect()
    }
}

impl Blocky for VerticalPermutation {
    fn get_block_size(&self) -> usize {
        self.columns * self.rows
    }
}

impl IndexEncrypt for VerticalPermutation {
    fn encrypt_indices(&self) -> Vec<usize> {
        self.run((0..self.get_block_size()).collect())
    }
}

impl BlockEncrypt for VerticalPermutation {}

#[cfg(test)]
mod tests {
    use crate::{
        algorithms::cyphers::{PadDecrypt, PadEncrypt},
        algorithms::{
            decode::PermutationBlockDecoder, permutation::SimplePermutation,
            vertical::VerticalPermutation,
        },
    };

    #[test]
    fn vertical_permutation() {
        let permutation = SimplePermutation::try_from(vec![1, 3, 0, 2]).unwrap();

        let original_data = "abcdefgh".chars().collect::<Vec<_>>();

        let vertical = VerticalPermutation::new(2, 4, permutation);

        let cypher = PermutationBlockDecoder::new(vertical);

        let (size, encrypted) = cypher.encrypt_with_pad(&original_data);

        assert_eq!(encrypted, "cgaedhbf".chars().collect::<Vec<_>>());

        let decrypted = cypher.decrypt_with_pad(&encrypted, size);
        assert_eq!(decrypted, original_data);
    }
}
