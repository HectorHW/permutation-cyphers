use crate::cyphers::{BlockEncrypt, Blocky};

use super::permutation::SimplePermutation;

#[derive(Clone, Debug)]
pub struct VerticalPermutation {
    rows: usize,
    columns: usize,
    permutation: SimplePermutation,
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
}

impl Blocky for VerticalPermutation {
    fn get_block_size(&self) -> usize {
        self.columns * self.rows
    }
}

impl BlockEncrypt for VerticalPermutation {
    fn encrypt_block<T>(&self, data: Vec<T>) -> Vec<T> {
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

#[cfg(test)]
mod tests {
    use crate::{
        algorithms::{
            decode::PermutationBlockDecoder, permutation::SimplePermutation,
            vertical::VerticalPermutation,
        },
        cyphers::{BlockDecrypt, BlockEncrypt},
    };

    #[test]
    fn vertical_permutation() {
        let permutation = SimplePermutation::try_from(vec![1, 3, 0, 2]).unwrap();

        let original_data = "abcdefgh".chars().collect::<Vec<_>>();

        let vertical = VerticalPermutation::new(2, 4, permutation);

        let cypher = PermutationBlockDecoder::new(vertical);

        let encrypted = cypher.encrypt_block(original_data.clone());

        assert_eq!(encrypted, "cgaedhbf".chars().collect::<Vec<_>>());

        let decrypted = cypher.decrypt_block(encrypted);
        assert_eq!(decrypted, original_data);
    }
}
