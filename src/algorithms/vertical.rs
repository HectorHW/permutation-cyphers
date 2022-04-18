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

impl<T> BlockEncrypt<T> for VerticalPermutation {
    fn encrypt_block(&self, data: Vec<T>) -> Vec<T> {
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

    fn decrypt_block(&self, data: Vec<T>) -> Vec<T> {
        assert_eq!(data.len(), self.get_block_size());

        let mut data = data.into_iter();

        let mut vectors: Vec<Vec<T>> = vec![];
        for _ in 0..self.columns {
            vectors.push(Vec::with_capacity(self.rows));
            for _ in 0..self.rows {
                vectors.last_mut().unwrap().push(data.next().unwrap());
            }
        }

        let blocks = self.permutation.decrypt_block(vectors);

        let mut columns = blocks
            .into_iter()
            .map(|column| column.into_iter())
            .collect::<Vec<_>>();
        (0..self.rows)
            .into_iter()
            .flat_map(|_| {
                columns
                    .iter_mut()
                    .map(|column| column.next().unwrap())
                    .collect::<Vec<T>>()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        algorithms::{permutation::SimplePermutation, vertical::VerticalPermutation},
        cyphers::BlockEncrypt,
    };

    #[test]
    fn vertical_permutation() {
        let permutation = SimplePermutation::try_from(vec![1, 3, 0, 2]).unwrap();

        let original_data = "abcdefgh".chars().collect::<Vec<_>>();

        let vertical = VerticalPermutation::new(2, 4, permutation);

        let encrypted = vertical.encrypt_block(original_data.clone());

        assert_eq!(encrypted, "cgaedhbf".chars().collect::<Vec<_>>());

        let decrypted = vertical.decrypt_block(encrypted);
        assert_eq!(decrypted, original_data);
    }
}
