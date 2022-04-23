use crate::{
    algorithms::permutation,
    cyphers::{BlockEncrypt, Blocky, IndexEncrypt},
};

#[derive(Clone, Debug)]
pub struct RailFenceCypher {
    pub(super) rows: usize,
    pub(super) columns: usize,
}

impl RailFenceCypher {
    pub fn new(rows: usize, columns: usize) -> Self {
        assert_ne!(rows, 0);
        assert_ne!(columns, 0);
        assert!(rows < columns);

        Self { rows, columns }
    }
}

impl Blocky for RailFenceCypher {
    fn get_block_size(&self) -> usize {
        self.columns
    }
}

#[derive(Clone, Copy, Debug)]
enum Direction {
    Up,
    Down,
}

impl Direction {
    fn reverse(&self) -> Self {
        match self {
            Direction::Up => Direction::Down,
            Direction::Down => Direction::Up,
        }
    }
}

impl IndexEncrypt for RailFenceCypher {
    fn encrypt_indices(&self) -> Vec<usize> {
        let mut matrix: Vec<Option<usize>> = std::iter::repeat_with(|| None)
            .take(self.columns * self.rows)
            .collect();

        let mut direction = Direction::Down;

        let mut i = 0;

        for j in 0..self.get_block_size() {
            matrix[i * self.columns + j] = Some(j);
            i = match direction {
                Direction::Up => i - 1,
                Direction::Down => i + 1,
            };
            if i == 0 || i == self.rows - 1 {
                direction = direction.reverse();
            }
        }

        permutation::SimplePermutation::inverse(
            &matrix.into_iter().flatten().collect::<Vec<usize>>(),
        )
    }
}

impl BlockEncrypt for RailFenceCypher {}

#[cfg(test)]
mod tests {
    use crate::cyphers::{BlockEncrypt, IndexEncrypt};

    use super::RailFenceCypher;

    #[test]
    fn encrypt() {
        let cypher = RailFenceCypher::new(3, 8);

        let data = "abcdefgh".chars().collect::<Vec<_>>();
        assert_eq!(
            cypher.encrypt_block(data),
            "aebdfhcg".chars().collect::<Vec<_>>()
        );
    }

    #[test]
    fn indices() {
        let cypher = RailFenceCypher::new(3, 8);
        // 0 1 2 3 4 5 6 7
        // 0 4 1 3 5 7 2 6
        assert_eq!(cypher.encrypt_indices(), vec![0, 2, 6, 3, 1, 4, 7, 5]);
    }
}
