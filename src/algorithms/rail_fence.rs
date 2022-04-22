use crate::cyphers::{BlockEncrypt, Blocky, IndexEncrypt};

pub struct RailFenceCypher {
    rows: usize,
    columns: usize,
}

impl RailFenceCypher {
    pub fn new(rows: usize, columns: usize) -> Self {
        assert_ne!(rows, 0);
        assert_ne!(columns, 0);
        assert!(rows < columns);

        Self { rows, columns }
    }

    fn run<T: Clone>(&self, data: Vec<T>) -> Vec<T> {
        assert_eq!(data.len(), self.get_block_size());
        let mut matrix: Vec<Option<T>> = std::iter::repeat_with(|| None)
            .take(self.columns * self.rows)
            .collect();

        let mut direction = Direction::Down;

        let mut i = 0;

        for (j, item) in data.into_iter().enumerate() {
            matrix[i * self.columns + j] = Some(item);
            i = match direction {
                Direction::Up => i - 1,
                Direction::Down => i + 1,
            };
            if i == 0 || i == self.rows - 1 {
                direction = direction.reverse();
            }
        }

        matrix.into_iter().flatten().collect()
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
    fn encrypt_indices(&self, data: Vec<usize>) -> Vec<usize> {
        self.run(data)
    }
}

impl<T: Clone> BlockEncrypt<T> for RailFenceCypher {
    fn encrypt_block(&self, data: Vec<T>) -> Vec<T> {
        self.run(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::cyphers::BlockEncrypt;

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
}
