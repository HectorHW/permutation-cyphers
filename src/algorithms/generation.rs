use rand::distributions::Distribution;
use rand::distributions::Standard;
use rand::prelude::SliceRandom;

use super::permutation::SimplePermutation;
use super::rail_fence::RailFenceCypher;
use super::vertical::VerticalPermutation;

impl Distribution<RailFenceCypher> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> RailFenceCypher {
        let columns = rng.gen_range(4..=16);
        let rows = rng.gen_range(2..=(columns - 2));
        RailFenceCypher::try_new(rows, columns).unwrap()
    }
}

impl Distribution<SimplePermutation> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> SimplePermutation {
        let size = rng.gen_range(2..=20);
        let mut indices = (0usize..size).collect::<Vec<_>>();
        indices.shuffle(rng);
        SimplePermutation::try_from(indices).unwrap()
    }
}

impl Distribution<VerticalPermutation> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> VerticalPermutation {
        let columns = rng.gen_range(4..=16);
        let rows = rng.gen_range(2..=(columns - 2));
        let permutation = {
            let mut indices = (0usize..columns).collect::<Vec<_>>();
            indices.shuffle(rng);
            SimplePermutation::try_from(indices).unwrap()
        };
        VerticalPermutation::try_new(rows, columns, permutation).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::algorithms::{
        permutation::SimplePermutation, rail_fence::RailFenceCypher, vertical::VerticalPermutation,
    };

    #[test]
    fn generate_permutation() {
        for _ in 0..1000 {
            let _permutation: SimplePermutation = thread_rng().gen();
        }
    }

    #[test]
    fn generate_railfence() {
        for _ in 0..1000 {
            let _permutation: RailFenceCypher = thread_rng().gen();
        }
    }

    #[test]
    fn generate_vertical() {
        for _ in 0..1000 {
            let _permutation: VerticalPermutation = thread_rng().gen();
        }
    }
}
