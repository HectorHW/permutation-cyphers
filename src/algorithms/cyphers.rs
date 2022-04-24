use std::error::Error;
use std::fmt::Debug;

use crate::{algorithms::move_by_indices, datastructs::ProvidesPad};

pub trait Blocky {
    fn get_block_size(&self) -> usize;
}

pub trait IndexEncrypt: Blocky {
    fn encrypt_indices(&self) -> Vec<usize>;
}

pub trait BlockEncrypt: IndexEncrypt {
    fn encrypt_block<T>(&self, data: Vec<T>) -> Vec<T> {
        let indices = self.encrypt_indices();
        move_by_indices(data, &indices)
    }
}

pub trait IndexDecrypt: Blocky {
    fn decrypt_indices(&self) -> Vec<usize>;
}

pub trait BlockDecrypt: IndexDecrypt {
    fn decrypt_block<T>(&self, data: Vec<T>) -> Vec<T> {
        let indices = self.decrypt_indices();
        move_by_indices(data, &indices)
    }
}

pub trait PadEncrypt: BlockEncrypt {
    fn encrypt_with_pad<T: ProvidesPad + Clone>(&self, data: &[T]) -> (usize, Vec<T>);
}

pub trait PadDecrypt: BlockDecrypt {
    fn decrypt_with_pad<T: Clone>(
        &self,
        data: &[T],
        original_size: usize,
    ) -> Result<Vec<T>, Box<dyn Error>>;
}

pub trait UnpadEncrypt: BlockEncrypt {
    fn encrypt_unpad<T: Clone>(&self, data: &[T]) -> Vec<T>;
}

pub trait UnpadDecrypt: BlockEncrypt + BlockDecrypt {
    fn decrypt_unpad<T: ProvidesPad + Clone>(&self, data: &[T]) -> Vec<T>;
}

impl<C> PadEncrypt for C
where
    C: BlockEncrypt,
{
    fn encrypt_with_pad<T: ProvidesPad + Clone>(&self, data: &[T]) -> (usize, Vec<T>) {
        let original_length = data.len();
        (
            original_length,
            data.chunks(self.get_block_size())
                .map(|chunk| chunk.to_vec())
                .map(|mut chunk| {
                    if chunk.len() == self.get_block_size() {
                        chunk
                    } else {
                        let elements_to_add = self.get_block_size() - chunk.len();
                        let mut pad = chunk[0].get_pad(elements_to_add);
                        chunk.append(&mut pad);
                        chunk
                    }
                })
                .flat_map(|chunk| self.encrypt_block(chunk))
                .collect::<Vec<T>>(),
        )
    }
}

impl<C: BlockDecrypt + Debug> PadDecrypt for C {
    fn decrypt_with_pad<T: Clone>(
        &self,
        data: &[T],
        original_size: usize,
    ) -> Result<Vec<T>, Box<dyn Error>> {
        if data.len() % self.get_block_size() != 0 {
            return Err(format!(
                "failure while decrypting: got {} items, expected multiples of {} in {:?}",
                data.len(),
                self.get_block_size(),
                self
            )
            .into());
        }
        assert_eq!(data.len() % self.get_block_size(), 0);
        let mut decrypted = data
            .chunks(self.get_block_size())
            .map(|chunk| chunk.to_vec())
            .flat_map(|chunk| self.decrypt_block(chunk))
            .collect::<Vec<_>>();
        decrypted.truncate(original_size);
        Ok(decrypted)
    }
}

impl<C> UnpadEncrypt for C
where
    C: PadEncrypt,
{
    fn encrypt_unpad<T: Clone>(&self, data: &[T]) -> Vec<T> {
        self.encrypt_with_pad(&data.iter().cloned().map(|i| Some(i)).collect::<Vec<_>>())
            .1
            .into_iter()
            .flatten()
            .collect()
    }
}

impl<C: PadEncrypt + PadDecrypt> UnpadDecrypt for C {
    fn decrypt_unpad<T: Clone + ProvidesPad>(&self, data: &[T]) -> Vec<T> {
        let original_size = data.len();

        let pad =
            (self.get_block_size() - original_size % self.get_block_size()) % self.get_block_size();

        let indices = (0..(original_size + pad)).collect::<Vec<_>>();

        let indices = self.encrypt_with_pad(&indices).1;

        let mut data = data.iter().cloned();

        let padded = indices
            .into_iter()
            .map(|idx| {
                if idx >= original_size {
                    None
                } else {
                    data.next()
                }
            })
            .collect::<Vec<_>>();

        //unwrap here because padded data is guranteed to have appropriate block size
        self.decrypt_with_pad(&padded, padded.len())
            .unwrap()
            .into_iter()
            .flatten()
            .collect()
    }
}

pub trait PadCypher: PadEncrypt + PadDecrypt {}

impl<C> PadCypher for C where C: PadEncrypt + PadDecrypt {}

pub trait UnpadCypher: UnpadEncrypt + UnpadDecrypt {}

impl<C> UnpadCypher for C where C: UnpadEncrypt + UnpadDecrypt {}

#[cfg(test)]
mod tests {

    use rand::seq::SliceRandom;
    use rand::thread_rng;

    use crate::algorithms::permutation::SimplePermutation;
    use crate::algorithms::rail_fence::RailFenceCypher;
    use crate::algorithms::stacked::StackedCypher;
    use crate::algorithms::vertical::VerticalPermutation;

    use crate::algorithms::stacked::{EncryptionStyle::*, PadApproach::*};

    fn get_cypher() -> StackedCypher {
        let mut cypher = StackedCypher::new();
        let size = 3usize + rand::random::<usize>() % 10usize;
        let mut permutation_idx = (0..size).collect::<Vec<_>>();
        permutation_idx.shuffle(&mut thread_rng());

        cypher.push(
            Padding,
            Byte,
            SimplePermutation::try_from(permutation_idx.clone()).unwrap(),
        );

        cypher.push(
            Unpadding,
            Byte,
            SimplePermutation::try_from(permutation_idx.clone()).unwrap(),
        );

        cypher.push(Padding, Byte, RailFenceCypher::try_new(3, 8).unwrap());
        cypher.push(
            Padding,
            Byte,
            VerticalPermutation::try_new(2, 4, SimplePermutation::trivial(4)).unwrap(),
        );

        cypher
    }

    #[test]
    fn randomly_test() {
        let expected: Vec<u8> = (0..15).collect();

        for _ in 0..1000 {
            let encoder = get_cypher();

            let data = encoder.encrypt(&expected).unwrap();

            assert_eq!(
                encoder.decrypt(data).unwrap(),
                expected,
                "testing {:?}",
                encoder
            );
        }
    }
}
