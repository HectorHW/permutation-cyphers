use crate::{algorithms::permutation::SimplePermutation, datastructs::ProvidesPad};

pub trait Blocky {
    fn get_block_size(&self) -> usize;
}

pub trait IndexEncrypt: Blocky {
    fn encrypt_indices(&self, data: Vec<usize>) -> Vec<usize>;
}

pub trait BlockEncrypt<T: Clone>: IndexEncrypt {
    fn encrypt_block(&self, data: Vec<T>) -> Vec<T> {
        let indices = self.encrypt_indices((0..data.len()).collect());
        SimplePermutation::run(data, &indices)
    }
}

pub trait IndexDecrypt: Blocky {
    fn decrypt_indices(&self, data: Vec<usize>) -> Vec<usize>;
}

pub trait BlockDecrypt<T: Clone>: IndexDecrypt {
    fn decrypt_block(&self, data: Vec<T>) -> Vec<T> {
        let indices = self.decrypt_indices((0..data.len()).collect());
        SimplePermutation::run(data, &indices)
    }
}

pub trait PadEncrypt<T: ProvidesPad + Clone>: BlockEncrypt<T> {
    fn encrypt_with_pad(&self, data: &[T]) -> (usize, Vec<T>);
}

pub trait PadDecrypt<T: Clone>: BlockDecrypt<T> {
    fn decrypt_with_pad(&self, data: &[T], original_size: usize) -> Vec<T>;
}

pub trait UnpadEncrypt<T: Clone + ProvidesPad>: BlockEncrypt<T> {
    fn encrypt_unpad(&self, data: &[T]) -> Vec<T>;
}

pub trait UnpadDecrypt<T: Clone>: BlockEncrypt<T> + BlockDecrypt<T> {
    fn decrypt_unpad(&self, data: &[T]) -> Vec<T>;
}

impl<T, C> PadEncrypt<T> for C
where
    C: BlockEncrypt<T>,
    T: ProvidesPad + Clone,
{
    fn encrypt_with_pad(&self, data: &[T]) -> (usize, Vec<T>) {
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
                        chunk.append(&mut T::get_pad(elements_to_add));
                        chunk
                    }
                })
                .flat_map(|chunk| self.encrypt_block(chunk))
                .collect::<Vec<T>>(),
        )
    }
}

impl<T, C> PadDecrypt<T> for C
where
    C: BlockDecrypt<T>,
    T: Clone,
{
    fn decrypt_with_pad(&self, data: &[T], original_size: usize) -> Vec<T> {
        assert_eq!(data.len() % self.get_block_size(), 0);
        let mut decrypted = data
            .chunks(self.get_block_size())
            .map(|chunk| chunk.to_vec())
            .flat_map(|chunk| self.decrypt_block(chunk))
            .collect::<Vec<_>>();
        decrypted.truncate(original_size);
        decrypted
    }
}

impl<T: Clone + ProvidesPad, C> UnpadEncrypt<T> for C
where
    C: PadEncrypt<T>,
{
    fn encrypt_unpad(&self, data: &[T]) -> Vec<T> {
        data.chunks(self.get_block_size())
            .map(|chunk| chunk.to_vec())
            .flat_map(|chunk| {
                if chunk.len() == self.get_block_size() {
                    self.encrypt_block(chunk)
                } else {
                    let indices = (0..self.get_block_size()).collect::<Vec<_>>();
                    let indices = self.encrypt_indices(indices);

                    let (size, data) = self.encrypt_with_pad(&chunk);

                    data.into_iter()
                        .zip(indices.into_iter())
                        .filter_map(|(data, idx)| if idx >= size { None } else { Some(data) })
                        .collect()
                }
            })
            .collect::<Vec<T>>()
    }
}

impl<T: Clone + ProvidesPad, C: PadEncrypt<T> + PadDecrypt<T>> UnpadDecrypt<T> for C {
    fn decrypt_unpad(&self, data: &[T]) -> Vec<T> {
        data.chunks(self.get_block_size())
            .map(|chunk| chunk.to_vec())
            .flat_map(|chunk| {
                if chunk.len() == self.get_block_size() {
                    self.decrypt_block(chunk)
                } else {
                    let original_len = chunk.len();
                    let indices = (0..self.get_block_size()).collect::<Vec<_>>();
                    let indices = self.encrypt_indices(indices);

                    let mut original_items = chunk.into_iter();
                    let chunk = indices
                        .into_iter()
                        .map(|idx| {
                            if idx >= original_len {
                                T::get_pad_value()
                            } else {
                                original_items.next().unwrap()
                            }
                        })
                        .collect();
                    let mut decrypted = self.decrypt_block(chunk);
                    decrypted.truncate(original_len);
                    decrypted
                }
            })
            .collect()
    }
}

pub trait PadCypher<T: Clone + ProvidesPad>: PadEncrypt<T> + PadDecrypt<T> {}

impl<T, C> PadCypher<T> for C
where
    T: Clone + ProvidesPad,
    C: PadEncrypt<T> + PadDecrypt<T>,
{
}

pub trait UnpadCypher<T: Clone + ProvidesPad>: UnpadEncrypt<T> + UnpadDecrypt<T> {}

impl<T, C> UnpadCypher<T> for C
where
    T: Clone + ProvidesPad,
    C: UnpadEncrypt<T> + UnpadDecrypt<T>,
{
}
