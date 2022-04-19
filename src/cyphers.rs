use crate::datastructs::ProvidesPad;

pub trait Blocky {
    fn get_block_size(&self) -> usize;
}
pub trait BlockEncrypt: Blocky {
    fn encrypt_block<T>(&self, data: Vec<T>) -> Vec<T>;
}

pub trait BlockDecrypt: Blocky {
    fn decrypt_block<T>(&self, data: Vec<T>) -> Vec<T>;
}

pub trait PadEncrypt: BlockEncrypt {
    fn encrypt_with_pad<T>(&self, data: &[T]) -> (usize, Vec<T>)
    where
        T: ProvidesPad + Clone;
}

pub trait PadDecrypt: BlockDecrypt {
    fn decrypt_with_pad<T>(&self, data: &[T], original_size: usize) -> Vec<T>
    where
        T: Clone;
}

impl<C> PadEncrypt for C
where
    C: BlockEncrypt,
{
    fn encrypt_with_pad<T>(&self, data: &[T]) -> (usize, Vec<T>)
    where
        T: ProvidesPad + Clone,
    {
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

impl<C> PadDecrypt for C
where
    C: BlockDecrypt,
{
    fn decrypt_with_pad<T>(&self, data: &[T], original_size: usize) -> Vec<T>
    where
        T: Clone,
    {
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
