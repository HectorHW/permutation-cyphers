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

pub trait UnpadEncrypt: BlockEncrypt {
    fn encrypt_unpad<T: Clone>(&self, data: &[T]) -> Vec<T>;
}

pub trait UnpadDecrypt: BlockEncrypt + BlockDecrypt {
    fn decrypt_unpad<T: Clone>(&self, data: &[T]) -> Vec<T>;
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

impl<C: PadEncrypt> UnpadEncrypt for C {
    fn encrypt_unpad<T: Clone>(&self, data: &[T]) -> Vec<T> {
        let data = data.to_vec();
        let data = data.into_iter().map(|data| Some(data)).collect::<Vec<_>>();

        self.encrypt_with_pad(&data)
            .1
            .into_iter()
            .flatten()
            .collect()
    }
}

impl<C: PadEncrypt + PadDecrypt> UnpadDecrypt for C {
    fn decrypt_unpad<T: Clone>(&self, data: &[T]) -> Vec<T> {
        let data = data.to_vec();
        let original_length = data.len();
        let original_placing = std::iter::repeat(true).take(data.len()).collect::<Vec<_>>();
        let original_placing = self.encrypt_with_pad(&original_placing).1;
        let mut data = data.into_iter();

        let data = original_placing
            .into_iter()
            .map(|placement| if placement { data.next() } else { None })
            .collect::<Vec<_>>();
        self.decrypt_with_pad(data.as_slice(), original_length)
            .into_iter()
            .flatten()
            .collect()
    }
}
