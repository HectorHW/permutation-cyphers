use crate::datastructs::ProvidesPad;

pub trait Blocky {
    fn get_block_size(&self) -> usize;
}
pub trait BlockEncrypt<T>: Blocky {
    fn encrypt_block(&self, data: Vec<T>) -> Vec<T>;

    fn decrypt_block(&self, data: Vec<T>) -> Vec<T>;
}

pub trait PadEncrypt<T>: BlockEncrypt<T>
where
    T: ProvidesPad + Clone,
{
    fn encrypt_with_pad(&self, data: &[T]) -> (usize, Vec<T>);

    fn decrypt_with_pad(&self, data: &[T], original_size: usize) -> Vec<T>;
}

impl<T, C> PadEncrypt<T> for C
where
    T: ProvidesPad + Clone,
    C: BlockEncrypt<T>,
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
