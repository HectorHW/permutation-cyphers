use crate::cyphers::{BlockDecrypt, BlockEncrypt, Blocky};

use super::permutation::SimplePermutation;

pub struct PermutationBlockDecoder<E>
where
    E: BlockEncrypt,
{
    forward: E,
    backward: SimplePermutation,
}

impl<E> PermutationBlockDecoder<E>
where
    E: BlockEncrypt,
{
    pub fn new(encoder: E) -> Self {
        let backward = encoder.encrypt_block((0..encoder.get_block_size()).collect());
        PermutationBlockDecoder {
            forward: encoder,
            backward: SimplePermutation::try_from(backward).unwrap(),
        }
    }
}

impl<E> Blocky for PermutationBlockDecoder<E>
where
    E: BlockEncrypt,
{
    fn get_block_size(&self) -> usize {
        self.forward.get_block_size()
    }
}

impl<E> BlockEncrypt for PermutationBlockDecoder<E>
where
    E: BlockEncrypt,
{
    fn encrypt_block<T>(&self, data: Vec<T>) -> Vec<T> {
        self.forward.encrypt_block(data)
    }
}

impl<E> BlockDecrypt for PermutationBlockDecoder<E>
where
    E: BlockEncrypt,
{
    fn decrypt_block<T>(&self, data: Vec<T>) -> Vec<T> {
        self.backward.encrypt_block(data)
    }
}
