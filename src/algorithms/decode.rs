use std::marker::PhantomData;

use crate::cyphers::{BlockDecrypt, BlockEncrypt, Blocky, IndexDecrypt, IndexEncrypt};

use super::permutation::SimplePermutation;

pub struct PermutationBlockDecoder<T, E>
where
    E: BlockEncrypt<T>,
    T: Clone,
{
    forward: E,
    backward: SimplePermutation,
    _marker: PhantomData<T>,
}

impl<T, E> PermutationBlockDecoder<T, E>
where
    T: Clone,
    E: BlockEncrypt<T>,
{
    pub fn new(encoder: E) -> Self {
        let backward = encoder.encrypt_indices((0..encoder.get_block_size()).collect());
        PermutationBlockDecoder {
            forward: encoder,
            backward: SimplePermutation::try_from(backward).unwrap(),
            _marker: PhantomData,
        }
    }

    pub fn get_inner(&self) -> &E {
        &self.forward
    }
}

impl<T, E> Blocky for PermutationBlockDecoder<T, E>
where
    T: Clone,
    E: BlockEncrypt<T>,
{
    fn get_block_size(&self) -> usize {
        self.forward.get_block_size()
    }
}

impl<T, E> IndexEncrypt for PermutationBlockDecoder<T, E>
where
    T: Clone,
    E: BlockEncrypt<T>,
{
    fn encrypt_indices(&self, data: Vec<usize>) -> Vec<usize> {
        self.forward.encrypt_indices(data)
    }
}

impl<T, E> BlockEncrypt<T> for PermutationBlockDecoder<T, E>
where
    T: Clone,
    E: BlockEncrypt<T>,
{
    fn encrypt_block(&self, data: Vec<T>) -> Vec<T> {
        self.forward.encrypt_block(data)
    }
}

impl<T, E> IndexDecrypt for PermutationBlockDecoder<T, E>
where
    T: Clone,
    E: BlockEncrypt<T>,
{
    fn decrypt_indices(&self, data: Vec<usize>) -> Vec<usize> {
        self.backward.encrypt_indices(data)
    }
}

impl<T, E> BlockDecrypt<T> for PermutationBlockDecoder<T, E>
where
    T: Clone,
    E: BlockEncrypt<T>,
{
    fn decrypt_block(&self, data: Vec<T>) -> Vec<T> {
        self.backward.encrypt_block(data)
    }
}
