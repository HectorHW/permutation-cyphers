use crate::cyphers::{BlockDecrypt, BlockEncrypt, Blocky, IndexDecrypt, IndexEncrypt};

use super::permutation::SimplePermutation;

#[derive(Clone, Debug)]
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
        let backward = encoder.encrypt_indices();
        PermutationBlockDecoder {
            forward: encoder,
            backward: SimplePermutation::try_from(SimplePermutation::inverse(&backward)).unwrap(),
        }
    }

    pub fn get_inner(&self) -> &E {
        &self.forward
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

impl<E> IndexEncrypt for PermutationBlockDecoder<E>
where
    E: BlockEncrypt,
{
    fn encrypt_indices(&self) -> Vec<usize> {
        self.forward.encrypt_indices()
    }
}

impl<E> BlockEncrypt for PermutationBlockDecoder<E> where E: BlockEncrypt {}

impl<E> IndexDecrypt for PermutationBlockDecoder<E>
where
    E: BlockEncrypt,
{
    fn decrypt_indices(&self) -> Vec<usize> {
        self.backward.encrypt_indices()
    }
}

impl<E> BlockDecrypt for PermutationBlockDecoder<E> where E: BlockEncrypt {}
