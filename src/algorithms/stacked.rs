use crate::{
    algorithms::cyphers::{PadDecrypt, PadEncrypt, UnpadDecrypt, UnpadEncrypt},
    datastructs::ProvidesPad,
};

use std::{error::Error, fmt::Debug};

use super::{
    decode::PermutationBlockDecoder, permutation::SimplePermutation, rail_fence::RailFenceCypher,
    vertical::VerticalPermutation,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Permutation(PermutationBlockDecoder<SimplePermutation>),
    RailFence(PermutationBlockDecoder<RailFenceCypher>),
    Vertical(PermutationBlockDecoder<VerticalPermutation>),
}

impl From<SimplePermutation> for Algorithm {
    fn from(p: SimplePermutation) -> Self {
        Algorithm::Permutation(PermutationBlockDecoder::new(p))
    }
}

impl From<RailFenceCypher> for Algorithm {
    fn from(p: RailFenceCypher) -> Self {
        Algorithm::RailFence(PermutationBlockDecoder::new(p))
    }
}

impl From<VerticalPermutation> for Algorithm {
    fn from(p: VerticalPermutation) -> Self {
        Algorithm::Vertical(PermutationBlockDecoder::new(p))
    }
}

impl Algorithm {
    pub fn epad<T: Clone + ProvidesPad>(&self, data: &[T]) -> (usize, Vec<T>) {
        match self {
            Algorithm::Permutation(p) => p.encrypt_with_pad(data),
            Algorithm::RailFence(p) => p.encrypt_with_pad(data),
            Algorithm::Vertical(p) => p.encrypt_with_pad(data),
        }
    }
    pub fn dpad<T: Clone + ProvidesPad>(
        &self,
        data: &[T],
        original_size: usize,
    ) -> Result<Vec<T>, Box<dyn Error>> {
        match self {
            Algorithm::Permutation(p) => p.decrypt_with_pad(data, original_size),
            Algorithm::RailFence(p) => p.decrypt_with_pad(data, original_size),
            Algorithm::Vertical(p) => p.decrypt_with_pad(data, original_size),
        }
    }

    pub fn eunpad<T: Clone + ProvidesPad>(&self, data: &[T]) -> Vec<T> {
        match self {
            Algorithm::Permutation(p) => p.encrypt_unpad(data),
            Algorithm::RailFence(p) => p.encrypt_unpad(data),
            Algorithm::Vertical(p) => p.encrypt_unpad(data),
        }
    }
    pub fn dunpad<T: Clone + ProvidesPad>(&self, data: &[T]) -> Vec<T> {
        match self {
            Algorithm::Permutation(p) => p.decrypt_unpad(data),
            Algorithm::RailFence(p) => p.decrypt_unpad(data),
            Algorithm::Vertical(p) => p.decrypt_unpad(data),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PadApproach {
    Padding(Algorithm),
    Unpadding(Algorithm),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackedCypher {
    algorithms: Vec<PadApproach>,
}

impl StackedCypher {
    pub fn new() -> Self {
        StackedCypher { algorithms: vec![] }
    }

    pub fn push_padding<C>(&mut self, cypher: C)
    where
        Algorithm: From<C>,
    {
        self.algorithms.push(PadApproach::Padding(cypher.into()));
    }

    pub fn push_unpadding<C>(&mut self, cypher: C)
    where
        Algorithm: From<C>,
    {
        self.algorithms.push(PadApproach::Unpadding(cypher.into()));
    }

    pub fn encrypt<T: Clone + ProvidesPad>(&self, data: &[T]) -> (Vec<usize>, Vec<T>) {
        self.algorithms
            .iter()
            .fold((vec![], data.to_vec()), |(mut indices, data), op| {
                let (created_indices, data) = match op {
                    PadApproach::Padding(op) => op.epad(&data),
                    PadApproach::Unpadding(op) => (data.len(), op.eunpad(&data)),
                };

                indices.push(created_indices);
                (indices, data)
            })
    }

    pub fn decrypt<T: Clone + ProvidesPad>(
        &self,
        data: &[T],
        sizes: &[usize],
    ) -> Result<Vec<T>, Box<dyn Error>> {
        self.algorithms.iter().zip(sizes.iter()).rev().try_fold(
            data.to_vec(),
            |data, (op, &size)| match op {
                PadApproach::Padding(op) => op.dpad(&data, size),
                PadApproach::Unpadding(op) => Ok(op.dunpad(&data)),
            },
        )
    }

    pub(crate) fn len(&self) -> usize {
        self.algorithms.len()
    }

    pub(crate) fn items(&self) -> impl Iterator<Item = &PadApproach> {
        self.algorithms.iter()
    }
}
