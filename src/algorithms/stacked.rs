use crate::{
    algorithms::cyphers::{PadDecrypt, PadEncrypt, UnpadDecrypt, UnpadEncrypt},
    datastructs::{BitVector, ProvidesPad},
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PadApproach {
    Padding,
    Unpadding,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncryptionStyle {
    Bit,
    Byte,
    Char,
    Group(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackedCypher {
    algorithms: Vec<(PadApproach, EncryptionStyle, Algorithm)>,
}

impl StackedCypher {
    pub fn new() -> Self {
        StackedCypher { algorithms: vec![] }
    }

    pub fn push<C>(&mut self, pad_approach: PadApproach, style: EncryptionStyle, cypher: C)
    where
        Algorithm: From<C>,
    {
        self.algorithms.push((pad_approach, style, cypher.into()))
    }

    fn e_with_padding<T: ProvidesPad + Clone>(
        data: &[T],
        op: &Algorithm,
        pad_approach: PadApproach,
    ) -> (usize, Vec<T>) {
        match pad_approach {
            PadApproach::Padding => op.epad(data),
            PadApproach::Unpadding => (data.len(), op.eunpad(data)),
        }
    }

    fn d_with_padding<T: ProvidesPad + Clone>(
        data: &[T],
        size: usize,
        op: &Algorithm,
        pad_approach: PadApproach,
    ) -> Result<Vec<T>, Box<dyn Error>> {
        match pad_approach {
            PadApproach::Padding => op.dpad(data, size),
            PadApproach::Unpadding => Ok(op.dunpad(data)),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<usize>, Vec<u8>), Box<dyn Error>> {
        self.algorithms.iter().try_fold(
            (vec![], data.to_vec()),
            |(mut indices, data), (pad_approach, style, op)| {
                let (created_indices, data) = match style {
                    EncryptionStyle::Bit => {
                        let bits = crate::datastructs::BitVector::from(data.as_slice()).0;
                        let (size, encrypted) = Self::e_with_padding(&bits, op, *pad_approach);
                        (size, BitVector(encrypted).into())
                    }
                    EncryptionStyle::Byte => Self::e_with_padding(&data, op, *pad_approach),
                    EncryptionStyle::Char => {
                        let chars = String::from_utf8(data)?.chars().collect::<Vec<_>>();
                        let (size, encrypted) = Self::e_with_padding(&chars, op, *pad_approach);
                        (size, encrypted.into_iter().collect::<String>().into_bytes())
                    }
                    &EncryptionStyle::Group(group_size) => {
                        let string = String::from_utf8(data)?;
                        let groups =
                            crate::datastructs::groups_from_str(string.as_str(), group_size)?;

                        let (size, encrypted) = Self::e_with_padding(&groups, op, *pad_approach);
                        (
                            size,
                            crate::datastructs::string_from_groups(&encrypted).into_bytes(),
                        )
                    }
                };

                indices.push(created_indices);
                Ok((indices, data))
            },
        )
    }

    pub fn decrypt(&self, (sizes, data): (Vec<usize>, Vec<u8>)) -> Result<Vec<u8>, Box<dyn Error>> {
        self.algorithms.iter().zip(sizes.iter()).rev().try_fold(
            data.to_vec(),
            |data, ((pad_approach, style, op), &size)| {
                let data: Vec<u8> = match style {
                    EncryptionStyle::Bit => {
                        let bits = crate::datastructs::BitVector::from(data.as_slice()).0;
                        let encrypted = Self::d_with_padding(&bits, size, op, *pad_approach)?;
                        BitVector(encrypted).into()
                    }
                    EncryptionStyle::Byte => Self::d_with_padding(&data, size, op, *pad_approach)?,
                    EncryptionStyle::Char => {
                        let chars = String::from_utf8(data)?.chars().collect::<Vec<_>>();
                        let encrypted = Self::d_with_padding(&chars, size, op, *pad_approach)?;
                        encrypted.into_iter().collect::<String>().into_bytes()
                    }
                    &EncryptionStyle::Group(group_size) => {
                        let string = String::from_utf8(data)?;
                        let groups =
                            crate::datastructs::groups_from_str(string.as_str(), group_size)?;

                        let encrypted = Self::d_with_padding(&groups, size, op, *pad_approach)?;

                        crate::datastructs::string_from_groups(&encrypted).into_bytes()
                    }
                };

                Ok(data)
            },
        )
    }

    pub(crate) fn len(&self) -> usize {
        self.algorithms.len()
    }

    pub(crate) fn items(&self) -> impl Iterator<Item = &(PadApproach, EncryptionStyle, Algorithm)> {
        self.algorithms.iter()
    }
}
