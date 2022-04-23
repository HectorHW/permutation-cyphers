use std::iter::repeat;

#[derive(Copy, Clone, Debug, Default)]
pub struct Bit(bool);

pub trait ProvidesPad: Sized {
    fn get_pad(&self, pad_size: usize) -> Vec<Self> {
        std::iter::repeat_with(|| self.get_pad_value())
            .take(pad_size)
            .collect()
    }
    fn get_pad_value(&self) -> Self;
}

impl<T> ProvidesPad for T
where
    T: Default,
{
    fn get_pad(&self, size: usize) -> Vec<Self> {
        std::iter::repeat_with(|| T::default()).take(size).collect()
    }

    fn get_pad_value(&self) -> Self {
        T::default()
    }
}

pub struct BitVector(pub Vec<Bit>);

impl From<&[u8]> for BitVector {
    fn from(value: &[u8]) -> Self {
        BitVector(Vec::from_iter(value.iter().flat_map(|byte| to_bits(*byte))))
    }
}

impl From<Vec<Bit>> for BitVector {
    fn from(bits: Vec<Bit>) -> Self {
        Self(bits)
    }
}

impl From<BitVector> for Vec<u8> {
    fn from(value: BitVector) -> Self {
        value
            .0
            .into_iter()
            .collect::<Vec<_>>()
            .as_slice()
            .chunks(8)
            .map(from_bits)
            .collect()
    }
}

pub fn to_bits(mut value: u8) -> Vec<Bit> {
    let mut result = vec![];
    while value != 0 {
        result.push(Bit((value & 1) != 0));
        value >>= 1;
    }
    result.append(
        &mut repeat(Bit(false))
            .take(8 - result.len())
            .collect::<Vec<_>>(),
    );
    result
}

pub fn from_bits(bits: &[Bit]) -> u8 {
    debug_assert!(bits.len() <= 8);
    let mut result: u8 = 0;
    let mut power: u8 = 1;
    for bitvalue in bits {
        if bitvalue.0 {
            result |= power;
        }
        power <<= 1;
    }
    result
}

#[derive(Clone, Debug)]
pub struct CharGroup(Vec<char>);

pub fn groups_from_str(s: &str, group_size: usize) -> Vec<CharGroup> {
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(group_size)
        .map(|chunk| CharGroup(chunk.to_vec()))
        .collect()
}

pub fn string_from_groups(groups: &[CharGroup]) -> String {
    groups.iter().cloned().flat_map(|g| g.0).collect()
}

impl ProvidesPad for CharGroup {
    fn get_pad_value(&self) -> Self {
        CharGroup((0..self.0.len()).map(|_| Default::default()).collect())
    }
}
