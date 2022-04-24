#![allow(dead_code)]

use std::error::Error;

use crate::datastructs::{groups_from_str, string_from_groups, BitVector};

use self::stacked::StackedCypher;
pub mod cyphers;
pub mod decode;
pub mod generation;
pub mod permutation;
pub mod rail_fence;
pub mod serialization;
pub mod stacked;
pub mod vertical;

///accepts `indices` which are used as follows:
///
///for item and target index `i`: result\[i\] = item
pub(super) fn move_by_indices<T>(data: Vec<T>, indices: &[usize]) -> Vec<T> {
    use std::mem::MaybeUninit;
    assert_eq!(indices.len(), data.len());
    let mut items: Vec<MaybeUninit<T>> = std::iter::repeat_with(|| MaybeUninit::uninit())
        .take(data.len())
        .collect();

    for (&index, value) in indices.iter().zip(data.into_iter()) {
        items[index].write(value);
    }

    items
        .into_iter()
        //this is safe because all indices are present in permutation
        // => all indices are written exactly once
        .map(|item| unsafe { item.assume_init() })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::move_by_indices;

    #[test]
    fn substitution() {
        assert_eq!(
            move_by_indices(vec!['a', 'b', 'c', 'd'], &[1, 2, 0, 3]),
            vec!['c', 'a', 'b', 'd']
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encryption {
    algorithm: StackedCypher,
    style: EncryptionStyle,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncryptionStyle {
    Bit,
    Byte,
    Char,
    Group(usize),
}

impl Encryption {
    pub fn new(algorithm: StackedCypher, style: EncryptionStyle) -> Self {
        Self { algorithm, style }
    }

    pub fn get_style(&self) -> EncryptionStyle {
        self.style
    }

    pub fn get_algorithm(&self) -> &StackedCypher {
        &self.algorithm
    }

    pub fn accepts_characters(&self) -> bool {
        matches!(
            self.style,
            EncryptionStyle::Char | EncryptionStyle::Group(_)
        )
    }

    pub fn encrypt_text(&self, data: &str) -> Result<(Vec<usize>, String), Box<dyn Error>> {
        match self.style {
            EncryptionStyle::Bit => {
                Err("cannot perform encryption text -> text on bit level".into())
            }
            EncryptionStyle::Byte => {
                Err("cannot perform encryption text -> text on byte level".into())
            }
            EncryptionStyle::Char => {
                let data = data.chars().collect::<Vec<_>>();
                let (size, encrypted) = self.algorithm.encrypt(&data);
                Ok((size, encrypted.into_iter().collect()))
            }
            EncryptionStyle::Group(group_size) => {
                if data.len() % group_size != 0 {
                    return Err(
                        format!(
                            "unsupported string for group encryption: got {} chars; accept multiples of {}", 
                        data.len(), group_size)
                        .into());
                }
                let data = dbg!(groups_from_str(data, group_size));
                let (size, encrypted) = self.algorithm.encrypt(&data);
                Ok((size, string_from_groups(&encrypted)))
            }
        }
    }

    pub fn encrypt_raw(&self, data: &[u8]) -> Result<(Vec<usize>, Vec<u8>), Box<dyn Error>> {
        match self.style {
            EncryptionStyle::Bit => {
                let data = BitVector::from(data);
                let (sizes, encrypted) = self.algorithm.encrypt(&data.0);
                Ok((sizes, BitVector::from(encrypted).into()))
            }
            EncryptionStyle::Byte => Ok(self.algorithm.encrypt(data)),
            EncryptionStyle::Char => {
                Err("cannot perform raw -> raw encryption on char level".into())
            }
            EncryptionStyle::Group(_) => {
                Err("cannot perform raw -> raw encryption on char group level".into())
            }
        }
    }

    pub fn decrypt_text(&self, data: (Vec<usize>, Vec<u8>)) -> Result<String, Box<dyn Error>> {
        let (sizes, data) = data;
        match self.style {
            EncryptionStyle::Bit => {
                String::from_utf8(self.decrypt_raw((sizes, data))?).map_err(|e| e.into())
            }
            EncryptionStyle::Byte => {
                String::from_utf8(self.decrypt_raw((sizes, data))?).map_err(|e| e.into())
            }
            EncryptionStyle::Char => {
                let data = String::from_utf8(data.to_vec())?;
                let chars = data.chars().collect::<Vec<_>>();
                let decrypted = self.algorithm.decrypt(&chars, &sizes)?;
                Ok(decrypted.into_iter().collect())
            }
            EncryptionStyle::Group(group_size) => {
                let data = String::from_utf8(data.to_vec())?;
                let groups = groups_from_str(&data, group_size);
                let decrypted = self.algorithm.decrypt(&groups, &sizes)?;
                Ok(string_from_groups(&decrypted))
            }
        }
    }

    pub fn decrypt_raw(&self, data: (Vec<usize>, Vec<u8>)) -> Result<Vec<u8>, Box<dyn Error>> {
        let (sizes, data) = data;
        match self.style {
            EncryptionStyle::Bit => {
                let data = BitVector::from(data.as_slice());
                let decrypted = self.algorithm.decrypt(&data.0, &sizes)?;
                Ok(BitVector::from(decrypted).into())
            }
            EncryptionStyle::Byte => Ok(self.algorithm.decrypt(&data, &sizes)?),
            EncryptionStyle::Char => Err("cannot decrypt to raw on char level".into()),
            EncryptionStyle::Group(_) => Err("cannot decrypt to raw on char group level".into()),
        }
    }
}

#[cfg(test)]
mod usecase_tests {
    use super::{serialization, stacked::StackedCypher, Encryption, EncryptionStyle};

    fn get_algorithm() -> StackedCypher {
        serialization::Deserializer::new(
            "2 padding simple 4 1 3 0 2 unpadding vertical 4 2 simple 4 0 1 2 3 ".as_bytes(),
        )
        .read_cypher()
        .unwrap()
    }

    fn text_text_for_style(style: EncryptionStyle) {
        let algorithm = get_algorithm();
        let encryption = Encryption::new(algorithm, style);
        let string = "abcdefgh";

        let data = encryption.encrypt_text(string).unwrap();

        assert_eq!(
            encryption
                .decrypt_text((data.0, data.1.into_bytes()))
                .unwrap(),
            string
        )
    }

    fn raw_text_for_style(style: EncryptionStyle) {
        let algorithm = get_algorithm();
        let encryption = Encryption::new(algorithm, style);
        let string = "abcdefgh";

        assert_eq!(
            encryption
                .decrypt_text(encryption.encrypt_raw(string.as_bytes()).unwrap())
                .unwrap(),
            string
        )
    }

    #[test]
    fn should_work_with_text() {
        raw_text_for_style(EncryptionStyle::Bit);
        raw_text_for_style(EncryptionStyle::Byte);
        text_text_for_style(EncryptionStyle::Char);
        text_text_for_style(EncryptionStyle::Group(2));
    }
}
