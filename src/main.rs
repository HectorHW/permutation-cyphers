use crate::{
    algorithms::{permutation::SimplePermutation, vertical::VerticalPermutation},
    cyphers::PadEncrypt,
};

mod algorithms;
mod cyphers;
mod datastructs;

fn main() {
    let permutation = SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap();

    let original_data = (1..=10).collect::<Vec<_>>();

    println!("original: {original_data:?}");

    let (original_len, encrypted) = permutation.encrypt_with_pad(&original_data);

    println!("{encrypted:?} (original len {original_len})");

    let decrypted = permutation.decrypt_with_pad(&encrypted, original_len);

    println!("{decrypted:?}");

    let vertical = VerticalPermutation::new(2, 4, permutation);

    let (original_len, encrypted) = vertical.encrypt_with_pad(&original_data);
    println!("{encrypted:?} (original len {original_len})");

    let decrypted = vertical.decrypt_with_pad(&encrypted, original_len);

    println!("{decrypted:?}");
}
