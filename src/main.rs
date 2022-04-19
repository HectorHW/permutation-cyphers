use crate::{
    algorithms::{
        decode::PermutationBlockDecoder, permutation::SimplePermutation,
        vertical::VerticalPermutation,
    },
    cyphers::{PadDecrypt, PadEncrypt},
};

mod algorithms;
mod cyphers;
mod datastructs;

fn main() {
    let permutation = SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap();

    let cypher = PermutationBlockDecoder::new(permutation.clone());

    let original_data = (1..=10).collect::<Vec<_>>();

    println!("original:\n{original_data:?}");

    let (original_len, encrypted) = cypher.encrypt_with_pad(&original_data);

    println!("{encrypted:?} (original len {original_len})");

    let decrypted = cypher.decrypt_with_pad(&encrypted, original_len);

    println!("{decrypted:?}");

    let vertical = VerticalPermutation::new(2, 4, permutation);

    let cypher = PermutationBlockDecoder::new(vertical);

    let (original_len, encrypted) = cypher.encrypt_with_pad(&original_data);
    println!("{encrypted:?} (original len {original_len})");

    let decrypted = cypher.decrypt_with_pad(&encrypted, original_len);

    println!("{decrypted:?}");
}
