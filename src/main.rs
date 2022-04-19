use crate::{
    algorithms::{
        decode::PermutationBlockDecoder, permutation::SimplePermutation,
        vertical::VerticalPermutation,
    },
    cyphers::{PadDecrypt, PadEncrypt, UnpadDecrypt, UnpadEncrypt},
};

mod algorithms;
mod cyphers;
mod datastructs;

fn main() {
    println!("{:-^40}", "padded");
    let permutation = SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap();

    let cypher = PermutationBlockDecoder::new(permutation.clone());

    let original_data = (1..=10).collect::<Vec<_>>();

    println!("original:\n{original_data:?}");

    let (original_len, encrypted) = cypher.encrypt_with_pad(&original_data);

    println!("encrypted (perm):\n{encrypted:?} (original len {original_len})");

    let decrypted = cypher.decrypt_with_pad(&encrypted, original_len);

    println!("decrypted (perm):\n{decrypted:?}");

    let vertical = VerticalPermutation::new(2, 4, permutation);

    let cypher = PermutationBlockDecoder::new(vertical);

    let (original_len, encrypted) = cypher.encrypt_with_pad(&original_data);
    println!("encrypted (vertical):\n{encrypted:?} (original len {original_len})");

    let decrypted = cypher.decrypt_with_pad(&encrypted, original_len);

    println!("decrypted (vertical):\n{decrypted:?}");

    println!("{:-^40}", "unpadded");
    println!("original:\n{original_data:?}");
    let cypher =
        PermutationBlockDecoder::new(SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap());
    let encrypted = cypher.encrypt_unpad(&original_data);
    println!("encrypted:\n{encrypted:?}");
    let decrypted = cypher.decrypt_unpad(&encrypted);
    println!("decrypted:\n{decrypted:?}");
}
