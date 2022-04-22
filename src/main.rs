use crate::algorithms::{
    decode::PermutationBlockDecoder, permutation::SimplePermutation, stacked::StackedCypher,
    vertical::VerticalPermutation,
};

mod algorithms;
mod cyphers;
mod datastructs;

fn main() {
    let mut cypher = StackedCypher::<usize>::new(vec![]);

    cypher.push_padding(PermutationBlockDecoder::new(
        SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap(),
    ));
    cypher.push_unpadding(PermutationBlockDecoder::new(VerticalPermutation::new(
        2,
        4,
        SimplePermutation::trivial(4),
    )));

    let original_data = (1..=10).collect::<Vec<_>>();

    println!("original:\n{original_data:?}");

    let (original_len, encrypted) = cypher.encrypt(&original_data);

    println!("encrypted (perm):\n{encrypted:?} (original len {original_len:?})");

    let decrypted = cypher.decrypt(&encrypted, &original_len);

    println!("decrypted (perm):\n{decrypted:?}");
}
