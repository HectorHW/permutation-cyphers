use crate::algorithms::{
    permutation::SimplePermutation, serialization::Serializer, stacked::StackedCypher,
    vertical::VerticalPermutation,
};

mod algorithms;
mod datastructs;

fn main() {
    let mut cypher = StackedCypher::new();

    cypher.push_padding(SimplePermutation::try_from(vec![1, 3, 0, 2]).unwrap());
    cypher.push_unpadding(VerticalPermutation::new(
        2,
        4,
        SimplePermutation::trivial(4),
    ));

    let original_data = (1..=20).collect::<Vec<_>>();

    println!("original:\n{original_data:?}");

    let (original_len, encrypted) = cypher.encrypt(&original_data);

    println!("encrypted (perm):\n{encrypted:?} (original len {original_len:?})");

    let decrypted = cypher.decrypt(&encrypted, &original_len);

    println!("decrypted (perm):\n{decrypted:?}");

    let mut stdout = std::io::stdout();

    Serializer::new(&mut stdout).write(&cypher).unwrap();
}
