use crate::algorithms::{
    permutation::SimplePermutation, rail_fence::RailFenceCypher, stacked::StackedCypher,
    vertical::VerticalPermutation, Encryption,
};

#[test]
fn should_work_for_complex_cypher() {
    let cypher = {
        let mut cypher = StackedCypher::new();
        cypher.push_padding(SimplePermutation::try_from(vec![0, 2, 1, 3]).unwrap());
        cypher.push_unpadding(
            VerticalPermutation::try_new(
                2,
                4,
                SimplePermutation::try_from(vec![2, 3, 1, 0]).unwrap(),
            )
            .unwrap(),
        );

        cypher.push_padding(RailFenceCypher::try_new(3, 8).unwrap());

        cypher.push_unpadding(SimplePermutation::try_from(vec![0, 1]).unwrap());
        cypher
    };

    let encryption = Encryption::new(cypher, crate::algorithms::EncryptionStyle::Char);

    let provided = "i love mom";

    let enc = encryption.encrypt_text(provided).unwrap();

    dbg!(&enc);

    assert_eq!(
        encryption
            .decrypt_text((enc.0, enc.1.into_bytes()))
            .unwrap(),
        provided
    )
}
