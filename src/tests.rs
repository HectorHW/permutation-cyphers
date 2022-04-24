use crate::algorithms::{
    permutation::SimplePermutation, rail_fence::RailFenceCypher, stacked::StackedCypher,
    vertical::VerticalPermutation,
};

use crate::algorithms::stacked::{EncryptionStyle::*, PadApproach::*};

#[test]
fn should_work_for_complex_cypher() {
    let cypher = {
        let mut cypher = StackedCypher::new();
        cypher.push(
            Padding,
            Char,
            SimplePermutation::try_from(vec![0, 2, 1, 3]).unwrap(),
        );
        cypher.push(
            Unpadding,
            Byte,
            VerticalPermutation::try_new(
                2,
                4,
                SimplePermutation::try_from(vec![2, 3, 1, 0]).unwrap(),
            )
            .unwrap(),
        );

        cypher.push(Padding, Byte, RailFenceCypher::try_new(3, 8).unwrap());

        cypher.push(
            Padding,
            Bit,
            SimplePermutation::try_from(vec![0, 1]).unwrap(),
        );
        cypher
    };

    let provided = "i love mom";

    let enc = cypher.encrypt(provided.as_bytes()).unwrap();

    dbg!(&enc);

    assert_eq!(cypher.decrypt(enc).unwrap(), provided.as_bytes())
}
