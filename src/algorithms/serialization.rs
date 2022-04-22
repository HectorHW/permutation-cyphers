use std::{
    error::Error,
    io::{self, BufRead, Write},
};

use crate::{
    algorithms::{
        decode::PermutationBlockDecoder,
        permutation::SimplePermutation,
        stacked::{Algorithm, StackedCypher},
    },
    datastructs::ProvidesPad,
};

use super::{rail_fence::RailFenceCypher, vertical::VerticalPermutation};

pub struct Serializer<'w, W: Write> {
    writer: &'w mut W,
}

impl<'w, W: Write> Serializer<'w, W> {
    pub fn new(target: &'w mut W) -> Self {
        Self { writer: target }
    }

    pub fn write<T: Clone + ProvidesPad + 'static>(
        &mut self,
        cypher: &StackedCypher<T>,
    ) -> io::Result<()> {
        self.write_number(cypher.len())?;

        macro_rules! downcast_serialize {
            ( $b: expr) => {
                $b.downcast_ref::<PermutationBlockDecoder<T, SimplePermutation>>()
                    .map(PermutationBlockDecoder::get_inner)
                    .map(|p| self.write_simple_permutation(p))
                    .or_else(|| {
                        $b.downcast_ref::<PermutationBlockDecoder<T, RailFenceCypher>>()
                            .map(PermutationBlockDecoder::get_inner)
                            .map(|p| self.write_rail_fence(p))
                    })
                    .or_else(|| {
                        $b.downcast_ref::<PermutationBlockDecoder<T, VerticalPermutation>>()
                            .map(PermutationBlockDecoder::get_inner)
                            .map(|p| self.write_vertical_permutation(p))
                    })
                    .unwrap()
            };
        }

        for algorithm in cypher.items() {
            match algorithm {
                Algorithm::Padding(b) => {
                    self.write_str("padding")?;

                    downcast_serialize!(b)
                }
                Algorithm::Unpadding(b) => {
                    self.write_str("unpadding")?;

                    downcast_serialize!(b)
                }
            }?;
        }

        Ok(())
    }

    fn write_number(&mut self, n: usize) -> io::Result<()> {
        write!(self.writer, "{} ", n)
    }

    fn write_array(&mut self, array: &[usize]) -> io::Result<()> {
        write!(self.writer, "{} ", array.len())?;
        array
            .iter()
            .try_for_each(|&n| write!(self.writer, "{} ", n))
    }

    fn write_str(&mut self, value: &str) -> io::Result<()> {
        write!(self.writer, "{} ", value)
    }

    fn write_simple_permutation(&mut self, p: &SimplePermutation) -> io::Result<()> {
        self.write_str("simple")?;
        self.write_array(&p.indices)
    }

    fn write_rail_fence(&mut self, p: &RailFenceCypher) -> io::Result<()> {
        self.write_str("rail")?;
        self.write_number(p.columns)?;
        self.write_number(p.rows)
    }

    fn write_vertical_permutation(&mut self, p: &VerticalPermutation) -> io::Result<()> {
        self.write_str("vertical")?;
        self.write_number(p.columns)?;
        self.write_number(p.rows)?;
        self.write_simple_permutation(&p.permutation)
    }
}

pub struct Deserializer<R: BufRead> {
    reader: R,
}

impl<R: BufRead> Deserializer<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn read<T: ProvidesPad + Clone + 'static>(
        &mut self,
    ) -> Result<StackedCypher<T>, Box<dyn Error>> {
        let size = self.read_number()?;

        Ok(StackedCypher::<T>::new(
            (0..size)
                .map(|_| {
                    let tag = self.read_string()?;

                    macro_rules! read_permutation {
                        ($v:expr) => {{
                            let name = self.read_string()?;

                            $v(match name.as_str() {
                                "simple" => Box::new(PermutationBlockDecoder::new(
                                    self.read_simple_permutation()?,
                                )),
                                "vertical" => {
                                    Box::new(PermutationBlockDecoder::new(self.read_vertical()?))
                                }
                                "rail" => {
                                    Box::new(PermutationBlockDecoder::new(self.read_rail_fence()?))
                                }

                                other => {
                                    return Err(format!("unknown permutation type {other}").into());
                                }
                            })
                        }};
                    }

                    match tag.as_str() {
                        "padding" => Ok(read_permutation!(Algorithm::Padding)),
                        "unpadding" => Ok(read_permutation!(Algorithm::Unpadding)),
                        other => Err(format!("unknown pad mode {other}").into()),
                    }
                })
                .collect::<Result<Vec<_>, Box<dyn Error>>>()?,
        ))
    }

    fn read_string(&mut self) -> Result<String, Box<dyn Error>> {
        let mut buffer = Vec::new();
        self.reader.read_until(b' ', &mut buffer)?;
        let _ = buffer.pop();

        let res = String::from_utf8(buffer)?;
        Ok(res)
    }

    fn read_number(&mut self) -> Result<usize, Box<dyn Error>> {
        self.read_string()?.parse::<usize>().map_err(|e| e.into())
    }

    fn read_array(&mut self) -> Result<Vec<usize>, Box<dyn Error>> {
        let size = self.read_number()?;
        (0..size).map(|_| self.read_number()).collect()
    }

    fn read_simple_permutation(&mut self) -> Result<SimplePermutation, Box<dyn Error>> {
        SimplePermutation::try_from(self.read_array()?)
            .ok_or_else(|| "failed to read simple permutation".into())
    }

    fn read_rail_fence(&mut self) -> Result<RailFenceCypher, Box<dyn Error>> {
        Ok(RailFenceCypher::new(
            self.read_number()?,
            self.read_number()?,
        ))
    }

    fn read_vertical(&mut self) -> Result<VerticalPermutation, Box<dyn Error>> {
        let columns = self.read_number()?;
        let rows = self.read_number()?;
        let _tag = self.read_string()?;
        let permutation = self.read_simple_permutation()?;

        Ok(VerticalPermutation::new(rows, columns, permutation))
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    use crate::algorithms::{
        decode::PermutationBlockDecoder, permutation::SimplePermutation, stacked::StackedCypher,
        vertical::VerticalPermutation,
    };

    use super::{Deserializer, Serializer};

    #[test]
    fn should_serialize() {
        let mut cypher = StackedCypher::<usize>::new(vec![]);

        cypher.push_padding(PermutationBlockDecoder::new(
            SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap(),
        ));
        cypher.push_unpadding(PermutationBlockDecoder::new(VerticalPermutation::new(
            2,
            4,
            SimplePermutation::trivial(4),
        )));

        let expected = "2 padding simple 4 3 2 0 1 unpadding vertical 4 2 simple 4 0 1 2 3 ";
        let mut buf = BufWriter::new(Vec::new());
        Serializer::new(&mut buf).write(&cypher).unwrap();
        assert_eq!(
            String::from_utf8(buf.into_inner().unwrap()).unwrap(),
            expected
        )
    }

    #[test]
    fn should_deserialize() {
        let source = "2 padding simple 4 3 2 0 1 unpadding vertical 4 2 simple 4 0 1 2 3 ";

        let expected = {
            let mut cypher = StackedCypher::<usize>::new(vec![]);

            cypher.push_padding(PermutationBlockDecoder::new(
                SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap(),
            ));
            cypher.push_unpadding(PermutationBlockDecoder::new(VerticalPermutation::new(
                2,
                4,
                SimplePermutation::trivial(4),
            )));
            cypher
        };

        //since we cannot test the cyphers for equality, use another approach

        let produced = Deserializer::new(source.as_bytes()).read().unwrap();

        let expected_output = expected.encrypt(&(0..1000usize).collect::<Vec<_>>());

        let produced_output = produced.encrypt(&(0..1000usize).collect::<Vec<_>>());

        assert_eq!(expected_output, produced_output);
    }
}
