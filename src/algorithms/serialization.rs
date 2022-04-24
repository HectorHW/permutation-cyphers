use std::{
    error::Error,
    io::{self, BufRead, Write},
};

use crate::algorithms::{
    decode::PermutationBlockDecoder,
    permutation::SimplePermutation,
    stacked::{Algorithm, PadApproach, StackedCypher},
};

use super::{rail_fence::RailFenceCypher, stacked::EncryptionStyle, vertical::VerticalPermutation};

pub struct Serializer<'w, W: Write> {
    writer: &'w mut W,
}

impl<'w, W: Write> Serializer<'w, W> {
    pub fn new(target: &'w mut W) -> Self {
        Self { writer: target }
    }

    pub fn write(&mut self, cypher: &StackedCypher) -> io::Result<()> {
        self.write_number(cypher.len())?;

        for (pad, style, algorithm) in cypher.items() {
            match pad {
                PadApproach::Padding => self.write_str("padding")?,
                PadApproach::Unpadding => self.write_str("unpadding")?,
            }

            self.write_str(&match *style {
                EncryptionStyle::Bit => "bit".to_string(),
                EncryptionStyle::Byte => "byte".to_string(),
                EncryptionStyle::Char => "char".to_string(),
                EncryptionStyle::Group(g) => format!("group {g}"),
            })?;

            self.write_permutation(algorithm)?;
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

    fn write_permutation(&mut self, p: &Algorithm) -> io::Result<()> {
        match p {
            Algorithm::Permutation(p) => self.write_simple_permutation(p.get_inner()),
            Algorithm::RailFence(r) => self.write_rail_fence(r.get_inner()),
            Algorithm::Vertical(v) => self.write_vertical_permutation(v.get_inner()),
        }
    }
}

pub struct Deserializer<R: BufRead> {
    reader: R,
}

impl<R: BufRead> Deserializer<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn read(&mut self) -> Result<StackedCypher, Box<dyn Error>> {
        let size = self.read_number()?;

        let mut res = StackedCypher::new();

        for _ in 0..size {
            let pad = match self.read_string()?.as_str() {
                "padding" => PadApproach::Padding,
                "unpadding" => PadApproach::Unpadding,
                other => return Err(format!("unknown padding type {other}").into()),
            };

            let style = match self.read_string()?.as_str() {
                "bit" => EncryptionStyle::Bit,
                "byte" => EncryptionStyle::Byte,
                "char" => EncryptionStyle::Char,
                "group" => {
                    let size = self.read_number()?;
                    EncryptionStyle::Group(size)
                }
                other => return Err(format!("unknown encryption style {other}").into()),
            };

            let algo = self.read_permutation()?;

            res.push(pad, style, algo);
        }

        Ok(res)
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
        RailFenceCypher::try_new(self.read_number()?, self.read_number()?)
    }

    fn read_vertical(&mut self) -> Result<VerticalPermutation, Box<dyn Error>> {
        let rows = self.read_number()?;
        let columns = self.read_number()?;
        let _tag = self.read_string()?;
        let permutation = self.read_simple_permutation()?;

        VerticalPermutation::try_new(rows, columns, permutation)
    }

    fn read_permutation(&mut self) -> Result<Algorithm, Box<dyn Error>> {
        let tag = self.read_string()?;

        Ok(match tag.as_str() {
            "simple" => Algorithm::Permutation(PermutationBlockDecoder::new(
                self.read_simple_permutation()?,
            )),
            "vertical" => Algorithm::Vertical(PermutationBlockDecoder::new(self.read_vertical()?)),
            "rail" => Algorithm::RailFence(PermutationBlockDecoder::new(self.read_rail_fence()?)),

            other => {
                return Err(format!("unknown permutation type {other}").into());
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    use crate::algorithms::{
        permutation::SimplePermutation, stacked::StackedCypher, vertical::VerticalPermutation,
    };

    use super::{Deserializer, Serializer};

    use crate::algorithms::stacked::EncryptionStyle::*;
    use crate::algorithms::stacked::PadApproach::*;

    #[test]
    fn should_serialize() {
        let mut cypher = StackedCypher::new();

        cypher.push(
            Padding,
            Char,
            SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap(),
        );
        cypher.push(
            Unpadding,
            Byte,
            VerticalPermutation::try_new(2, 4, SimplePermutation::trivial(4)).unwrap(),
        );

        let expected =
            "2 padding char simple 4 3 2 0 1 unpadding byte vertical 4 2 simple 4 0 1 2 3 ";
        let mut buf = BufWriter::new(Vec::new());
        Serializer::new(&mut buf).write(&cypher).unwrap();
        assert_eq!(
            String::from_utf8(buf.into_inner().unwrap()).unwrap(),
            expected
        )
    }

    #[test]
    fn should_deserialize() {
        let source = "2 padding bit simple 4 3 2 0 1 unpadding byte vertical 2 4 simple 4 0 1 2 3 ";

        let expected = {
            let mut cypher = StackedCypher::new();

            cypher.push(
                Padding,
                Bit,
                SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap(),
            );
            cypher.push(
                Unpadding,
                Byte,
                VerticalPermutation::try_new(2, 4, SimplePermutation::trivial(4)).unwrap(),
            );
            cypher
        };

        //since we cannot test the cyphers for equality, use another approach

        let produced = Deserializer::new(source.as_bytes()).read().unwrap();

        let expected_output = expected.encrypt(&(0..255u8).collect::<Vec<_>>()).unwrap();

        let produced_output = produced.encrypt(&(0..255u8).collect::<Vec<_>>()).unwrap();

        assert_eq!(expected_output, produced_output);
    }
}
