use std::{
    error::Error,
    io::{self, BufRead, Write},
};

use crate::algorithms::{
    decode::PermutationBlockDecoder,
    permutation::SimplePermutation,
    stacked::{Algorithm, PadApproach, StackedCypher},
};

use super::{
    rail_fence::RailFenceCypher, vertical::VerticalPermutation, Encryption, EncryptionStyle,
};

pub struct Serializer<'w, W: Write> {
    writer: &'w mut W,
}

impl<'w, W: Write> Serializer<'w, W> {
    pub fn new(target: &'w mut W) -> Self {
        Self { writer: target }
    }

    pub fn write(&mut self, encryption: &Encryption) -> io::Result<()> {
        let tag = match encryption.get_style() {
            super::EncryptionStyle::Bit => "bit".to_string(),
            super::EncryptionStyle::Byte => "byte".to_string(),
            super::EncryptionStyle::Char => "char".to_string(),
            super::EncryptionStyle::Group(g) => format!("group {g}"),
        };

        self.write_str(&tag)?;

        self.write_cypher(&encryption.algorithm)
    }

    pub fn write_cypher(&mut self, cypher: &StackedCypher) -> io::Result<()> {
        self.write_number(cypher.len())?;

        for algorithm in cypher.items() {
            match algorithm {
                PadApproach::Padding(b) => {
                    self.write_str("padding")?;
                    self.write_permutation(b)
                }
                PadApproach::Unpadding(b) => {
                    self.write_str("unpadding")?;
                    self.write_permutation(b)
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

    pub fn read(&mut self) -> Result<Encryption, Box<dyn Error>> {
        let tag = self.read_string()?;
        let style = match tag.as_str() {
            "bit" => EncryptionStyle::Bit,
            "byte" => EncryptionStyle::Byte,
            "char" => EncryptionStyle::Char,
            "group" => {
                let size = self.read_number()?;
                EncryptionStyle::Group(size)
            }
            other => return Err(format!("unknown encryption style {other}").into()),
        };
        let cypher = self.read_cypher()?;
        Ok(Encryption::new(cypher, style))
    }

    pub fn read_cypher(&mut self) -> Result<StackedCypher, Box<dyn Error>> {
        let size = self.read_number()?;

        let mut res = StackedCypher::new();

        for _ in 0..size {
            let approach = self.read_string()?;

            let algo = self.read_permutation()?;
            match approach.as_str() {
                "padding" => res.push_padding(algo),
                "unpadding" => res.push_unpadding(algo),
                other => return Err(format!("unknown approach {other}").into()),
            }
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
        let columns = self.read_number()?;
        let rows = self.read_number()?;
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
        Encryption, EncryptionStyle,
    };

    use super::{Deserializer, Serializer};

    #[test]
    fn should_serialize() {
        let mut cypher = StackedCypher::new();

        cypher.push_padding(SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap());
        cypher.push_unpadding(
            VerticalPermutation::try_new(2, 4, SimplePermutation::trivial(4)).unwrap(),
        );

        let expected = "2 padding simple 4 3 2 0 1 unpadding vertical 4 2 simple 4 0 1 2 3 ";
        let mut buf = BufWriter::new(Vec::new());
        Serializer::new(&mut buf).write_cypher(&cypher).unwrap();
        assert_eq!(
            String::from_utf8(buf.into_inner().unwrap()).unwrap(),
            expected
        )
    }

    #[test]
    fn should_deserialize() {
        let source = "2 padding simple 4 3 2 0 1 unpadding vertical 4 2 simple 4 0 1 2 3 ";

        let expected = {
            let mut cypher = StackedCypher::new();

            cypher.push_padding(SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap());
            cypher.push_unpadding(
                VerticalPermutation::try_new(2, 4, SimplePermutation::trivial(4)).unwrap(),
            );
            cypher
        };

        //since we cannot test the cyphers for equality, use another approach

        let produced = Deserializer::new(source.as_bytes()).read_cypher().unwrap();

        let expected_output = expected.encrypt(&(0..1000usize).collect::<Vec<_>>());

        let produced_output = produced.encrypt(&(0..1000usize).collect::<Vec<_>>());

        assert_eq!(expected_output, produced_output);
    }

    #[test]
    fn work_with_encryption() {
        let cypher = {
            let mut cypher = StackedCypher::new();

            cypher.push_padding(SimplePermutation::try_from(vec![3, 2, 0, 1]).unwrap());
            cypher.push_unpadding(
                VerticalPermutation::try_new(2, 4, SimplePermutation::trivial(4)).unwrap(),
            );
            cypher
        };

        let encryption = Encryption::new(cypher, EncryptionStyle::Group(3));

        let mut buf = BufWriter::new(Vec::new());

        Serializer::new(&mut buf).write(&encryption).unwrap();

        let s = buf.into_inner().unwrap();

        let produced = Deserializer::new(s.as_slice()).read().unwrap();
        assert_eq!(produced, encryption);
    }
}
