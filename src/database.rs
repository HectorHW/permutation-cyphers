use std::io::{prelude::*, BufWriter};
use std::{collections::HashMap, error::Error, fs::File};

use crate::algorithms::serialization::{Deserializer, Serializer};
use crate::algorithms::stacked::StackedCypher;

pub struct Database {
    data: HashMap<String, StackedCypher>,
    file: std::fs::File,
}

impl Database {
    pub fn get<'e>(&'e self, key_name: &str) -> Option<&'e StackedCypher> {
        self.data.get(key_name)
    }

    pub fn get_inner(&self) -> &HashMap<String, StackedCypher> {
        &self.data
    }

    pub fn add(&mut self, key: &str, value: StackedCypher) -> Option<StackedCypher> {
        self.data.insert(key.to_owned(), value)
    }

    pub fn delete(&mut self, key: &str) -> Option<StackedCypher> {
        self.data.remove(key)
    }

    pub fn load_from_file(file: File) -> Result<Database, Box<dyn Error>> {
        let mut database = Database {
            data: Default::default(),
            file,
        };

        database.reload()?;
        Ok(database)
    }

    pub fn reload(&mut self) -> Result<(), Box<dyn Error>> {
        self.file.seek(std::io::SeekFrom::Start(0))?;
        let mut data = String::new();
        self.file.read_to_string(&mut data)?;

        let entries = data
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|substring| {
                let maybe_record: Result<(&str, &str), Box<dyn Error>> = substring
                    .split_once(':')
                    .ok_or_else(|| "failed to read database".into());
                let (name, config) = maybe_record?;
                let mut deserializer = Deserializer::new(config.as_bytes());
                Ok((name.to_string(), deserializer.read()?))
            })
            .collect::<Result<HashMap<String, StackedCypher>, Box<dyn Error>>>()?;

        self.data = entries;

        Ok(())
    }

    pub fn save(&mut self) -> Result<(), Box<dyn Error>> {
        self.file.seek(std::io::SeekFrom::Start(0))?;

        self.file.set_len(0)?;

        let content = self
            .data
            .iter()
            .map(|(k, v)| {
                let mut buffer = BufWriter::new(Vec::new());

                Serializer::new(&mut buffer).write(v)?;

                let string = String::from_utf8(buffer.into_inner()?)?;

                Ok(format!("{}:{}", k, string))
            })
            .collect::<Result<Vec<String>, Box<dyn Error>>>()?
            .join("\n");

        self.file.write_all(content.as_bytes())?;
        self.file.flush()?;

        Ok(())
    }
}
