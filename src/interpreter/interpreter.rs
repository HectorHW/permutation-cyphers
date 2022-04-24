use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};

use rand::{thread_rng, Rng};

use crate::{
    algorithms::{
        permutation::SimplePermutation,
        rail_fence::RailFenceCypher,
        stacked::{Algorithm, EncryptionStyle, PadApproach, StackedCypher},
        vertical::VerticalPermutation,
    },
    database::Database,
};

use super::parse::{
    AlgorithmType, DataSource, DataTarget, DecryptSource, PermutationType, PickApproach, Stmt,
};

pub struct Interpreter {
    db: Option<Database>,
}

impl Interpreter {
    pub fn new() -> Self {
        Interpreter { db: None }
    }

    fn require_database(&mut self) -> Result<&mut Database, Box<dyn Error>> {
        if self.db.is_none() {
            Err("database required to use this. load one with DATABASE first".into())
        } else {
            Ok(self.db.as_mut().unwrap())
        }
    }

    pub fn visit_stmt(&mut self, stmt: &Stmt) -> Result<String, Box<dyn Error>> {
        match stmt {
            Stmt::DatabasePick { name, create } => {
                let mut options = std::fs::File::options();
                let mut file = options.read(true).write(true);

                match create {
                    PickApproach::Create => {
                        file = file.create_new(true);
                    }
                    PickApproach::Load => file = file.create(false),
                    PickApproach::Any => file = file.create(true),
                }

                let file = file
                    .open(name)
                    .map_err(|e| format!("failed to open database file: {e}"))?;
                let database = Database::load_from_file(file)
                    .map_err(|e| format!("failed to read database: {e}"))?;

                let message = if self.db.is_some() {
                    format!("replaced own database with {}", name)
                } else {
                    format!("loaded database {}", name)
                };
                self.db = Some(database);
                Ok(message)
            }

            Stmt::Save => {
                self.require_database()?;
                self.db.as_mut().unwrap().save()?;
                Ok("saved database".to_string())
            }

            Stmt::Reload => {
                self.require_database()?.reload()?;
                Ok("reloaded database".to_string())
            }

            Stmt::List => {
                self.require_database()?;

                let items = self
                    .db
                    .as_ref()
                    .unwrap()
                    .get_inner()
                    .keys()
                    .map(|k| k.to_string())
                    .collect::<Vec<_>>();
                let total = items.len();

                Ok(format!("entries:\n{}\n({total} total)", items.join("\n")))
            }

            Stmt::Describe(name) => Ok({
                let cypher: &StackedCypher = self
                    .require_database()?
                    .get(name)
                    .ok_or_else(|| format!("no such entry {name}"))?;

                let items = cypher.items();

                let items = items
                    .map(|(pad, style, algo)| {
                        let pad = match pad {
                            PadApproach::Padding => "padding",
                            PadApproach::Unpadding => "unpadding",
                        };

                        let style = match style {
                            EncryptionStyle::Bit => "bit".to_string(),
                            EncryptionStyle::Byte => "byte".to_string(),
                            EncryptionStyle::Char => "char".to_string(),
                            EncryptionStyle::Group(g) => format!("group({})", g),
                        };

                        let algo = match algo {
                            Algorithm::Permutation(p) => {
                                format!("{:?}", p.get_inner())
                            }
                            Algorithm::RailFence(r) => {
                                format!("{:?}", r.get_inner())
                            }
                            Algorithm::Vertical(v) => {
                                format!("{:?}", v.get_inner())
                            }
                        };

                        format!("{pad} {style} {algo}")
                    })
                    .collect::<Vec<_>>()
                    .join("; ");

                format!("algorithms: [{items}]")
            }),
            Stmt::Encrypt { from, key, to } => {
                let db = self.require_database()?;

                let key = db.get(key).ok_or_else(|| format!("no key {key}"))?;

                let data = match from {
                    DataSource::String(s) => s.clone().into_bytes(),
                    DataSource::File(f) => std::fs::read(f)?,
                };

                let (sizes, msg) = key.encrypt(&data)?;

                match to {
                    DataTarget::Console => Ok(format!(
                        "{sizes:?} {msg:?} (\"{}\")",
                        escape(&String::from_utf8_lossy(&msg))
                    )),
                    DataTarget::File(f) => {
                        let mut file = File::options().write(true).create(true).open(f)?;

                        file.write_all(&sizes.len().to_be_bytes())?;

                        for size in sizes {
                            file.write_all(&size.to_be_bytes())?;
                        }
                        file.write_all(msg.as_slice())?;
                        Ok(format!("written {f}"))
                    }
                }
            }
            Stmt::Decrypt { from, key, to } => {
                let db = self.require_database()?;

                let key = db.get(key).ok_or_else(|| format!("no key {key}"))?;

                let data = match from {
                    DecryptSource::ConsoleString(sizes, s) => {
                        (sizes.clone(), unescape(s)?.into_bytes())
                    }

                    DecryptSource::ConsoleRaw(sizes, data) => (sizes.clone(), data.clone()),

                    DecryptSource::File(f) => {
                        let mut file = File::options().read(true).open(f)?;

                        let mut buf = [0u8; std::mem::size_of::<usize>()];
                        file.read_exact(&mut buf)?;

                        let total_indices = usize::from_be_bytes(buf);

                        let mut sizes = vec![];

                        for _ in 0..total_indices {
                            let mut buf = [0u8; std::mem::size_of::<usize>()];
                            file.read_exact(&mut buf)?;
                            sizes.push(usize::from_be_bytes(buf));
                        }
                        let mut data = vec![];
                        file.read_to_end(&mut data)?;
                        (sizes, data)
                    }
                };

                let message = key.decrypt(data)?;

                match to {
                    DataTarget::Console => Ok(format!("message: {}", {
                        if let Ok(msg) = String::from_utf8(message.clone()) {
                            format!("\"{}\"", msg)
                        } else {
                            format!(
                                "\"{}\" (not all characters were parsed normally)",
                                escape(&String::from_utf8_lossy(&message))
                            )
                        }
                    })),
                    DataTarget::File(f) => {
                        let mut file = File::options().write(true).create(true).open(f)?;
                        file.write_all(message.as_slice())?;
                        Ok(format!("written {f}"))
                    }
                }
            }

            Stmt::Delete(n) => match self.require_database()?.delete(n) {
                Some(_) => Ok(format!("deleted key {n}")),
                None => Err("no such key".into()),
            },

            Stmt::Add { name, algos } => {
                let db = self.require_database()?;

                let cypher = {
                    let mut cypher = StackedCypher::new();

                    for algo in algos {
                        let pad = algo.padding;
                        let style = algo.style;
                        let algo: Algorithm = match &algo.algo_type {
                            AlgorithmType::Permutation(PermutationType::Generated(size)) => {
                                SimplePermutation::random_with_size(*size)?.into()
                            }

                            AlgorithmType::Permutation(PermutationType::Manual(config)) => {
                                SimplePermutation::try_from(config.clone())
                                    .ok_or_else(|| {
                                        <Box<dyn Error>>::from("misconfigured permutation")
                                    })?
                                    .into()
                            }

                            AlgorithmType::RailFence(None) => {
                                thread_rng().gen::<RailFenceCypher>().into()
                            }

                            AlgorithmType::RailFence(Some((rows, columns))) => {
                                RailFenceCypher::try_new(*rows, *columns)?.into()
                            }
                            AlgorithmType::Vertical(None) => {
                                thread_rng().gen::<VerticalPermutation>().into()
                            }
                            AlgorithmType::Vertical(Some((rows, columns, c))) => {
                                let permutation = SimplePermutation::try_from(c.clone())
                                    .ok_or_else(|| {
                                        <Box<dyn Error>>::from(
                                            "misconfigured permutation of vertical cypher",
                                        )
                                    })?;
                                VerticalPermutation::try_new(*rows, *columns, permutation)?.into()
                            }
                        };
                        cypher.push(pad, style, algo);
                    }
                    cypher
                };

                Ok(match db.add(name, cypher) {
                    Some(_) => format!("replaced cypher \"{}\"", name),
                    None => format!("added cypher \"{}\"", name),
                })
            }
        }
    }
}

fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\0' => vec!['\\', '0'],
            '\n' => vec!['\\', 'n'],
            other => vec![other],
        })
        .collect()
}

fn unescape(s: &str) -> Result<String, Box<dyn Error>> {
    fn unescape_(s: &str) -> Result<String, usize> {
        let mut input = s.char_indices().peekable();

        let mut res = String::new();

        while input.peek().is_some() {
            match input.next().unwrap() {
                (idx, '\\') => match input.peek() {
                    Some((_, '0')) => {
                        input.next();
                        res.push('\0');
                    }
                    Some((_, 'n')) => {
                        input.next();
                        res.push('\n');
                    }

                    _ => return Err(idx),
                },

                (_, other) => {
                    res.push(other);
                }
            }
        }
        Ok(res)
    }

    unescape_(s).map_err(|idx| format!("error while unescaping at {idx}").into())
}
