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
        stacked::{Algorithm, PadApproach, StackedCypher},
        vertical::VerticalPermutation,
        Encryption,
    },
    database::Database,
};

use super::parse::{AlgorithmType, DataSource, DataTarget, DecryptSource, PickApproach, Stmt};

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
                let cypher: &Encryption = self
                    .require_database()?
                    .get(name)
                    .ok_or_else(|| format!("no such entry {name}"))?;

                let style = cypher.get_style();

                let items = cypher.get_algorithm().items();

                let items = items
                    .map(|algo| {
                        let (pad, algo) = match algo {
                            PadApproach::Padding(p) => ("padding", p),
                            PadApproach::Unpadding(p) => ("unpadding", p),
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

                        format!("{pad} {algo}")
                    })
                    .collect::<Vec<_>>()
                    .join("; ");

                format!("style: {style:?}; algorithms: [{items}]")
            }),
            Stmt::Encrypt { from, key, to } => {
                let db = self.require_database()?;

                let key = db.get(key).ok_or_else(|| format!("no key {key}"))?;

                if key.accepts_characters() {
                    let data = match from {
                        DataSource::String(s) => s.clone(),
                        DataSource::File(f) => std::fs::read_to_string(f)?,
                    };
                    let (sizes, msg) = key.encrypt_text(&data)?;

                    match to {
                        DataTarget::Console => Ok(format!("{sizes:?} \"{msg}\"")),
                        DataTarget::File(f) => {
                            let mut file = File::options().write(true).create(true).open(f)?;
                            file.write_fmt(format_args!("{sizes:?} \"{msg}\""))?;
                            Ok(format!("written {f}"))
                        }
                    }
                } else {
                    let data = match from {
                        DataSource::String(s) => s.clone().into_bytes(),
                        DataSource::File(f) => std::fs::read(f)?,
                    };

                    let (sizes, msg) = key.encrypt_raw(&data)?;

                    match to {
                        DataTarget::Console => Ok(format!("{sizes:?} {msg:?}")),
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
            }
            Stmt::Decrypt { from, key, to } => {
                let db = self.require_database()?;

                let key = db.get(key).ok_or_else(|| format!("no key {key}"))?;

                let data = match from {
                    DecryptSource::ConsoleString(sizes, s) => {
                        (sizes.clone(), s.to_string().into_bytes())
                    }

                    DecryptSource::ConsoleRaw(sizes, data) => (sizes.clone(), data.clone()),

                    DecryptSource::File(f) => {
                        let mut file = File::options().read(true).open(f)?;
                        if key.accepts_characters() {
                            use super::parse;
                            let mut content = String::new();
                            file.read_to_string(&mut content)?;
                            let (sizes, input) = parse::command_parser::string_data(&content)
                                .map_err(|e| format!("failed to parse input file: {e}"))?;
                            (sizes, input.into_bytes())
                        } else {
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
                    }
                };

                if key.accepts_characters() {
                    let message = key.decrypt_text(data)?;

                    match to {
                        DataTarget::Console => Ok(format!("message: \"{message}\"")),
                        DataTarget::File(f) => {
                            let mut file = File::options().write(true).create(true).open(f)?;
                            file.write_all(message.as_bytes())?;
                            Ok(format!("written {f}"))
                        }
                    }
                } else {
                    let message = key.decrypt_raw(data)?;

                    match to {
                        DataTarget::Console => Ok(format!("message: {}", {
                            if let Ok(msg) = String::from_utf8(message.clone()) {
                                format!("\"{}\"", msg)
                            } else {
                                format!(
                                    "\"{}\" (not all characters were parsed normally)",
                                    String::from_utf8_lossy(&message)
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
            }

            Stmt::Delete(n) => match self.require_database()?.delete(n) {
                Some(_) => Ok(format!("deleted key {n}")),
                None => Err("no such key".into()),
            },

            Stmt::Add {
                name,
                algo_type,
                algos,
            } => {
                let db = self.require_database()?;

                let cypher = {
                    let mut cypher = StackedCypher::new();

                    for algo in algos {
                        let padding = algo.padding;
                        let algo: Algorithm = match &algo.algo_type {
                            AlgorithmType::Permutation(None) => {
                                thread_rng().gen::<SimplePermutation>().into()
                            }

                            AlgorithmType::Permutation(Some(config)) => {
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
                        if padding {
                            cypher.push_padding(algo);
                        } else {
                            cypher.push_unpadding(algo)
                        }
                    }
                    cypher
                };

                let encryption = Encryption::new(cypher, *algo_type);

                Ok(match db.add(name, encryption) {
                    Some(_) => format!("replaced cypher \"{}\"", name),
                    None => format!("added cypher \"{}\"", name),
                })
            }
        }
    }
}
