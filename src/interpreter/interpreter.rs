use std::error::Error;

use crate::{
    algorithms::{
        stacked::{Algorithm, PadApproach},
        Encryption,
    },
    database::Database,
};

use super::ast::Stmt;

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
                    super::ast::PickApproach::Create => {
                        file = file.create_new(true);
                    }
                    super::ast::PickApproach::Load => file = file.create(false),
                    super::ast::PickApproach::Any => file = file.create(true),
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
        }
    }
}
