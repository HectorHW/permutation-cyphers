pub enum PickApproach {
    Create,
    Load,
    Any,
}

pub enum Stmt {
    DatabasePick { name: String, create: PickApproach },
    Save,
    List,
    Describe(String),
}
