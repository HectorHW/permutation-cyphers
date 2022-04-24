pub enum PickApproach {
    Create,
    Load,
    Any,
}

pub enum Stmt {
    DatabasePick {
        name: String,
        create: PickApproach,
    },
    Save,
    List,
    Reload,
    Describe(String),
    Delete(String),
    Encrypt {
        from: DataSource,
        key: String,
        to: DataTarget,
    },
    Decrypt {
        from: DecryptSource,
        key: String,
        to: DataTarget,
    },
}

pub enum DataSource {
    String(String),
    File(String),
}

pub enum DataTarget {
    Console,
    File(String),
}

pub enum DecryptSource {
    ConsoleString(Vec<usize>, String),
    ConsoleRaw(Vec<usize>, Vec<u8>),
    File(String),
}

peg::parser! {
    pub grammar command_parser() for str {

        rule string() -> String =
            "\"" s:$([^'"']*) "\"" {
                s.to_string()
            }

        pub rule program() -> Vec<Stmt> =
            s: (stmt() ** ";") {s}

        pub rule pick_approach() -> PickApproach =
            "CREATE" __ {
                PickApproach::Create
            }
            /
            "LOAD" __ {
                PickApproach::Load
            }

        pub rule stmt() -> Stmt =
            database()/
            save()/
            list() /
            reload() /
            describe() /
            encrypt() /
            decrypt() /
            delete()

        rule database() -> Stmt =
            _ pick: pick_approach()? _ "DATABASE" __ s:string() _  {Stmt::DatabasePick{
                name:s,
                create: pick.unwrap_or(PickApproach::Any)
            }}

        rule save() -> Stmt =
            _ "SAVE" _ {Stmt::Save}

        rule reload() -> Stmt =
            _ "RELOAD" _ {Stmt::Reload}

        rule list() -> Stmt =
            _ "LIST" _ {Stmt::List}

        rule describe() -> Stmt =
            _ "DESCRIBE" __ n:string() _ {
                Stmt::Describe(n)
            }

        rule delete() -> Stmt =
            _ "DELETE" __ n:string() _ {
                Stmt::Delete(n)
            }

        rule encrypt() -> Stmt =
            _ "ENCRYPT" __ source:encrypt_source() __ "WITH" __ key:string() _ target:encrypt_target()? _ {
                let target = target.unwrap_or(DataTarget::Console);

                Stmt::Encrypt{
                    from: source, key, to: target }
            }

        rule decrypt() -> Stmt =
        _ "DECRYPT" __ source:decrypt_source() __ "WITH" __ key:string() _ target:encrypt_target()? _ {
            let target = target.unwrap_or(DataTarget::Console);

            Stmt::Decrypt{
                    from: source, key, to: target }
        }

        rule encrypt_source() -> DataSource =
            "FROM" __ s:string() {
                DataSource::File(s)
            } /
            s: string() {
                DataSource::String(s)
            }

        rule encrypt_target() -> DataTarget =
            "INTO" __ s:string() {
                DataTarget::File(s)
            }

        rule decrypt_source() -> DecryptSource =
            "FROM" __ s:string() {
                DecryptSource::File(s)
            } /

            d:string_data() {
                DecryptSource::ConsoleString(d.0, d.1)
            } /

            d:binary_data() {
                DecryptSource::ConsoleRaw(d.0, d.1)
            }

        pub rule string_data() -> (Vec<usize>, String) =
            "[" n:(number()**", ") "]" " " data:string() {
                (n, data)
            }

        pub rule binary_data() -> (Vec<usize>, Vec<u8>) =
            "[" n:(number()**", ") "]" __ "[" data:(number()**", ") "]" {
                (n, data.into_iter().map(|i| i as u8).collect())
            }


        rule number() -> usize =
            s:['0'..='9']+ {
                s.into_iter().collect::<String>().parse::<usize>().unwrap()
            }

        rule _ = quiet!{[' ' | '\n' | '\t' | '\r']*}
        rule __ = quiet!{[' ' | '\n' | '\t' | '\r']+}
    }
}
