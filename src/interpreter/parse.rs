use crate::algorithms::EncryptionStyle;

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
    Add {
        name: String,
        algo_type: EncryptionStyle,
        algos: Vec<AlgorithmDescription>,
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

pub struct AlgorithmDescription {
    pub padding: bool,
    pub algo_type: AlgorithmType,
}

pub enum AlgorithmType {
    Permutation(Option<Vec<usize>>),
    RailFence(Option<(usize, usize)>),
    Vertical(Option<(usize, usize, Vec<usize>)>),
}

peg::parser! {

    pub grammar command_parser() for str {

use crate::algorithms::EncryptionStyle;


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
            delete() /
            add()

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


        rule add() -> Stmt =
            _ "ADD" __ n:string() __ "AS" __ style:encrypt_style() __ "ALGORITHMS" __ "[" _ a:algorithm()**(_ "," _) _ "]" {
                Stmt::Add{ name: n, algo_type: style, algos: a }
            }

        rule algorithm() -> AlgorithmDescription =
            style:pad_style() __ "PERMUTATION" _ "(" _ "GENERATED" _ ")" {
                AlgorithmDescription{
                    padding: style, algo_type: AlgorithmType::Permutation(None) }
            }/
            style:pad_style() __ "PERMUTATION" _ "(" _ n:number()++("," _) ","? _ ")" {
                AlgorithmDescription{
                    padding: style, algo_type: AlgorithmType::Permutation(Some(n)) }
            }/
            style:pad_style() __ "RAILFENCE" _ "(" _ "GENERATED" _ ")" {
                AlgorithmDescription{padding:style,
                    algo_type: AlgorithmType::RailFence(None) }
            }/
            style:pad_style() __ "RAILFENCE" _ "(" _ a:number() _ "," _ b:number() _ ")" {
                AlgorithmDescription{padding:style,
                    algo_type: AlgorithmType::RailFence(Some((a, b))) }
            }/
            style:pad_style() __ "VERTICAL" _ "(" _ "GENERATED" _ ")" {
                AlgorithmDescription{padding:style,
                    algo_type: AlgorithmType::Vertical(None) }
            }/
            style:pad_style() __ "VERTICAL" _ "(" _ a:number() _ "," _ b:number() _ "," _ "[" _ numbers: number()++(_ "," _) _ ","? _ "]" _ ")" {
                AlgorithmDescription{padding:style,
                    algo_type: AlgorithmType::Vertical(Some((a, b, numbers))) }
            }




        rule pad_style() -> bool =
            "PADDING" {true}/
            "UNPADDING" {false}

        rule encrypt_style() -> EncryptionStyle =
            "BIT" {
                EncryptionStyle::Bit
            }/
            "BYTE" {
                EncryptionStyle::Byte
            }/
            "CHAR" {
                EncryptionStyle::Char
            }/
            "GROUP" _ "(" n:number() _ ")" {
                EncryptionStyle::Group(n)
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

        rule number_vector() -> Vec<usize> =
            "[" n:number()**__ "]" {
                n
            }

        rule number() -> usize =
            s:['0'..='9']+ {
                s.into_iter().collect::<String>().parse::<usize>().unwrap()
            }

        rule _ = quiet!{[' ' | '\n' | '\t' | '\r']*}
        rule __ = quiet!{[' ' | '\n' | '\t' | '\r']+}
    }
}
