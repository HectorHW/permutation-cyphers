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
    Exit,
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
    pub padding: crate::algorithms::stacked::PadApproach,
    pub style: crate::algorithms::stacked::EncryptionStyle,
    pub algo_type: AlgorithmType,
}

pub enum AlgorithmType {
    Permutation(PermutationType),
    RailFence(Option<(usize, usize)>),
    Vertical(Option<(usize, usize, Vec<usize>)>),
}

pub enum PermutationType {
    Generated(usize),
    Manual(Vec<usize>),
}

peg::parser! {

    pub grammar command_parser() for str {

    use crate::algorithms::stacked::{EncryptionStyle, PadApproach};

        rule i(literal: &'static str)
            = input:$([_]*<{literal.len()}>)
            {? if input.eq_ignore_ascii_case(literal) { Ok(()) } else { Err(literal) } }

        rule string() -> String =
            "\"" s:$([^'"']*) "\"" {
                s.to_string()
            }

        pub rule program() -> Vec<Stmt> =
            s: (stmt() ** ";") {s}

        pub rule pick_approach() -> PickApproach =
            i("CREATE") __ {
                PickApproach::Create
            }
            /
            i("LOAD") __ {
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
            add() /
            exit()

        rule database() -> Stmt =
            _ pick: pick_approach()? _ i("DATABASE") __ s:string() _  {Stmt::DatabasePick{
                name:s,
                create: pick.unwrap_or(PickApproach::Any)
            }}

        rule save() -> Stmt =
            _ i("SAVE") _ {Stmt::Save}

        rule reload() -> Stmt =
            _ i("RELOAD") _ {Stmt::Reload}

        rule list() -> Stmt =
            _ i("LIST") _ {Stmt::List}

        rule describe() -> Stmt =
            _ i("DESCRIBE") __ n:string() _ {
                Stmt::Describe(n)
            }

        rule delete() -> Stmt =
            _ i("DELETE") __ n:string() _ {
                Stmt::Delete(n)
            }

        rule encrypt() -> Stmt =
            _ i("ENCRYPT") __ source:encrypt_source() __ i("WITH") __ key:string() _ target:encrypt_target()? _ {
                let target = target.unwrap_or(DataTarget::Console);

                Stmt::Encrypt{
                    from: source, key, to: target }
            }

        rule decrypt() -> Stmt =
        _ i("DECRYPT") __ source:decrypt_source() __ i("WITH") __ key:string() _ target:encrypt_target()? _ {
            let target = target.unwrap_or(DataTarget::Console);

            Stmt::Decrypt{
                    from: source, key, to: target }
        }


        rule add() -> Stmt =
            _ i("ADD") __ n:string() __ i("AS") __ "[" _ a:algorithm()**(_ "," _) _ "]" {
                Stmt::Add{ name: n, algos: a }
            }

        rule exit() -> Stmt =
            _ i("EXIT") _ {
                Stmt::Exit
            }

        rule algorithm() -> AlgorithmDescription =
            pad: pad_style() __ style: encrypt_style() __ desc: algorithm_style() {
                AlgorithmDescription{
                    padding:pad,
                     style,
                    algo_type:desc
                }
            }


        rule algorithm_style() -> AlgorithmType =
            i("PERMUTATION") _ "(" _ i("GENERATED") _ "(" _ size:number() _ ")" _ ")" {
                AlgorithmType::Permutation(PermutationType::Generated(size))
            }/
             i("PERMUTATION") _ "(" _ n:number()++("," _) ","? _ ")" {
                 AlgorithmType::Permutation(PermutationType::Manual(n))
            }/
            i("RAILFENCE") _ "(" _ i("GENERATED") _ ")" {
                 AlgorithmType::RailFence(None)
            }/
            i("RAILFENCE") _ "(" _ a:number() _ "," _ b:number() _ ")" {
                 AlgorithmType::RailFence(Some((a, b)))
            }/
            i("VERTICAL") _ "(" _ i("GENERATED") _ ")" {
                 AlgorithmType::Vertical(None)
            }/
            i("VERTICAL") _ "(" _ a:number() _ "," _ b:number() _ "," _ "[" _ numbers: number()++(_ "," _) _ ","? _ "]" _ ")" {
                AlgorithmType::Vertical(Some((a, b, numbers)))
            }




        rule pad_style() -> PadApproach =
            i("PADDING") {PadApproach::Padding}/
            i("UNPADDING") {PadApproach::Unpadding}

        rule encrypt_style() -> EncryptionStyle =
            i("BIT") {
                EncryptionStyle::Bit
            }/
            i("BYTE") {
                EncryptionStyle::Byte
            }/
            i("CHAR") {
                EncryptionStyle::Char
            }/
            i("GROUP") _ "(" n:number() _ ")" {
                EncryptionStyle::Group(n)
            }


        rule encrypt_source() -> DataSource =
            i("FROM") __ s:string() {
                DataSource::File(s)
            } /
            s: string() {
                DataSource::String(s)
            }

        rule encrypt_target() -> DataTarget =
            i("INTO") __ s:string() {
                DataTarget::File(s)
            }

        rule decrypt_source() -> DecryptSource =
            i("FROM") __ s:string() {
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
