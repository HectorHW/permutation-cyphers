peg::parser! {
    pub grammar command_parser() for str {
        use super::super::ast::*;

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
            _ pick: pick_approach()? _ "DATABASE" __ s:string() _  {Stmt::DatabasePick{
                name:s,
                create: pick.unwrap_or(PickApproach::Any)
            }} /
            _ "SAVE" _ {Stmt::Save} /

            _ "LIST" _ {Stmt::List} /

            _ "DESCRIBE" __ n:string() _ {
                Stmt::Describe(n)
            }

        rule _ = quiet!{[' ' | '\n' | '\t' | '\r']*}
        rule __ = quiet!{[' ' | '\n' | '\t' | '\r']+}
    }
}
