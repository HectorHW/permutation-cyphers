use std::{
    env,
    error::Error,
    io::{stdin, BufRead},
};

use interpreter::{interpreter::Interpreter, parse};

mod algorithms;
mod database;
mod datastructs;
mod interpreter;

#[cfg(test)]
mod tests;
fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 1 {
        run_repl();
    } else if args.len() == 2 {
        let filename = args.get(1).unwrap();
        run_file(filename).unwrap();
    } else {
        panic!("please provide 0 or 1 argument")
    }
}

fn run_file(filename: &str) -> Result<(), Box<dyn Error>> {
    use parse::command_parser;

    let file_content = std::fs::read_to_string(filename)?;

    let program = command_parser::program(&file_content).map_err(|e| {
        chic::Error::new(format!("parse error: expected {}", e.expected))
            .error(
                e.location.line,
                e.location.column,
                e.location.column + 1,
                file_content,
                "",
            )
            .to_string()
    })?;

    let mut interpreter = Interpreter::new();

    for stmt in program {
        println!(
            "{}",
            match interpreter.visit_stmt(&stmt)? {
                ExecResult::Message(s) => s,
                ExecResult::Exit => return Ok(()),
            }
        )
    }

    Ok(())
}

fn run_repl() {
    let mut interpreter = Interpreter::new();

    let stdin = stdin();
    let mut stdin = stdin.lock();

    let mut buffer = String::new();

    loop {
        buffer.clear();
        stdin
            .read_line(&mut buffer)
            .expect("error while reading from stdin");
        buffer = buffer.trim_end_matches(char::is_whitespace).to_string();
        match execute_statement(&mut interpreter, &buffer) {
            Ok(ExecResult::Message(m)) => println!("OK. {}", m),

            Ok(ExecResult::Exit) => break,
            Err(e) => println!("ERROR. {e}"),
        }
    }
}

pub enum ExecResult {
    Message(String),
    Exit,
}

fn execute_statement(
    interpreter: &mut Interpreter,
    line: &str,
) -> Result<ExecResult, Box<dyn Error>> {
    use parse::command_parser;

    let stmt = command_parser::stmt(line).map_err(|e| {
        chic::Error::new(format!("parse error: expected {}", e.expected))
            .error(
                e.location.line,
                e.location.column,
                e.location.column + 1,
                line,
                "",
            )
            .to_string()
    })?;

    interpreter.visit_stmt(&stmt)
}
