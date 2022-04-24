use std::{
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
            Ok(ExecResult::Ok(m)) => println!("OK. {}", m),

            Ok(ExecResult::Exit) => break,
            Err(e) => println!("ERROR. {e}"),
        }
    }
}

enum ExecResult {
    Ok(String),
    Exit,
}

fn execute_statement(
    interpreter: &mut Interpreter,
    line: &str,
) -> Result<ExecResult, Box<dyn Error>> {
    use parse::command_parser;

    if line.to_string().to_uppercase() == "EXIT" {
        return Ok(ExecResult::Exit);
    }

    let stmt = command_parser::stmt(line)?;

    interpreter.visit_stmt(&stmt).map(ExecResult::Ok)
}
