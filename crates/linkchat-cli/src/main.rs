#[path = "modules/commands.rs"]
mod commands;
#[path = "modules/encoding.rs"]
mod encoding;
#[path = "modules/errors.rs"]
mod errors;

use std::env;
use std::process::ExitCode;

use commands::run;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
