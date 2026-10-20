//! Standalone `arbiter-cli` binary entrypoint.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

/// Executes `arbiter-cli` using command-line arguments from `std::env::args()`.
#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = raw_args.iter().map(String::as_str).collect();
    let (code, msg) = arbiter_cli::run_cli_main(&borrowed);
    if code.is_success() {
        println!("{msg}");
    } else {
        eprintln!("{msg}");
    }
    std::process::ExitCode::from(u8::try_from(code.get()).unwrap_or(1))
}
