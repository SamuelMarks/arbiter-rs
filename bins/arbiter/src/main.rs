//! Multicall `arbiter` binary entrypoint.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

/// Dispatches `arbiter` based on `argv[0]` or subcommand from `std::env::args()`.
#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    let raw_args: Vec<String> = std::env::args().collect();
    let borrowed: Vec<&str> = raw_args.iter().map(String::as_str).collect();
    match arbiter::dispatch_multicall(&borrowed) {
        Ok(target) => {
            println!("{}", target.execute_target());
            std::process::ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::ExitCode::from(2)
        }
    }
}
