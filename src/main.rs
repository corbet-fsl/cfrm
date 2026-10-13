//! Native service composition. Domain decisions remain in the original owners.
#[cfg(not(target_arch = "wasm32"))]
mod serve;

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    use clap::Parser;
    if serve::run(serve::Arguments::parse()).await.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        // Config paths, credentials, member values and request diagnostics stay private.
        eprintln!("forum service unavailable");
        std::process::ExitCode::FAILURE
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}
