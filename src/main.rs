// SPDX-License-Identifier: GPL-3.0-only

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match terraris::app::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("terraris: {error}");
            ExitCode::FAILURE
        }
    }
}
