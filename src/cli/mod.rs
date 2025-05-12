use std::{ops::Sub, path::{Path, PathBuf}};

pub use base64::Base64SubCommand;
use clap::Parser;
use csv::CsvOpts;
use genpass::GenPassOpts;
mod base64;
mod csv;
mod genpass;
mod http;
mod text;

use crate::CmdExecutor;

pub use self::csv::OutputFormat;
pub use base64::Base64Format;
pub use http::HttpSubCommand;
pub use text::{TextSignFormat, TextSubCommand};

#[derive(Debug, Parser)]
#[command(name="rcli", version, author, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or convert to CSV to other formats")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand)]
    Base64(Base64SubCommand),
    #[command(subcommand)]
    Text(TextSubCommand),
    #[command(subcommand)]
    Http(HttpSubCommand),
}

impl CmdExecutor for SubCommand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            Self::Csv(opts) => opts.execute().await,
            Self::GenPass(opts) => opts.execute().await,
            Self::Base64(opts) => opts.execute().await,
            Self::Text(opts) => opts.execute().await,
            Self::Http(opts) => opts.execute().await
        }
    }
}

fn verify_file(filename: &str) -> Result<String, &'static str> {
    // if input is "-" or file exists
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("Path does not exist or is not a directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_file() {
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("*"), Err("File does not exist"));
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("non-exist"), Err("File does not exist"));
    }
}
