use clap::Parser;
use crate::{process_jwt_sign, process_jwt_verify, CmdExecutor};


#[derive(Debug, Parser)]
pub enum JWTSubCommand {
    #[command(about = "Sign a JWT Token")]
    Sign(JWTSignOpts),
    #[command(about = "Verify a JWT Token")]
    Verify(JWTVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JWTSignOpts {
    #[arg(long)]
    sub: String,
    #[arg(long)]
    aud: String,
    #[arg(long)]
    exp: String,
}


#[derive(Debug, Parser)]
pub struct JWTVerifyOpts {
    #[arg(long, short)]
    token: String,
}

impl CmdExecutor for JWTSubCommand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            JWTSubCommand::Sign(opts) => opts.execute().await,
            JWTSubCommand::Verify(opts) => opts.execute().await,
        }
    }
}

impl CmdExecutor for JWTSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_jwt_sign(self.sub, self.aud, self.exp)?;
        println!("{}", token);
        Ok(())
    }
}

impl CmdExecutor for JWTVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        process_jwt_verify(self.token)?;
        Ok(())
    }
}
