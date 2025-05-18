use anyhow::Result;
use chacha20poly1305::KeyInit;
use chrono::{Duration, Utc};
use hmac::Hmac;
use jwt::{Claims, Header, SignWithKey, Token, VerifyWithKey};
use sha2::Sha256;
use std::{collections::BTreeMap};

pub fn process_jwt_sign(sub: String, aud: String, exp: String) -> Result<String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret")?;
    let mut claims = BTreeMap::new();
    let now = Utc::now();
    let exp_duration = Duration::seconds(exp.parse::<i64>()?);
    claims.insert("sub", sub);
    claims.insert("aud", aud);
    claims.insert("iat", now.timestamp().to_string());
    claims.insert("exp", (now + exp_duration).timestamp().to_string());
    
    let token_str = claims.sign_with_key(&key)?;
    println!("{}", token_str);
    Ok(token_str)
}

pub fn process_jwt_verify(token: String) -> Result<()> {
    let key: Hmac<Sha256>  = Hmac::new_from_slice(b"some-secret")?;
    let verified: Result<Token<Header, Claims, _>, _> = token.verify_with_key(&key);
    match verified {
        Ok(data) => {
            println!("Token valid");
            println!("{:#?}", data.claims());
            Ok(())
        }
        Err(e) => {
            eprintln!("Token invalid: {}", e);
            Err(anyhow::anyhow!("Token invalid: {}", e))
        }
    }
}
