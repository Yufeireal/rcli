use std::{collections::HashMap, io::Read};

use anyhow::{Ok, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{ed25519::signature::SignerMut, Signature, SigningKey, VerifyingKey};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use rand::{rngs::OsRng, RngCore};

use crate::TextSignFormat;

use super::process_genpass;

pub trait TextSigner {
    // signer could sign any input data
    fn sign(&mut self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub struct Blake3 {
    key: [u8; 32],
}
pub struct Edd25519Signer {
    key: SigningKey,
}

pub struct Edd25519Verifier {
    key: VerifyingKey,
}

impl TextSigner for Blake3 {
    fn sign(&mut self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Edd25519Signer {
    fn sign(&mut self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerifier for Edd25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let signature = Signature::from_bytes(sig);
        Ok(self.key.verify_strict(&buf, &signature).is_ok())
    }
}

impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Edd25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }
    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let sk: SigningKey = SigningKey::generate(&mut OsRng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.to_bytes().to_vec());
        map.insert("ed25519.pk", pk.to_bytes().to_vec());
        Ok(map)
    }
}

impl Edd25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

fn get_key(key: &str) -> Result<Key> {
    let mut key_bytes = [0u8; 32];
    let key_raw = key.as_bytes();
    if key_raw.len() != 32 {
        return Err(anyhow::anyhow!("Key must be exactly 32 bytes long"));
    }
    key_bytes.copy_from_slice(key_raw);
    Ok(Key::from_slice(&key_bytes).clone())
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8], // (ptr, length
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let mut signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Edd25519Signer::try_new(key)?),
    };
    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Edd25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Edd25519Signer::generate(),
    }
}

pub fn process_text_encrypt(reader: &mut dyn Read, key: &str) -> Result<Vec<u8>> {
    let key = get_key(key)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    let cipher = ChaCha20Poly1305::new(&key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, buf.as_slice()).unwrap();
    let mut ret = Vec::new();
    ret.extend_from_slice(nonce_bytes.as_slice());
    ret.extend_from_slice(&ciphertext);
    Ok(ret)
}

pub fn process_text_decrypt(reader: &mut dyn Read, key: &str) -> Result<Vec<u8>> {
    let key = get_key(key)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    let decoded = BASE64_URL_SAFE_NO_PAD.decode(&buf)?;
    print!("asdfasdfasfasdf");
    let (nonce_bytes, ciphertext) = decoded.split_at(12);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("chacha20poly1305 decrypt error: {:?}", e))?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");
    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }
    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = "33Ypo4rveYpWmJKAiGnnse-wHQhMVujjmcVkV4Tl43k";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }
}
