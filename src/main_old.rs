#![allow(unused_imports)]
#![allow(dead_code)]
use std::str::FromStr;

use anyhow::*;
use bip32::{DerivationPath, Prefix, Seed, XPrv};
use bip39::{Language, Mnemonic};
use hex::{decode, encode};
use libsecp256k1::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use ring::pbkdf2;
use std::num::NonZeroU32;
use tiny_keccak::{Hasher, Keccak};

fn keccak_hash(input: [u8; 65]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut address_slice = [0u8; 32];
    keccak.update(&input[1..]);
    keccak.finalize(&mut address_slice);
    address_slice
}

fn calculate_seed_from_phrase(mnemonic: &str, passphrase: &str) -> String {
    let mnemonic_norm = unidecode::unidecode(mnemonic);
    let salt = format!("mnemonic{}", passphrase);

    let mut seed = [0u8; 64]; // 512 bits

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(2048).unwrap(),
        salt.as_bytes(),
        mnemonic_norm.as_bytes(),
        &mut seed,
    );

    hex::encode(seed)
}

fn eth_from_secret() -> Result<()> {
    let secret_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let secret_bytes = &decode(secret_hex)?;
    let secret_key = SecretKey::parse_slice(secret_bytes)?;
    let public_key = PublicKey::from_secret_key(&secret_key);
    let public_bytes = public_key.serialize();

    println!("Public Key: {:?}", encode(public_bytes));

    let public_hash = keccak_hash(public_bytes);
    let last_20_bytes = &public_hash[12..];
    let address_hex = encode(last_20_bytes);

    println!("Address: {}", address_hex);

    assert_eq!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266", address_hex);

    Ok(())
}

fn eth_from_mnemonic(phrase: &str) -> Result<()> {
    // Hardhat's generative phrase
    // let mnemonic_phrase = "test test test test test test test test test test test junk";
    let mnemonic = Mnemonic::from_str(phrase).expect("Error creating mnemonic");
    let seed = mnemonic.to_seed(""); // hardhat doesn't use a password
    println!("Seed: {}", hex::encode(&seed));
    let root_key = XPrv::new(&seed)?;

    println!("Root: {}", root_key.to_extended_key(Prefix::XPRV));

    for i in 0..9 {
        let path = DerivationPath::from_str(&format!("m/44'/60'/0'/0/{}", i))?;
        let xprv = XPrv::derive_from_path(&seed, &path)?;
        let private_key = xprv.private_key().to_bytes();
        let secret_key = SecretKey::parse_slice(&private_key)?;

        let public_key = PublicKey::from_secret_key(&secret_key);

        // Get the keccak hash of the address
        let mut keccak = Keccak::v256();
        let mut address_slice = [0u8; 32];
        keccak.update(&public_key.serialize()[1..]);
        keccak.finalize(&mut address_slice);

        // Take the last 20 bytes from the address
        let address = hex::encode(&address_slice[12..]);
        println!("Address: {:?}", address);
    }

    Ok(())
}

fn main() -> Result<()> {
    let phrase = "hill goose clean talent day glove all found barrel edge belt bag";
    // eth_from_secret()?;
    eth_from_mnemonic(&phrase)?;
    // let seed = calculate_seed_from_phrase(&phrase, "");
    // println!("{}", seed);
    Ok(())
}
