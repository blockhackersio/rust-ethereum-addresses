#![allow(unused_imports)]
#![allow(dead_code)]
use std::str::FromStr;

use anyhow::*;
use bip32::{DerivationPath, Seed, XPrv};
use bip39::{Language, Mnemonic};
use libsecp256k1::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use tiny_keccak::{Hasher, Keccak};

fn eth_from_secret() -> Result<()> {
    println!("Generating an Ethereum address");

    // Hard hat secret key and public address
    let hh_secret = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let hh_address = "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_lowercase();

    // Use the secp256k1 lib to generate a public key
    let key_bytes = &hex::decode(hh_secret).unwrap();
    let secret_key = SecretKey::parse_slice(key_bytes)?;
    let public_key = PublicKey::from_secret_key(&secret_key);
    println!("Public Key: {:?}", hex::encode(public_key.serialize()));

    // Get the keccak hash of the address
    let mut keccak = Keccak::v256();
    let mut address_slice = [0u8; 32];
    keccak.update(&public_key.serialize()[1..]);
    keccak.finalize(&mut address_slice);

    // Take the last 20 bytes from the address
    let address = hex::encode(&address_slice[12..]);
    println!("Address: {:?}", address);

    // Addresses match
    assert_eq!(hh_address, address);

    Ok(())
}

fn eth_from_mnemonic() -> Result<()> {
    // Hardhat's generative phrase
    let mnemonic_phrase = "test test test test test test test test test test test junk";
    let mnemonic = Mnemonic::from_str(mnemonic_phrase).expect("Error creating mnemonic");
    let seed = mnemonic.to_seed(""); // hardhat doesn't use a password

    for i in 0..9 {
        let path = DerivationPath::from_str(&format!("m/44'/60'/0'/0/{}", i)).unwrap();
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
    // eth_from_secret()?;
    eth_from_mnemonic()?;
    Ok(())
}
