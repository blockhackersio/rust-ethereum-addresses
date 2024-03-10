mod utils;

use anyhow::*;
use bip32::{ChildNumber, DerivationPath, XPrv};
use bip39::Mnemonic;
use libsecp256k1::PublicKey;
use std::str::FromStr;

use crate::utils::to_eth_addr;

fn main() -> Result<()> {
    let phrase = "hill goose clean talent day glove all found barrel edge belt bag";
    let seed = Mnemonic::from_str(phrase)?.to_seed("");
    let xprv = XPrv::derive_from_path(&seed, &DerivationPath::from_str("m/44'/60'/0'/0")?)?;
    let xpub = xprv.public_key();

    for i in 0..9 {
        let child = xpub.derive_child(ChildNumber(i))?;
        let pubkey = PublicKey::parse_slice(&child.to_bytes(), None)?;
        let address = to_eth_addr(pubkey.serialize());
        println!("m/44'/60'/0'/0/{}:\t0x{}", i, address);
    }

    Ok(())
}
