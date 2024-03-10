use tiny_keccak::{Hasher, Keccak};

pub fn to_eth_addr(pubkey: [u8; 65]) -> String {
    let mut keccak = Keccak::v256();
    let mut address_slice = [0u8; 32];
    keccak.update(&pubkey[1..]);
    keccak.finalize(&mut address_slice);
    let address = hex::encode(&address_slice[12..]);
    address
}
