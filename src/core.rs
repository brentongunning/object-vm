pub const ID_LEN: usize = 32;
pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

pub type PubKey = [u8; PUBKEY_LEN];
pub type Sig = [u8; SIG_LEN];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u8,
    pub script: Vec<u8>,
}
