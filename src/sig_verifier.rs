use crate::{
    core::{PubKey, Sig},
    errors::VerifyError,
};

pub trait SigVerifier {
    fn verify(&mut self, pubkey: &PubKey, sig: &Sig, index: usize) -> Result<(), VerifyError>;
}
