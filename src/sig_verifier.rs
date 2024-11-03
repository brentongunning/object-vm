use crate::{
    core::{PubKey, Sig, Tx},
    errors::VerifyError,
};

pub trait SigVerifier {
    fn verify(&mut self, pubkey: &PubKey, sig: &Sig, index: usize) -> Result<(), VerifyError>;
}

pub struct SigVerifierImpl<'a> {
    _tx: &'a Tx,
}

impl<'a> SigVerifierImpl<'a> {
    pub fn new(tx: &'a Tx) -> Self {
        Self { _tx: tx }
    }
}

impl<'a> SigVerifier for SigVerifierImpl<'a> {
    fn verify(&mut self, _pubkey: &PubKey, _sig: &Sig, _index: usize) -> Result<(), VerifyError> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Tx;

    #[test]
    #[should_panic]
    fn test_sig_verifier() {
        let tx = Tx {
            version: 1,
            script: vec![0x01, 0x02, 0x03],
        };
        let mut verifier = SigVerifierImpl::new(&tx);
        let pubkey = [0u8; 32];
        let sig = [0u8; 64];
        let index = 0;
        verifier.verify(&pubkey, &sig, index).ok();
    }
}
