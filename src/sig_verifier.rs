use crate::{
    core::{Hash, PubKey, Sig, Tx, PUBKEY_LEN, SIG_LEN},
    errors::{ScriptError, VerifyError},
    opcodes::*,
    script::skip_op,
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

fn sighash(tx: &Tx, index: usize) -> Result<Hash, VerifyError> {
    let opcode = *tx.script.get(index).ok_or(VerifyError::BadIndex)?;

    let mut tx = tx.clone();

    match opcode {
        OP_SIGN => {}
        OP_SIGNTO => tx.script.truncate(index + 1 + PUBKEY_LEN + SIG_LEN),
        _ => return Err(VerifyError::BadIndex),
    }

    clear_sigs(&mut tx.script)?;

    Ok(tx.id())
}

fn clear_sigs(script: &mut [u8]) -> Result<(), ScriptError> {
    let mut i = 0;
    while i < script.len() {
        let next = skip_op(script, i)?;
        if script[i] == OP_SIGN || script[i] == OP_SIGNTO {
            script[i + 1 + PUBKEY_LEN..next].fill(0);
        }
        i = next;
    }
    Ok(())
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
