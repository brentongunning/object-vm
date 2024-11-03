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

    let mut sign_tx = tx.clone();

    match opcode {
        OP_SIGN => {}
        OP_SIGNTO => sign_tx.script.truncate(index + 1 + PUBKEY_LEN + SIG_LEN),
        _ => return Err(VerifyError::BadIndex),
    }

    clear_sigs(&mut sign_tx.script)?;

    Ok(sign_tx.id())
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
    use crate::core::{blake3d, ReadWrite, Tx};

    #[test]
    fn sighash() {
        use super::sighash;
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_0]);
        assert!(matches!(sighash(&tx, 0), Err(VerifyError::BadIndex)));
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        tx.script.extend_from_slice(&[OP_SIGNTO]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        let mut tx2 = Tx::default();
        tx2.script.extend_from_slice(&[OP_SIGN]);
        tx2.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx2.script.extend_from_slice(&[0; SIG_LEN]);
        tx2.script.extend_from_slice(&[OP_SIGNTO]);
        tx2.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx2.script.extend_from_slice(&[0; SIG_LEN]);
        assert_eq!(sighash(&tx, 0).unwrap(), tx2.id());
        assert_eq!(sighash(&tx, 97).unwrap(), tx2.id());
        assert!(matches!(sighash(&tx, 98), Err(VerifyError::BadIndex)));
        assert!(matches!(sighash(&tx, 255), Err(VerifyError::BadIndex)));
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_0]);
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        tx.script.extend_from_slice(&[OP_1]);
        let mut tx2 = Tx::default();
        tx2.script.extend_from_slice(&[OP_0]);
        tx2.script.extend_from_slice(&[OP_SIGN]);
        tx2.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx2.script.extend_from_slice(&[0; SIG_LEN]);
        tx2.script.extend_from_slice(&[OP_1]);
        assert_eq!(sighash(&tx, 1).unwrap(), tx2.id());
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_0]);
        tx.script.extend_from_slice(&[OP_SIGNTO]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        tx.script.extend_from_slice(&[OP_1]);
        let mut tx2 = Tx::default();
        tx2.script.extend_from_slice(&[OP_0]);
        tx2.script.extend_from_slice(&[OP_SIGNTO]);
        tx2.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx2.script.extend_from_slice(&[0; SIG_LEN]);
        assert_eq!(sighash(&tx, 1).unwrap(), tx2.id());
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_SIGNTO]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN - 1]);
        let h = sighash(&tx, 0);
        assert!(matches!(
            h,
            Err(VerifyError::Script(ScriptError::UnexpectedEndOfScript))
        ));
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        tx.script.extend_from_slice(&[255]);
        let h = sighash(&tx, 0);
        assert!(matches!(
            h,
            Err(VerifyError::Script(ScriptError::BadOpcode))
        ));
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        let mut tx2 = Tx::default();
        tx2.script.extend_from_slice(&[OP_SIGN]);
        tx2.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx2.script.extend_from_slice(&[0; SIG_LEN]);
        assert_eq!(sighash(&tx, 0).unwrap(), blake3d(&tx2.to_vec()));
        let s = "0577959c0cb4de5242e4db8c750e1c418acea4850e59b479e263b29838bfba98";
        let h = sighash(&tx, 0).unwrap();
        assert_eq!(h.as_slice(), &hex::decode(s).unwrap());
    }

    #[test]
    fn clear_sigs() {
        use super::clear_sigs;
        let mut v = vec![];
        clear_sigs(&mut v).unwrap();
        let mut v = vec![OP_1, OP_IF, OP_DUP, OP_BLAKE3];
        let w = vec![OP_1, OP_IF, OP_DUP, OP_BLAKE3];
        clear_sigs(&mut v).unwrap();
        assert_eq!(v, w);
        let mut v = [vec![OP_SIGN], vec![1; PUBKEY_LEN], vec![2; SIG_LEN]].concat();
        let w = [vec![OP_SIGN], vec![1; PUBKEY_LEN], vec![0; SIG_LEN]].concat();
        clear_sigs(&mut v).unwrap();
        assert_eq!(v, w);
        let mut v = [
            vec![OP_SIGN],
            vec![1; PUBKEY_LEN],
            vec![2; SIG_LEN],
            vec![OP_SIGNTO],
            vec![1; PUBKEY_LEN],
            vec![2; SIG_LEN],
        ]
        .concat();
        let w = [
            vec![OP_SIGN],
            vec![1; PUBKEY_LEN],
            vec![0; SIG_LEN],
            vec![OP_SIGNTO],
            vec![1; PUBKEY_LEN],
            vec![0; SIG_LEN],
        ]
        .concat();
        clear_sigs(&mut v).unwrap();
        assert_eq!(v, w);
        let mut v = [
            vec![OP_0],
            vec![OP_SIGN],
            vec![1; PUBKEY_LEN],
            vec![2; SIG_LEN],
            vec![OP_IF],
            vec![OP_SIGNTO],
            vec![1; PUBKEY_LEN],
            vec![2; SIG_LEN],
            vec![OP_ENDIF],
        ]
        .concat();
        let w = [
            vec![OP_0],
            vec![OP_SIGN],
            vec![1; PUBKEY_LEN],
            vec![0; SIG_LEN],
            vec![OP_IF],
            vec![OP_SIGNTO],
            vec![1; PUBKEY_LEN],
            vec![0; SIG_LEN],
            vec![OP_ENDIF],
        ]
        .concat();
        clear_sigs(&mut v).unwrap();
        assert_eq!(v, w);
        let mut v = [vec![OP_SIGN], vec![1; PUBKEY_LEN], vec![2; SIG_LEN - 1]].concat();
        assert!(matches!(
            clear_sigs(&mut v),
            Err(ScriptError::UnexpectedEndOfScript)
        ));
        let mut v = vec![161];
        assert!(matches!(clear_sigs(&mut v), Err(ScriptError::BadOpcode)));
    }
}
