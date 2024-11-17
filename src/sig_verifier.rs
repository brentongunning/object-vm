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
    tx: &'a Tx,
}

impl<'a> SigVerifierImpl<'a> {
    pub fn new(tx: &'a Tx) -> Self {
        Self { tx }
    }
}

impl<'a> SigVerifier for SigVerifierImpl<'a> {
    fn verify(&mut self, pubkey: &PubKey, sig: &Sig, index: usize) -> Result<(), VerifyError> {
        let sighash = sighash(self.tx, index)?;

        let ed25519_public_key = ed25519_dalek_blake3::PublicKey::from_bytes(pubkey)
            .map_err(|_| VerifyError::BadPubKey)?;

        let ed25519_signature = ed25519_dalek_blake3::Signature::from_bytes(sig)
            .map_err(|_| VerifyError::BadSignature)?;

        ed25519_public_key
            .verify_strict(&sighash, &ed25519_signature)
            .map_err(|_| VerifyError::BadSignature)?;

        Ok(())
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
    use crate::core::{Id, ReadWrite, Tx};

    #[test]
    fn verify_sign() {
        use super::sighash;
        use ed25519_dalek_blake3::{Keypair, Signer};
        let mut csprng = rand::rngs::OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let pubkey = keypair.public.to_bytes();
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_0]);
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&pubkey);
        tx.script.extend_from_slice(&[0; SIG_LEN]);
        tx.script.extend_from_slice(&[OP_1]);
        let msg = sighash(&tx, 1).unwrap();
        let sig = keypair.sign(&msg);
        let sig_start = 2 + PUBKEY_LEN;
        let sig_end = sig_start + SIG_LEN;
        tx.script[sig_start..sig_end].copy_from_slice(&sig.to_bytes());
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(sig_verifier.verify(&pubkey, &sig.to_bytes(), 1).is_ok());
    }

    #[test]
    fn verify_signto() {
        use super::sighash;
        use ed25519_dalek_blake3::{Keypair, Signer};
        let mut csprng = rand::rngs::OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let pubkey = keypair.public.to_bytes();
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_0]);
        tx.script.extend_from_slice(&[OP_SIGNTO]);
        tx.script.extend_from_slice(&pubkey);
        tx.script.extend_from_slice(&[0; SIG_LEN]);
        tx.script.extend_from_slice(&[OP_1]);
        let msg = sighash(&tx, 1).unwrap();
        let sig = keypair.sign(&msg);
        let sig_start = 2 + PUBKEY_LEN;
        let sig_end = sig_start + SIG_LEN;
        tx.script[sig_start..sig_end].copy_from_slice(&sig.to_bytes());
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(sig_verifier.verify(&pubkey, &sig.to_bytes(), 1).is_ok());
    }

    #[test]
    fn verify_multiple() {
        use super::sighash;
        use ed25519_dalek_blake3::{Keypair, Signer};
        let mut csprng = rand::rngs::OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let pubkey = keypair.public.to_bytes();
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_0]);
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&pubkey);
        tx.script.extend_from_slice(&[0; SIG_LEN]);
        tx.script.extend_from_slice(&[OP_1]);
        tx.script.extend_from_slice(&[OP_SIGNTO]);
        tx.script.extend_from_slice(&pubkey);
        tx.script.extend_from_slice(&[0; SIG_LEN]);
        tx.script.extend_from_slice(&[OP_2]);
        let msg = sighash(&tx, 1).unwrap();
        let sig = keypair.sign(&msg);
        let sig_start = 2 + PUBKEY_LEN;
        let sig_end = sig_start + SIG_LEN;
        tx.script[sig_start..sig_end].copy_from_slice(&sig.to_bytes());
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(sig_verifier.verify(&pubkey, &sig.to_bytes(), 1).is_ok());
        let index = 3 + PUBKEY_LEN + SIG_LEN;
        let msg = sighash(&tx, index).unwrap();
        let sig = keypair.sign(&msg);
        let sig_start = 4 + PUBKEY_LEN * 2 + SIG_LEN;
        let sig_end = sig_start + SIG_LEN;
        tx.script[sig_start..sig_end].copy_from_slice(&sig.to_bytes());
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(sig_verifier.verify(&pubkey, &sig.to_bytes(), index).is_ok());
    }

    #[test]
    fn verify_bad_index() {
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_0]);
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(matches!(
            sig_verifier.verify(&[0; PUBKEY_LEN], &[0; SIG_LEN], 0),
            Err(VerifyError::BadIndex)
        ));
    }

    #[test]
    fn verify_unexpected_end_of_script() {
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(matches!(
            sig_verifier.verify(&[0; PUBKEY_LEN], &[0; SIG_LEN], 0),
            Err(VerifyError::Script(ScriptError::UnexpectedEndOfScript))
        ));
    }

    #[test]
    fn verify_bad_pubkey() {
        let mut bad_pubkey = [0; PUBKEY_LEN];
        bad_pubkey[PUBKEY_LEN - 1] = 1;
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&bad_pubkey);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(matches!(
            sig_verifier.verify(&bad_pubkey, &[0; SIG_LEN], 0),
            Err(VerifyError::BadPubKey)
        ));
    }

    #[test]
    fn verify_bad_signature() {
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(matches!(
            sig_verifier.verify(&[1; PUBKEY_LEN], &[255; SIG_LEN], 0),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn verify_invalid_signature() {
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&[1; PUBKEY_LEN]);
        tx.script.extend_from_slice(&[2; SIG_LEN]);
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(matches!(
            sig_verifier.verify(&[1; PUBKEY_LEN], &[0; SIG_LEN], 0),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn verify_fixed() {
        let pubkey = "dc4cfabc05ca45762bc958ae223e1f5f7130bf86cea27de7eac527810ebc3e91";
        let sig = "467039ef938d5e2fbcd0487a95dfc4c63ddbe4736b93baabd7fdd4f66d40c29fdd8c16534f0e369e134fb38e2ba3a6cd4d621be16b2d3ab6fbcbd236c4479408";
        use ed25519_dalek_blake3::{PublicKey, Signature};
        let pubkey = hex::decode(pubkey).unwrap();
        let pubkey = PublicKey::from_bytes(&pubkey).unwrap();
        let sig = hex::decode(sig).unwrap();
        let sig = Signature::from_bytes(&sig).unwrap();
        let mut tx = Tx::default();
        tx.script.extend_from_slice(&[OP_0]);
        tx.script.extend_from_slice(&[OP_SIGN]);
        tx.script.extend_from_slice(&pubkey.to_bytes());
        tx.script.extend_from_slice(&[0; SIG_LEN]);
        tx.script.extend_from_slice(&[OP_1]);
        let sig_start = 2 + PUBKEY_LEN;
        let sig_end = sig_start + SIG_LEN;
        tx.script[sig_start..sig_end].copy_from_slice(&sig.to_bytes());
        let mut sig_verifier = SigVerifierImpl::new(&tx);
        assert!(sig_verifier
            .verify(&pubkey.to_bytes(), &sig.to_bytes(), 1)
            .is_ok());
    }

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
        let expected: Id = blake3::hash(&tx2.to_vec()).into();
        assert_eq!(sighash(&tx, 0).unwrap(), expected);
        let s = "63786c7448592ce7f832ef6d916eed52302ebc58404fd34d6e239c8548d8f93c";
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
