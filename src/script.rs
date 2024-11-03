use crate::{
    core::{ID_LEN, PUBKEY_LEN, SIG_LEN},
    errors::ScriptError,
    opcodes::*,
};

pub fn skip_branch(script: &[u8], mut i: usize) -> Result<usize, ScriptError> {
    let mut sub = 0;
    while i < script.len() {
        match script[i] {
            OP_IF => sub += 1,
            OP_ELSE => {
                if sub == 0 {
                    return Ok(i);
                }
            }
            OP_ENDIF => {
                if sub == 0 {
                    return Ok(i);
                }
                sub -= 1;
            }
            _ => {}
        }
        i = skip_op(script, i)?;
    }
    Err(ScriptError::BadConditional)
}

pub fn skip_op(script: &[u8], mut i: usize) -> Result<usize, ScriptError> {
    let opcode = *script.get(i).ok_or(ScriptError::UnexpectedEndOfScript)?;

    i += 1;

    if opcode > 155 {
        return Err(ScriptError::BadOpcode);
    }

    let advance = |len: usize| {
        if i + len > script.len() {
            return Err(ScriptError::UnexpectedEndOfScript);
        }
        Ok(i + len)
    };

    match opcode {
        1..=75 => advance(opcode as usize),
        OP_PUSHDATA1 => {
            advance(1)?;
            let len = script[i] as usize;
            advance(1 + len)
        }
        OP_PUSHDATA2 => {
            advance(2)?;
            let len = u16::from_le_bytes(script[i..i + 2].try_into().unwrap()) as usize;
            advance(2 + len)
        }
        OP_PUSHDATA4 => {
            advance(4)?;
            let len = u32::from_le_bytes(script[i..i + 4].try_into().unwrap()) as usize;
            advance(4 + len)
        }
        OP_SIGN | OP_SIGNTO => advance(PUBKEY_LEN + SIG_LEN),
        OP_UNIQUIFIER => advance(ID_LEN),
        _ => Ok(i),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_branch() {
        use super::skip_branch;
        let r = skip_branch(&[], 0);
        assert!(matches!(r, Err(ScriptError::BadConditional)));
        let r = skip_branch(&[], 1);
        assert!(matches!(r, Err(ScriptError::BadConditional)));
        assert_eq!(skip_branch(&[OP_ELSE], 0).unwrap(), 0);
        assert_eq!(skip_branch(&[OP_ENDIF], 0).unwrap(), 0);
        assert_eq!(skip_branch(&[OP_0, OP_ELSE], 0).unwrap(), 1);
        assert_eq!(skip_branch(&[OP_DUP, OP_ENDIF], 0).unwrap(), 1);
        let v = [OP_IF, OP_ELSE, OP_ENDIF];
        let r = skip_branch(&v, 0);
        assert!(matches!(r, Err(ScriptError::BadConditional)));
        assert_eq!(skip_branch(&[OP_IF, OP_ELSE, OP_ENDIF], 1).unwrap(), 1);
        assert_eq!(skip_branch(&[OP_IF, OP_ELSE, OP_ENDIF], 2).unwrap(), 2);
        let v = [OP_0, OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF, OP_3];
        let r = skip_branch(&v, 0);
        assert!(matches!(r, Err(ScriptError::BadConditional)));
        let r = skip_branch(&v, 1);
        assert!(matches!(r, Err(ScriptError::BadConditional)));
        assert_eq!(skip_branch(&v, 2).unwrap(), 3);
        assert_eq!(skip_branch(&v, 4).unwrap(), 5);
        let r = skip_branch(&v, 6);
        assert!(matches!(r, Err(ScriptError::BadConditional)));
        assert_eq!(skip_branch(&[OP_IF, OP_ENDIF, OP_ELSE], 0).unwrap(), 2);
        let r = skip_branch(&[OP_IF, OP_ELSE, OP_ENDIF, OP_ELSE], 0);
        assert_eq!(r.unwrap(), 3);
        let v = [OP_IF, OP_IF, OP_ENDIF, OP_ENDIF, OP_ELSE];
        assert_eq!(skip_branch(&v, 0).unwrap(), 4);
        assert_eq!(skip_branch(&[OP_IF, OP_ENDIF, OP_ENDIF], 0).unwrap(), 2);
        let v = [OP_IF, OP_ENDIF, OP_IF, OP_ENDIF, OP_ELSE];
        assert_eq!(skip_branch(&v, 0).unwrap(), 4);
        let r = skip_branch(&[OP_UNIQUIFIER, 0, 1, 2, 3], 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let v = [255, OP_ENDIF];
        assert!(matches!(skip_branch(&v, 0), Err(ScriptError::BadOpcode)));
    }

    #[test]
    fn skip_op() {
        use super::skip_op;
        let r = skip_op(&[], 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let r = skip_op(&[OP_0], 1);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        assert_eq!(skip_op(&[OP_0], 0).unwrap(), 1);
        assert_eq!(skip_op(&[OP_1, OP_2, OP_3], 0).unwrap(), 1);
        assert_eq!(skip_op(&[OP_1, OP_2, OP_3], 1).unwrap(), 2);
        assert_eq!(skip_op(&[OP_1, OP_2, OP_3], 2).unwrap(), 3);
        assert_eq!(skip_op(&[OP_IF, OP_ENDIF], 0).unwrap(), 1);
        assert_eq!(skip_op(&[OP_IF, OP_ENDIF], 1).unwrap(), 2);
        assert_eq!(skip_op(&[OP_0, OP_PUSH + 1, 1], 1).unwrap(), 3);
        assert_eq!(skip_op(&[OP_0, OP_PUSH + 1, 1, OP_1], 1).unwrap(), 3);
        let v = [vec![OP_0, OP_PUSH + 75], vec![0; 75]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 77);
        let v = [vec![OP_0, OP_PUSHDATA1, 0]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 3);
        let v = [vec![OP_0, OP_PUSHDATA1, 1, 0]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 4);
        let v = [vec![OP_0, OP_PUSHDATA1, 255], vec![0; 255]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 258);
        let v = [vec![OP_0, OP_PUSHDATA2, 0, 0]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 4);
        let v = [vec![OP_0, OP_PUSHDATA2, 1, 0, 0]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 5);
        let v = [vec![OP_0, OP_PUSHDATA2, 255, 0], vec![0; 255]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 259);
        let v = [vec![OP_0, OP_PUSHDATA2, 0, 1], vec![0; 256]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 260);
        let v = [vec![OP_0, OP_PUSHDATA2, 1, 1], vec![0; 257]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 261);
        let v = [vec![OP_0, OP_PUSHDATA2, 255, 255], vec![0; 65535]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 65539);
        let v = [vec![OP_0, OP_PUSHDATA4, 0, 0, 0, 0]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 6);
        let v = [vec![OP_0, OP_PUSHDATA4, 1, 0, 0, 0, 0]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 7);
        let v = [vec![OP_0, OP_PUSHDATA4, 0, 0, 1, 0], vec![0; 65536]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 65542);
        let v = [vec![OP_0, OP_PUSHDATA4, 1, 1, 1, 0], vec![0; 65793]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 65799);
        let v = [vec![OP_UNIQUIFIER], vec![0; ID_LEN]].concat();
        assert_eq!(skip_op(&v, 0).unwrap(), 1 + ID_LEN);
        let v = [vec![OP_0, OP_UNIQUIFIER], vec![0; ID_LEN]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 2 + ID_LEN);
        let v = [vec![OP_SIGN], vec![0; PUBKEY_LEN + SIG_LEN]].concat();
        assert_eq!(skip_op(&v, 0).unwrap(), 1 + PUBKEY_LEN + SIG_LEN);
        let v = [vec![OP_0, OP_SIGNTO, OP_0], vec![0; PUBKEY_LEN + SIG_LEN]].concat();
        assert_eq!(skip_op(&v, 1).unwrap(), 2 + PUBKEY_LEN + SIG_LEN);
        assert!(matches!(skip_op(&[161], 0), Err(ScriptError::BadOpcode)));
        assert!(matches!(skip_op(&[255], 0), Err(ScriptError::BadOpcode)));
        assert_eq!(skip_op(&[OP_0, 255], 0).unwrap(), 1);
        let r = skip_op(&[OP_0, 255], 1);
        assert!(matches!(r, Err(ScriptError::BadOpcode)));
        let r = skip_op(&[vec![OP_0, OP_PUSH + 1]].concat(), 1);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let r = skip_op(&[vec![OP_0, OP_PUSH + 75], vec![0; 74]].concat(), 1);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let v = [vec![OP_0, OP_PUSHDATA2, 255, 255], vec![0; 255]].concat();
        let r = skip_op(&v, 1);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let r = skip_op(&[vec![OP_0, OP_PUSHDATA4, 1, 0, 0, 0]].concat(), 1);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let v = [vec![OP_UNIQUIFIER], vec![0; ID_LEN - 1]].concat();
        let r = skip_op(&v, 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let v = [vec![OP_SIGN], vec![0; PUBKEY_LEN + SIG_LEN - 1]].concat();
        let r = skip_op(&v, 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let v = [vec![OP_SIGNTO], vec![0; PUBKEY_LEN + SIG_LEN - 1]].concat();
        let r = skip_op(&v, 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let r = skip_op(&[OP_PUSHDATA1], 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let r = skip_op(&[OP_PUSHDATA2], 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let r = skip_op(&[OP_PUSHDATA2, 0], 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let r = skip_op(&[OP_PUSHDATA4], 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
        let r = skip_op(&[OP_PUSHDATA4, 0, 0, 0], 0);
        assert!(matches!(r, Err(ScriptError::UnexpectedEndOfScript)));
    }
}
