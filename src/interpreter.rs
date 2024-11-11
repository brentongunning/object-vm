use crate::{
    core::{Id, PubKey, Sig, ID_LEN, PUBKEY_LEN, SIG_LEN},
    errors::{ExecuteError, ScriptError, StackError},
    opcodes::*,
    script::skip_branch,
    sig_verifier::SigVerifier,
    stack::{decode_bigint, decode_bool, decode_num, encode_bigint, encode_bool, Stack},
    vm::Vm,
};
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};

pub trait Interpreter {
    type SigVerifier: SigVerifier;
    type Vm: Vm;

    fn execute(&mut self, script: &[u8]) -> Result<(), ExecuteError>;
}

pub struct InterpreterImpl<S: SigVerifier, V: Vm> {
    sig_verifier: S,
    vm: V,
}

impl<S: SigVerifier, V: Vm> InterpreterImpl<S, V> {
    pub fn new(sig_verifier: S, vm: V) -> Self {
        Self { sig_verifier, vm }
    }
}

impl<S: SigVerifier, V: Vm> Interpreter for InterpreterImpl<S, V> {
    type SigVerifier = S;
    type Vm = V;

    fn execute(&mut self, script: &[u8]) -> Result<(), ExecuteError> {
        let mut branch = vec![]; // true if executing current if/else branch

        let mut i = 0;

        fn read<'a>(script: &'a [u8], i: &mut usize, len: usize) -> Result<&'a [u8], ScriptError> {
            let ret = script
                .get(*i..*i + len)
                .ok_or(ScriptError::UnexpectedEndOfScript)?;
            *i += len;
            Ok(ret)
        }

        while i < script.len() {
            if !branch.is_empty() && !branch.last().unwrap() {
                i = skip_branch(script, i)?;
            }

            let opcode = script[i];

            i += 1;

            match opcode {
                OP_PUSH..=75 => {
                    let len = (opcode - OP_PUSH) as usize;
                    let elem = read(script, &mut i, len)?;
                    self.vm.stack().push(elem)?;
                }

                OP_PUSHDATA1 => {
                    let len = read(script, &mut i, 1)?[0] as usize;
                    let elem = read(script, &mut i, len)?;
                    self.vm.stack().push(elem)?;
                }

                OP_PUSHDATA2 => {
                    let len_buf = read(script, &mut i, 2)?;
                    let len = u16::from_le_bytes(len_buf.try_into().unwrap()) as usize;
                    let elem = read(script, &mut i, len)?;
                    self.vm.stack().push(elem)?;
                }

                OP_PUSHDATA4 => {
                    let len_buf = read(script, &mut i, 4)?;
                    let len = u32::from_le_bytes(len_buf.try_into().unwrap()) as usize;
                    let elem = read(script, &mut i, len)?;
                    self.vm.stack().push(elem)?;
                }

                OP_NEG1 => self.vm.stack().push(&[0xff])?,

                OP_1..=OP_16 => self.vm.stack().push(&[opcode - OP_1 + 1])?,

                OP_IF => branch.push(self.vm.stack().pop(decode_bool)?),

                OP_ELSE => {
                    let value = branch.last_mut().ok_or(ScriptError::BadConditional)?;
                    *value = !*value;
                }

                OP_ENDIF => {
                    branch.pop().ok_or(ScriptError::BadConditional)?;
                }

                OP_NOT => {
                    let value = self.vm.stack().pop(decode_bool)?;
                    self.vm.stack().push(&encode_bool(!value))?;
                }

                OP_VERIFY => {
                    if !self.vm.stack().pop(decode_bool)? {
                        return Err(ExecuteError::OpVerifyFailed);
                    }
                }

                OP_DUPN => {
                    let n: u64 = self.vm.stack().pop(decode_num)??;
                    self.vm.stack().dup(n as usize)?;
                }

                OP_DUP..=OP_DUP9 => {
                    let n = (opcode - OP_DUP) as usize + 1;
                    self.vm.stack().dup(n)?;
                }

                OP_SWAPN => {
                    let n: u64 = self.vm.stack().pop(decode_num)??;
                    self.vm.stack().swap(n as usize)?;
                }

                OP_SWAP..=OP_SWAP9 => {
                    let n = (opcode - OP_SWAP) as usize + 1;
                    self.vm.stack().swap(n)?;
                }

                OP_DROP => {
                    self.vm.stack().pop(|_| {})?;
                }

                OP_DEPTH => {
                    let depth = self.vm.stack().depth();
                    self.vm.stack().push(&encode_bigint(BigInt::from(depth)))?;
                }

                OP_TOALTSTACK => {
                    self.vm.stack().move_to_alt_stack()?;
                }

                OP_FROMALTSTACK => {
                    self.vm.stack().move_from_alt_stack()?;
                }

                OP_CAT => {
                    let b = self.vm.stack().pop(|x| x.to_vec())?;
                    let a = self.vm.stack().pop(|x| x.to_vec())?;
                    self.vm.stack().push(&[a, b].concat())?;
                }

                OP_SPLIT => {
                    let n: u64 = self.vm.stack().pop(decode_num)??;
                    let a = self.vm.stack().pop(|x| x.to_vec())?;
                    if n as usize > a.len() {
                        Err(StackError::BadElement)?;
                    }
                    let (left, right) = a.split_at(n as usize);
                    self.vm.stack().push(&left.to_vec())?;
                    self.vm.stack().push(&right.to_vec())?;
                }

                OP_SIZE => {
                    let len = self.vm.stack().last(|x| x.len())?;
                    self.vm.stack().push(&encode_bigint(BigInt::from(len)))?;
                }

                OP_NUM2BIN => {
                    let size: u64 = self.vm.stack().pop(decode_num)??;
                    let n = self.vm.stack().pop(decode_bigint)?;
                    let mut bytes = if n.sign() == Sign::NoSign {
                        vec![]
                    } else {
                        n.to_signed_bytes_le()
                    };
                    if (size as usize) < bytes.len() {
                        Err(StackError::BadElement)?;
                    }
                    let byte = if n.sign() == Sign::Minus { 0xff } else { 0 };
                    bytes.extend_from_slice(&vec![byte; size as usize - bytes.len()]);
                    self.vm.stack().push(&bytes)?;
                }

                OP_BIN2NUM => {
                    let n = self.vm.stack().pop(decode_bigint)?;
                    self.vm.stack().push(&encode_bigint(n))?;
                }

                OP_INVERT => {
                    let mut buf = self.vm.stack().pop(|x| x.to_vec())?;
                    buf.iter_mut().for_each(|b| *b = !*b);
                    self.vm.stack().push(&buf)?;
                }

                OP_AND | OP_OR | OP_XOR => {
                    let b = self.vm.stack().pop(|x| x.to_vec())?;
                    let a = self.vm.stack().pop(|x| x.to_vec())?;
                    if a.len() != b.len() {
                        Err(StackError::BadElement)?;
                    }
                    let r: Vec<u8> = match opcode {
                        OP_AND => a.iter().zip(b.iter()).map(|(x, y)| x & y).collect(),
                        OP_OR => a.iter().zip(b.iter()).map(|(x, y)| x | y).collect(),
                        OP_XOR => a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect(),
                        _ => unreachable!(),
                    };
                    self.vm.stack().push(&r)?;
                }

                OP_LSHIFT => {
                    let b = self.vm.stack().pop(decode_num::<u64>)?? as usize;
                    let mut a = self.vm.stack().pop(|x| x.to_vec())?;
                    for i in 0..a.len() {
                        if b % 8 == 0 {
                            a[i] = *a.get(i + b / 8).unwrap_or(&0);
                        } else {
                            let l = *a.get(i + b / 8).unwrap_or(&0);
                            let r = *a.get(i + b / 8 + 1).unwrap_or(&0);
                            a[i] = (l << (b % 8)) | (r >> (8 - b % 8));
                        }
                    }
                    self.vm.stack().push(&a)?;
                }

                OP_RSHIFT => {
                    let b = self.vm.stack().pop(decode_num::<u64>)?? as usize;
                    let mut a = self.vm.stack().pop(|x| x.to_vec())?;
                    for i in (0..a.len()).rev() {
                        if b % 8 == 0 {
                            a[i] = if i >= b / 8 { a[i - b / 8] } else { 0 };
                        } else {
                            let l = if i >= b / 8 + 1 { a[i - b / 8 - 1] } else { 0 };
                            let r = if i >= b / 8 { a[i - b / 8] } else { 0 };
                            a[i] = (l << (8 - b % 8)) | (r >> (b % 8));
                        }
                    }
                    self.vm.stack().push(&a)?;
                }

                OP_EQUAL => {
                    let b = self.vm.stack().pop(|x| x.to_vec())?;
                    let a = self.vm.stack().pop(|x| x.to_vec())?;
                    self.vm.stack().push(&encode_bool(a == b))?;
                }

                OP_ADD | OP_SUB | OP_MUL | OP_DIV | OP_MOD | OP_NUMEQUAL | OP_LT | OP_GT => {
                    let b = self.vm.stack().pop(decode_bigint)?;
                    let a = self.vm.stack().pop(decode_bigint)?;
                    if (opcode == OP_DIV || opcode == OP_MOD) && b.sign() == Sign::NoSign {
                        return Err(ExecuteError::DivideByZero);
                    }
                    let r = match opcode {
                        OP_ADD => encode_bigint(a + b),
                        OP_SUB => encode_bigint(a - b),
                        OP_MUL => encode_bigint(a * b),
                        OP_DIV => encode_bigint(a / b),
                        OP_MOD => encode_bigint(a % b),
                        OP_NUMEQUAL => encode_bool(a == b),
                        OP_LT => encode_bool(a < b),
                        OP_GT => encode_bool(a > b),
                        _ => unreachable!(),
                    };
                    self.vm.stack().push(&r)?;
                }

                OP_BLAKE3 => {
                    let data = self.vm.stack().pop(|x| x.to_vec())?;
                    self.vm.stack().push(blake3::hash(&data).as_bytes())?;
                }

                OP_SHA256 => {
                    let data = self.vm.stack().pop(|x| x.to_vec())?;
                    let mut sha256 = Sha256::new();
                    sha256.update(&data);
                    self.vm.stack().push(sha256.finalize().as_slice())?;
                }

                OP_SIGN | OP_SIGNTO => {
                    let index = i - 1;
                    let pubkey_buf = read(script, &mut i, PUBKEY_LEN)?;
                    let sig_buf = read(script, &mut i, SIG_LEN)?;
                    let pubkey: PubKey = pubkey_buf.try_into().unwrap();
                    let sig: Sig = sig_buf.try_into().unwrap();
                    self.sig_verifier.verify(&pubkey, &sig, index)?;
                    self.vm.stack().push(&pubkey)?;
                    self.vm.auth()?;
                }

                OP_UNIQUIFIER => {
                    let revision_id_buf = read(script, &mut i, ID_LEN)?;
                    let revision_id: Id = revision_id_buf.try_into().unwrap();
                    self.vm.stack().push(&revision_id)?;
                    self.vm.uniquifier()?;
                }

                OP_DEPLOY => {
                    self.vm.deploy()?;
                }

                OP_CREATE => {
                    self.vm.create()?;
                }

                OP_CALL => {
                    self.vm.call()?;
                }

                OP_STATE => {
                    self.vm.state()?;
                }

                OP_CLASS => {
                    self.vm.class()?;
                }

                OP_FUND => {
                    self.vm.fund()?;
                }

                _ => Err(ScriptError::BadOpcode)?,
            }
        }

        if !branch.is_empty() {
            Err(ScriptError::BadConditional)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::{VerifyError, VmError},
        stack::{decode_arr, StackImpl},
    };

    struct StubVm {
        stack: StackImpl,
    }

    impl Vm for StubVm {
        type Stack = StackImpl;

        fn stack(&mut self) -> &mut Self::Stack {
            &mut self.stack
        }

        fn deploy(&mut self) -> Result<(), VmError> {
            let _code: Vec<u8> = self.stack().pop(|x| x.to_vec())?;
            self.stack().push(&Id::default())?;
            Ok(())
        }

        fn create(&mut self) -> Result<(), VmError> {
            let _class_id: Id = self.stack().pop(decode_arr)??;
            self.stack().push(&Id::default())?;
            Ok(())
        }

        fn call(&mut self) -> Result<(), VmError> {
            let _object_id: Id = self.stack().pop(decode_arr)??;
            Ok(())
        }

        fn state(&mut self) -> Result<(), VmError> {
            let _object_id: Id = self.stack().pop(decode_arr)??;
            self.stack().push(&[])?;
            Ok(())
        }

        fn class(&mut self) -> Result<(), VmError> {
            let _object_id: Id = self.stack().pop(decode_arr)??;
            self.stack().push(&Id::default())?;
            Ok(())
        }

        fn auth(&mut self) -> Result<(), VmError> {
            let _pubkey: PubKey = self.stack().pop(decode_arr)??;
            Ok(())
        }

        fn uniquifier(&mut self) -> Result<(), VmError> {
            let _revision_id: Id = self.stack().pop(decode_arr)??;
            Ok(())
        }

        fn fund(&mut self) -> Result<(), VmError> {
            let _object_id: Id = self.stack().pop(decode_arr)??;
            Ok(())
        }

        fn caller(&mut self) -> Result<(), VmError> {
            self.stack().push(&Id::default())?;
            Ok(())
        }
    }

    struct StubSigVerifier {}

    impl SigVerifier for StubSigVerifier {
        fn verify(
            &mut self,
            _pubkey: &PubKey,
            _sig: &Sig,
            _index: usize,
        ) -> Result<(), VerifyError> {
            Ok(())
        }
    }

    fn test_with_stubs(
        script: &[u8],
        stack_elements: Option<Vec<Vec<u8>>>,
        altstack_elements: Option<Vec<Vec<u8>>>,
        result: Result<(), ExecuteError>,
    ) {
        let sig_verifier = StubSigVerifier {};
        let stack = StackImpl::default();
        let vm = StubVm { stack };
        let mut interpreter = InterpreterImpl::new(sig_verifier, vm);
        match interpreter.execute(script) {
            Ok(()) => assert!(result.is_ok()),
            Err(e) => assert_eq!(format!("{:?}", e), format!("{:?}", result.unwrap_err())),
        }
        if let Some(stack_elements) = stack_elements {
            for elem in stack_elements.iter().rev() {
                assert_eq!(&interpreter.vm.stack().pop(|x| x.to_vec()).unwrap(), elem);
            }
            assert_eq!(interpreter.vm.stack().depth(), 0);
        }
        if let Some(altstack_elements) = altstack_elements {
            for elem in altstack_elements.iter().rev() {
                interpreter.vm.stack().move_from_alt_stack().unwrap();
                assert_eq!(&interpreter.vm.stack().pop(|x| x.to_vec()).unwrap(), elem);
            }
            assert!(interpreter.vm.stack().move_from_alt_stack().is_err());
        }
    }

    fn test_ok(script: &[u8]) {
        test_with_stubs(script, None, None, Ok(()));
    }

    fn test_err(script: &[u8], e: impl Into<ExecuteError>) {
        test_with_stubs(script, None, None, Err(e.into()));
    }

    fn test_ok_with_stack(script: &[u8], stack: Vec<Vec<u8>>) {
        test_with_stubs(script, Some(stack), None, Ok(()));
    }

    #[test]
    fn empty() {
        test_ok(&[]);
    }

    #[test]
    fn invalid_opcode() {
        test_err(&[156], ScriptError::BadOpcode);
        test_err(&[255], ScriptError::BadOpcode);
    }

    #[test]
    fn unexecuted_branch() {
        test_ok_with_stack(&[OP_0, OP_IF, OP_0, OP_ENDIF], vec![]);
        test_ok_with_stack(&[OP_0, OP_IF, OP_16, OP_ENDIF], vec![]);
        test_ok_with_stack(&[OP_0, OP_IF, OP_PUSH + 1, 1, OP_ENDIF], vec![]);
        test_ok_with_stack(&[OP_0, OP_IF, OP_PUSHDATA1, 0, OP_ENDIF], vec![]);
        test_ok_with_stack(&[OP_0, OP_IF, OP_PUSHDATA2, 0, 0, OP_ENDIF], vec![]);
        test_ok_with_stack(&[OP_0, OP_IF, OP_PUSHDATA4, 0, 0, 0, 0, OP_ENDIF], vec![]);
        test_ok_with_stack(
            &[
                vec![OP_0, OP_IF, OP_UNIQUIFIER],
                vec![0; ID_LEN],
                vec![OP_ENDIF],
            ]
            .concat(),
            vec![],
        );
    }

    #[test]
    fn invalid_unexecuted_branch() {
        let v = [OP_0, OP_IF, 161, OP_ELSE, OP_ENDIF];
        test_err(&v, ScriptError::BadOpcode);
        let v = [OP_1, OP_1, OP_IF, OP_IF, OP_ELSE, 200, OP_ENDIF, OP_ENDIF];
        test_err(&v, ScriptError::BadOpcode);
        let v = [OP_0, OP_IF, OP_0, OP_1, 255, OP_ENDIF];
        test_err(&v, ScriptError::BadOpcode);
        let v = [OP_0, OP_IF, OP_UNIQUIFIER, OP_ENDIF];
        test_err(&v, ScriptError::UnexpectedEndOfScript);
        let v = [OP_0, OP_IF, OP_PUSH + 75, OP_ENDIF];
        test_err(&v, ScriptError::UnexpectedEndOfScript);
        let v = [OP_0, OP_IF, OP_PUSHDATA1, 10, OP_ENDIF];
        test_err(&v, ScriptError::UnexpectedEndOfScript);
        let v = [OP_0, OP_IF, OP_PUSHDATA2, OP_ENDIF];
        test_err(&v, ScriptError::UnexpectedEndOfScript);
        let v = [OP_0, OP_IF, OP_PUSHDATA4, OP_ENDIF];
        test_err(&v, ScriptError::UnexpectedEndOfScript);
    }
}
