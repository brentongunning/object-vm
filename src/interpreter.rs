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

    fn test_ok_with_altstack(script: &[u8], stack: Vec<Vec<u8>>, altstack: Vec<Vec<u8>>) {
        test_with_stubs(script, Some(stack), Some(altstack), Ok(()));
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

    #[test]
    fn op_num() {
        test_ok_with_stack(&[OP_0], vec![vec![]]);
        test_ok_with_stack(&[OP_NEG1], vec![vec![0xff]]);
        test_ok_with_stack(&[OP_1], vec![vec![1]]);
        test_ok_with_stack(&[OP_16], vec![vec![16]]);
        let v = [OP_0, OP_NEG1, OP_1, OP_16];
        test_ok_with_stack(&v, vec![vec![], vec![0xff], vec![1], vec![16]]);
    }

    #[test]
    fn op_push() {
        test_ok_with_stack(&[OP_PUSH + 0], vec![vec![]]);
        let v = [vec![OP_PUSH + 75], vec![0; 75]].concat();
        test_ok_with_stack(&v, vec![vec![0; 75]]);
        let v = [OP_PUSH + 0, OP_PUSH + 0, OP_PUSH + 0];
        test_ok_with_stack(&v, vec![vec![], vec![], vec![]]);
        let v = [OP_PUSH + 1, 1, OP_PUSH + 1, 2, OP_PUSH + 1, 3];
        test_ok_with_stack(&v, vec![vec![1], vec![2], vec![3]]);
        let v = [OP_PUSH + 1, 0, OP_PUSH + 2, 0, 0, OP_PUSH + 3, 0, 0, 0];
        test_ok_with_stack(&v, vec![vec![0], vec![0, 0], vec![0, 0, 0]]);
        test_err(&[OP_PUSH + 1], ScriptError::UnexpectedEndOfScript);
        let v = [vec![OP_PUSH + 75], vec![0; 74]].concat();
        test_err(&v, ScriptError::UnexpectedEndOfScript);
    }

    #[test]
    fn op_pushdata1() {
        test_ok_with_stack(&[OP_PUSHDATA1, 0], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSHDATA1, 1, 1], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSHDATA1, 2, 1, 2], vec![vec![1, 2]]);
        test_ok_with_stack(&[OP_PUSHDATA1, 3, 1, 2, 3], vec![vec![1, 2, 3]]);
        let v = [vec![OP_PUSHDATA1, 255], vec![0; 255]].concat();
        test_ok_with_stack(&v, vec![vec![0; 255]]);
        let v = [OP_PUSHDATA1, 0, OP_PUSHDATA1, 1, 1];
        test_ok_with_stack(&v, vec![vec![], vec![1]]);
        test_err(&[OP_PUSHDATA1], ScriptError::UnexpectedEndOfScript);
        test_err(&[OP_PUSHDATA1, 1], ScriptError::UnexpectedEndOfScript);
        test_err(&[OP_PUSHDATA1, 2, 1], ScriptError::UnexpectedEndOfScript);
    }

    #[test]
    fn op_pushdata2() {
        test_ok_with_stack(&[OP_PUSHDATA2, 0, 0], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSHDATA2, 1, 0, 1], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSHDATA2, 2, 0, 1, 2], vec![vec![1, 2]]);
        test_ok_with_stack(&[OP_PUSHDATA2, 3, 0, 1, 2, 3], vec![vec![1, 2, 3]]);
        let v = [vec![OP_PUSHDATA2, 2, 1], vec![0; 258]].concat();
        test_ok_with_stack(&v, vec![vec![0; 258]]);
        let v = [vec![OP_PUSHDATA2, 255, 255], vec![0; 65535]].concat();
        test_ok_with_stack(&v, vec![vec![0; 65535]]);
        let v = [OP_PUSHDATA2, 0, 0, OP_PUSHDATA2, 1, 0, 1];
        test_ok_with_stack(&v, vec![vec![], vec![1]]);
        test_err(&[OP_PUSHDATA2], ScriptError::UnexpectedEndOfScript);
        test_err(&[OP_PUSHDATA2, 1], ScriptError::UnexpectedEndOfScript);
        test_err(&[OP_PUSHDATA2, 2, 0], ScriptError::UnexpectedEndOfScript);
        test_err(&[OP_PUSHDATA2, 2, 0, 1], ScriptError::UnexpectedEndOfScript);
        let v = [vec![OP_PUSHDATA2, 255, 255], vec![0; 65534]].concat();
        test_err(&v, ScriptError::UnexpectedEndOfScript);
    }

    #[test]
    fn op_pushdata4() {
        test_ok_with_stack(&[OP_PUSHDATA4, 0, 0, 0, 0], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSHDATA4, 1, 0, 0, 0, 1], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSHDATA4, 2, 0, 0, 0, 1, 2], vec![vec![1, 2]]);
        test_ok_with_stack(&[OP_PUSHDATA4, 3, 0, 0, 0, 1, 2, 3], vec![vec![1, 2, 3]]);
        let v = [vec![OP_PUSHDATA4, 2, 1, 0, 0], vec![0; 258]].concat();
        test_ok_with_stack(&v, vec![vec![0; 258]]);
        let v = [vec![OP_PUSHDATA4, 0, 0, 1, 0], vec![0; 65536]].concat();
        test_ok_with_stack(&v, vec![vec![0; 65536]]);
        let v = [OP_PUSHDATA4, 0, 0, 0, 0, OP_PUSHDATA4, 1, 0, 0, 0, 1];
        test_ok_with_stack(&v, vec![vec![], vec![1]]);
        test_err(&[OP_PUSHDATA4], ScriptError::UnexpectedEndOfScript);
        test_err(&[OP_PUSHDATA4, 1], ScriptError::UnexpectedEndOfScript);
        test_err(&[OP_PUSHDATA4, 2, 0], ScriptError::UnexpectedEndOfScript);
        test_err(&[OP_PUSHDATA4, 2, 0, 0], ScriptError::UnexpectedEndOfScript);
        let v = [OP_PUSHDATA4, 2, 0, 0, 0];
        test_err(&v, ScriptError::UnexpectedEndOfScript);
        let v = [vec![OP_PUSHDATA4, 0, 0, 1, 0], vec![0; 65535]].concat();
        test_err(&v, ScriptError::UnexpectedEndOfScript);
    }

    #[test]
    fn op_not() {
        test_ok_with_stack(&[OP_0, OP_NOT], vec![vec![1]]);
        test_ok_with_stack(&[OP_NEG1, OP_NOT], vec![vec![]]);
        test_ok_with_stack(&[OP_16, OP_NOT], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 1, 0, OP_NOT], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSH + 2, 0, 0, OP_NOT], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSH + 1, 1, OP_NOT], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 2, 0, 1, OP_NOT], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 1, 255, OP_NOT], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 2, 0, 255, OP_NOT], vec![vec![]]);
        test_err(&[OP_NOT], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_if() {
        test_ok(&[OP_0, OP_IF, OP_ENDIF]);
        test_ok(&[OP_1, OP_IF, OP_ENDIF]);
        test_ok(&[OP_0, OP_IF, OP_0, OP_VERIFY, OP_ENDIF]);
        test_ok(&[OP_0, OP_0, OP_IF, OP_IF, OP_ENDIF, OP_ENDIF]);
        let v = [OP_1, OP_IF, OP_0, OP_VERIFY, OP_ENDIF];
        test_err(&v, ExecuteError::OpVerifyFailed);
        let v = [
            OP_1, OP_1, OP_IF, OP_IF, OP_0, OP_VERIFY, OP_ENDIF, OP_ENDIF,
        ];
        test_err(&v, ExecuteError::OpVerifyFailed);
        test_err(&[OP_IF], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_IF], ScriptError::BadConditional);
        let v = [OP_0, OP_0, OP_IF, OP_IF, OP_ENDIF];
        test_err(&v, ScriptError::BadConditional);
    }

    #[test]
    fn op_else() {
        test_ok(&[OP_0, OP_IF, OP_ELSE, OP_ENDIF]);
        test_ok(&[OP_1, OP_IF, OP_ELSE, OP_ENDIF]);
        test_ok(&[
            OP_0, OP_IF, OP_0, OP_VERIFY, OP_ELSE, OP_1, OP_VERIFY, OP_ENDIF,
        ]);
        test_ok(&[
            OP_0, OP_0, OP_IF, OP_0, OP_VERIFY, OP_ELSE, OP_IF, OP_0, OP_VERIFY, OP_ELSE, OP_ENDIF,
            OP_ENDIF,
        ]);
        let v = [OP_0, OP_IF, OP_ELSE, OP_0, OP_VERIFY, OP_ENDIF];
        test_err(&v, ExecuteError::OpVerifyFailed);
        let v = [
            OP_0, OP_1, OP_IF, OP_IF, OP_ELSE, OP_0, OP_VERIFY, OP_ENDIF, OP_ENDIF,
        ];
        test_err(&v, ExecuteError::OpVerifyFailed);
        let v = [
            OP_1, OP_0, OP_IF, OP_ELSE, OP_IF, OP_0, OP_VERIFY, OP_ENDIF, OP_ENDIF,
        ];
        test_err(&v, ExecuteError::OpVerifyFailed);
        test_err(&[OP_ELSE], ScriptError::BadConditional);
        test_err(&[OP_1, OP_IF, OP_ELSE], ScriptError::BadConditional);
        test_err(&[OP_0, OP_ELSE], ScriptError::BadConditional);
        let v = [OP_0, OP_0, OP_IF, OP_ELSE, OP_IF, OP_ENDIF];
        test_err(&v, ScriptError::BadConditional);
    }

    #[test]
    fn op_endif() {
        let v = [
            OP_1, OP_1, OP_1, OP_IF, OP_IF, OP_1, OP_ELSE, OP_0, OP_VERIFY, OP_ENDIF, OP_IF, OP_2,
            OP_ELSE, OP_0, OP_VERIFY, OP_ENDIF, OP_ELSE, OP_0, OP_VERIFY, OP_ENDIF,
        ];
        test_ok_with_stack(&v, vec![vec![1], vec![2]]);
        test_err(&[OP_ENDIF], ScriptError::BadConditional);
    }

    #[test]
    fn op_verify() {
        test_ok(&[OP_1, OP_VERIFY]);
        test_ok(&[OP_0, OP_NOT, OP_VERIFY]);
        test_ok(&[OP_PUSH + 2, 255, 255, OP_VERIFY]);
        test_err(&[OP_0, OP_VERIFY], ExecuteError::OpVerifyFailed);
        test_err(
            &[OP_PUSH + 4, 0, 0, 0, 0, OP_VERIFY],
            ExecuteError::OpVerifyFailed,
        );
        test_err(&[OP_1, OP_0, OP_VERIFY], ExecuteError::OpVerifyFailed);
        test_err(&[OP_VERIFY], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_dupn() {
        test_ok_with_stack(&[OP_0, OP_DUPN], vec![]);
        test_ok_with_stack(&[OP_0, OP_1, OP_DUPN], vec![vec![], vec![]]);
        let v = [OP_0, OP_1, OP_2, OP_DUPN];
        test_ok_with_stack(&v, vec![vec![], vec![1], vec![], vec![1]]);
        let v = [
            OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_10, OP_DUPN,
        ];
        let s = vec![
            vec![],
            vec![1],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![7],
            vec![8],
            vec![9],
        ];
        test_ok_with_stack(&v, [s.clone(), s].concat());
        test_ok_with_stack(&[OP_0, OP_1, OP_1, OP_DUPN], vec![vec![], vec![1], vec![1]]);
        let v = [OP_1, OP_PUSH + 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, OP_DUPN];
        test_ok_with_stack(&v, vec![vec![1], vec![1]]);
        let v = [OP_0, OP_1, OP_2, OP_2, OP_DUPN];
        test_ok_with_stack(&v, vec![vec![], vec![1], vec![2], vec![1], vec![2]]);
        test_err(&[OP_DUPN], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_1, OP_DUPN], ExecuteError::Stack(StackError::Underflow));
        let v = [OP_PUSH + 9, 0, 0, 0, 0, 0, 0, 0, 0, 1, OP_DUPN];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
    }

    #[test]
    fn op_dup() {
        test_ok_with_stack(&[OP_0, OP_DUP], vec![vec![], vec![]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_DUP], vec![vec![], vec![1], vec![1]]);
        let v = [OP_0, OP_1, OP_DUP2];
        test_ok_with_stack(&v, vec![vec![], vec![1], vec![], vec![1]]);
        let v = [OP_0, OP_1, OP_2, OP_DUP2];
        test_ok_with_stack(&v, vec![vec![], vec![1], vec![2], vec![1], vec![2]]);
        let v = vec![
            OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_DUP9,
        ];
        let s = vec![
            vec![],
            vec![1],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![7],
            vec![8],
        ];
        test_ok_with_stack(&v, [s.clone(), s].concat());
        test_err(&[OP_DUP], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_1, OP_DUP2], ExecuteError::Stack(StackError::Underflow));
        let v = [OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_DUP9];
        test_err(&v, ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_swapn() {
        test_ok_with_stack(&[OP_0, OP_0, OP_SWAPN], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_1, OP_SWAPN], vec![vec![1], vec![]]);
        let v = [OP_0, OP_1, OP_2, OP_2, OP_SWAPN];
        test_ok_with_stack(&v, vec![vec![2], vec![1], vec![]]);
        let v = [
            OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_10, OP_10, OP_SWAPN,
        ];
        let s = vec![
            vec![10],
            vec![1],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![7],
            vec![8],
            vec![9],
            vec![],
        ];
        test_ok_with_stack(&v, s);
        let v = [OP_0, OP_1, OP_2, OP_1, OP_SWAPN];
        test_ok_with_stack(&v, vec![vec![], vec![2], vec![1]]);
        let v = [OP_0, OP_1, OP_PUSH + 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, OP_SWAPN];
        test_ok_with_stack(&v, vec![vec![1], vec![]]);
        test_err(&[OP_SWAPN], ExecuteError::Stack(StackError::Underflow));
        let v = vec![OP_0, OP_SWAPN];
        test_err(&v, ExecuteError::Stack(StackError::Underflow));
        let v = vec![OP_1, OP_SWAPN];
        test_err(&v, ExecuteError::Stack(StackError::Underflow));
        let v = vec![OP_0, OP_1, OP_SWAPN];
        test_err(&v, ExecuteError::Stack(StackError::Underflow));
        let v = [OP_PUSH + 9, 0, 0, 0, 0, 0, 0, 0, 0, 1, OP_SWAPN];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
    }

    #[test]
    fn op_swap() {
        test_ok_with_stack(&[OP_0, OP_1, OP_SWAP], vec![vec![1], vec![]]);
        let v = [OP_0, OP_1, OP_2, OP_SWAP2];
        test_ok_with_stack(&v, vec![vec![2], vec![1], vec![]]);
        let v = [
            OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_SWAP9,
        ];
        let s = vec![
            vec![9],
            vec![1],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![7],
            vec![8],
            vec![],
        ];
        test_ok_with_stack(&v, s);
        test_err(&[OP_SWAP], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_SWAP], ExecuteError::Stack(StackError::Underflow));
        test_err(
            &[OP_0, OP_0, OP_SWAP2],
            ExecuteError::Stack(StackError::Underflow),
        );
        let v = [
            OP_0, OP_0, OP_0, OP_0, OP_0, OP_0, OP_0, OP_0, OP_0, OP_SWAP9,
        ];
        test_err(&v, ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_drop() {
        test_ok_with_stack(&[OP_0, OP_DROP], vec![]);
        test_ok_with_stack(&[OP_0, OP_1, OP_DROP], vec![vec![]]);
        let v = [OP_0, OP_1, OP_DROP, OP_DROP];
        test_ok_with_stack(&v, vec![]);
        test_err(&[OP_DROP], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_depth() {
        test_ok_with_stack(&[OP_DEPTH], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_DEPTH], vec![vec![], vec![1]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_DEPTH], vec![vec![], vec![1], vec![2]]);
        let v = [vec![0; 255], vec![OP_DEPTH]].concat();
        let s = [vec![vec![]; 255], vec![vec![255, 0]]].concat();
        test_ok_with_stack(&v, s);
    }

    #[test]
    fn op_toaltstack() {
        test_ok_with_altstack(&[OP_0, OP_TOALTSTACK], vec![], vec![vec![]]);
        test_ok_with_altstack(&[OP_0, OP_1, OP_TOALTSTACK], vec![vec![]], vec![vec![1]]);
        test_err(&[OP_TOALTSTACK], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_fromaltstack() {
        test_ok_with_altstack(
            &[OP_0, OP_TOALTSTACK, OP_FROMALTSTACK],
            vec![vec![]],
            vec![],
        );
        test_ok_with_altstack(
            &[OP_0, OP_1, OP_TOALTSTACK, OP_TOALTSTACK, OP_FROMALTSTACK],
            vec![vec![]],
            vec![vec![1]],
        );
        test_err(
            &[OP_FROMALTSTACK],
            ExecuteError::Stack(StackError::Underflow),
        );
    }

    #[test]
    fn op_cat() {
        test_ok_with_stack(&[OP_0, OP_0, OP_CAT], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_CAT], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_0, OP_CAT], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_CAT], vec![vec![1, 1]]);
        let v = [OP_PUSH + 2, 1, 2, OP_PUSH + 3, 3, 4, 5, OP_CAT];
        test_ok_with_stack(&v, vec![vec![1, 2, 3, 4, 5]]);
        test_err(&[OP_CAT], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_CAT], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_split() {
        test_ok_with_stack(&[OP_0, OP_0, OP_SPLIT], vec![vec![], vec![]]);
        test_ok_with_stack(&[OP_1, OP_0, OP_SPLIT], vec![vec![], vec![1]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_SPLIT], vec![vec![1], vec![]]);
        let v = [OP_PUSH + 3, 1, 2, 3, OP_0, OP_SPLIT];
        test_ok_with_stack(&v, vec![vec![], vec![1, 2, 3]]);
        let v = [OP_PUSH + 3, 1, 2, 3, OP_1, OP_SPLIT];
        test_ok_with_stack(&v, vec![vec![1], vec![2, 3]]);
        let v = [OP_PUSH + 3, 1, 2, 3, OP_2, OP_SPLIT];
        test_ok_with_stack(&v, vec![vec![1, 2], vec![3]]);
        let v = [OP_PUSH + 3, 1, 2, 3, OP_3, OP_SPLIT];
        test_ok_with_stack(&v, vec![vec![1, 2, 3], vec![]]);
        test_err(&[OP_SPLIT], ExecuteError::Stack(StackError::Underflow));
        test_err(
            &[OP_0, OP_SPLIT],
            ExecuteError::Stack(StackError::Underflow),
        );
        test_err(
            &[OP_1, OP_NEG1, OP_SPLIT],
            ExecuteError::Stack(StackError::BadElement),
        );
        test_err(
            &[OP_1, OP_2, OP_SPLIT],
            ExecuteError::Stack(StackError::BadElement),
        );
    }

    #[test]
    fn op_size() {
        test_ok_with_stack(&[OP_0, OP_SIZE], vec![vec![], vec![]]);
        test_ok_with_stack(&[OP_1, OP_SIZE], vec![vec![1], vec![1]]);
        test_ok_with_stack(&[OP_PUSH + 2, 1, 2, OP_SIZE], vec![vec![1, 2], vec![2]]);
        let v = [vec![OP_PUSHDATA1, 255], vec![0; 255], vec![OP_SIZE]].concat();
        let s = vec![vec![0; 255], vec![255, 0]];
        test_ok_with_stack(&v, s);
        test_err(&[OP_SIZE], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_num2bin() {
        test_ok_with_stack(&[OP_0, OP_0, OP_NUM2BIN], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_3, OP_NUM2BIN], vec![vec![0, 0, 0]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_NUM2BIN], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_3, OP_NUM2BIN], vec![vec![1, 0, 0]]);
        test_ok_with_stack(&[OP_NEG1, OP_1, OP_NUM2BIN], vec![vec![0xff]]);
        test_ok_with_stack(&[OP_NEG1, OP_3, OP_NUM2BIN], vec![vec![0xff, 0xff, 0xff]]);
        test_ok_with_stack(&[OP_PUSH + 3, 0, 0, 0, OP_0, OP_NUM2BIN], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 3, 0, 0, 0, OP_1, OP_NUM2BIN], vec![vec![0]]);
        let v = vec![OP_1, OP_0, OP_NUM2BIN];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
        let v = vec![OP_0, OP_NEG1, OP_NUM2BIN];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
        let v = [OP_PUSH + 2, 0, 1, OP_1, OP_NUM2BIN];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
        test_err(&[OP_NUM2BIN], ExecuteError::Stack(StackError::Underflow));
        let v = vec![OP_0, OP_NUM2BIN];
        test_err(&v, ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_bin2num() {
        test_ok_with_stack(&[OP_0, OP_BIN2NUM], vec![vec![]]);
        test_ok_with_stack(&[OP_1, OP_BIN2NUM], vec![vec![1]]);
        test_ok_with_stack(&[OP_NEG1, OP_BIN2NUM], vec![vec![0xff]]);
        test_ok_with_stack(&[OP_PUSH + 3, 0, 0, 0, OP_BIN2NUM], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 3, 1, 0, 0, OP_BIN2NUM], vec![vec![1]]);
        let v = [OP_PUSH + 3, 0xff, 0xff, 0xff, OP_BIN2NUM];
        test_ok_with_stack(&v, vec![vec![0xff]]);
        test_err(&[OP_BIN2NUM], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_invert() {
        test_ok_with_stack(&[OP_0, OP_INVERT], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 1, 0, OP_INVERT], vec![vec![0xff]]);
        test_ok_with_stack(&[OP_PUSH + 1, 0xff, OP_INVERT], vec![vec![0]]);
        let v = [OP_PUSH + 1, 0b11001110, OP_INVERT];
        test_ok_with_stack(&v, vec![vec![0b00110001]]);
        test_ok_with_stack(&[OP_PUSH + 2, 0, 0xff, OP_INVERT], vec![vec![0xff, 0]]);
        let v = [OP_PUSH + 2, 0b11001110, 0, OP_INVERT];
        test_ok_with_stack(&v, vec![vec![0b00110001, 0xff]]);
        test_err(&[OP_INVERT], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_and() {
        test_ok_with_stack(&[OP_0, OP_0, OP_AND], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 1, 0, OP_1, OP_AND], vec![vec![0]]);
        test_ok_with_stack(&[OP_1, OP_PUSH + 1, 0, OP_AND], vec![vec![0]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_AND], vec![vec![1]]);
        let v = [OP_PUSH + 2, 1, 2, OP_PUSH + 2, 0, 0xff, OP_AND];
        test_ok_with_stack(&v, vec![vec![0, 2]]);
        let v = [OP_PUSH + 2, 1, 2, OP_PUSH + 2, 0xff, 0, OP_AND];
        test_ok_with_stack(&v, vec![vec![1, 0]]);
        test_err(&[OP_AND], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_AND], ExecuteError::Stack(StackError::Underflow));
        let v = vec![OP_0, OP_1, OP_AND];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
        let v = [OP_PUSH + 2, 0, 0, OP_PUSH + 3, 0, 0, 0, OP_AND];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
    }

    #[test]
    fn op_or() {
        test_ok_with_stack(&[OP_0, OP_0, OP_OR], vec![vec![]]);
        test_ok_with_stack(&[OP_PUSH + 1, 0, OP_1, OP_OR], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_PUSH + 1, 0, OP_OR], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_OR], vec![vec![1]]);
        let v = [OP_PUSH + 2, 1, 2, OP_PUSH + 2, 0, 0xff, OP_OR];
        test_ok_with_stack(&v, vec![vec![1, 0xff]]);
        let v = [OP_PUSH + 2, 1, 2, OP_PUSH + 2, 0xff, 0, OP_OR];
        test_ok_with_stack(&v, vec![vec![0xff, 2]]);
        test_err(&[OP_OR], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_OR], ExecuteError::Stack(StackError::Underflow));
        let v = vec![OP_0, OP_1, OP_OR];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
        let v = [OP_PUSH + 2, 0, 0, OP_PUSH + 3, 0, 0, 0, OP_OR];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
    }

    #[test]
    fn op_xor() {
        test_ok_with_stack(&[OP_0, OP_0, OP_XOR], vec![vec![]]);
        let v = [OP_PUSH + 1, 0, OP_PUSH + 1, 0b11001110, OP_XOR];
        test_ok_with_stack(&v, vec![vec![0b11001110]]);
        let v = [OP_PUSH + 1, 0b11001110, OP_PUSH + 1, 0, OP_XOR];
        test_ok_with_stack(&v, vec![vec![0b11001110]]);
        let v = [OP_PUSH + 1, 0xff, OP_PUSH + 1, 0b11001110, OP_XOR];
        test_ok_with_stack(&v, vec![vec![0b00110001]]);
        let v = [OP_PUSH + 1, 0b11001110, OP_PUSH + 1, 0xff, OP_XOR];
        test_ok_with_stack(&v, vec![vec![0b00110001]]);
        let v = [OP_PUSH + 2, 0, 0xff, OP_PUSH + 2, 0xff, 0xff, OP_XOR];
        test_ok_with_stack(&v, vec![vec![0xff, 0]]);
        let v = [OP_PUSH + 2, 0xff, 0, OP_PUSH + 2, 0xff, 0xff, OP_XOR];
        test_ok_with_stack(&v, vec![vec![0, 0xff]]);
        test_err(&[OP_XOR], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_XOR], ExecuteError::Stack(StackError::Underflow));
        test_err(
            &[OP_0, OP_1, OP_XOR],
            ExecuteError::Stack(StackError::BadElement),
        );
        let v = [OP_PUSH + 2, 0, 0, OP_PUSH + 3, 0, 0, 0, OP_XOR];
        test_err(&v, ExecuteError::Stack(StackError::BadElement));
    }

    #[test]
    fn op_lshift() {
        test_ok_with_stack(&[OP_0, OP_0, OP_LSHIFT], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_LSHIFT], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_16, OP_LSHIFT], vec![vec![]]);
        test_ok_with_stack(&[OP_1, OP_0, OP_LSHIFT], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_PUSH + 1, 0, OP_LSHIFT], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSH + 1, 0, OP_0, OP_LSHIFT], vec![vec![0]]);
        test_ok_with_stack(&[OP_PUSH + 1, 1, OP_0, OP_LSHIFT], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSH + 1, 255, OP_0, OP_LSHIFT], vec![vec![255]]);
        test_ok_with_stack(&[OP_PUSH + 2, 0, 0, OP_0, OP_LSHIFT], vec![vec![0, 0]]);
        test_ok_with_stack(&[OP_PUSH + 2, 1, 2, OP_0, OP_LSHIFT], vec![vec![1, 2]]);
        let v = [OP_PUSH + 2, 254, 255, OP_0, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![254, 255]]);
        test_ok_with_stack(&[OP_PUSH + 2, 27, 93, OP_8, OP_LSHIFT], vec![vec![93, 0]]);
        let v = [OP_PUSH + 3, 27, 93, 155, OP_8, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![93, 155, 0]]);
        let v = [OP_PUSH + 3, 27, 93, 155, OP_16, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![155, 0, 0]]);
        let v = [OP_PUSH + 1, 0b11001110, OP_1, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![0b10011100]]);
        let v = [OP_PUSH + 1, 0b11001110, OP_3, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![0b01110000]]);
        let v = [OP_PUSH + 1, 0b11001101, OP_7, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![0b10000000]]);
        let v = [OP_PUSH + 2, 0b11001110, 0b10101101, OP_1, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![0b10011101, 0b01011010]]);
        let v = [OP_PUSH + 2, 0b11001110, 0b10101101, OP_3, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![0b01110101, 0b01101000]]);
        let v = [OP_PUSH + 2, 0b11001110, 0b10101101, OP_7, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![0b01010110, 0b10000000]]);
        let v = [
            OP_PUSH + 3,
            0b00000001,
            0b00000010,
            0b00000100,
            OP_7,
            OP_LSHIFT,
        ];
        test_ok_with_stack(&v, vec![vec![0b10000001, 0b00000010, 0b00000000]]);
        let v = [
            OP_PUSH + 4,
            0b10000001,
            0b10000010,
            0b10000100,
            0b10001000,
            OP_9,
            OP_LSHIFT,
        ];
        test_ok_with_stack(&v, vec![vec![0b00000101, 0b00001001, 0b00010000, 0]]);
        let v = [
            OP_PUSH + 4,
            0b10000001,
            0b10000010,
            0b10000100,
            0b10001000,
            OP_PUSH + 1,
            17,
            OP_LSHIFT,
        ];
        test_ok_with_stack(&v, vec![vec![0b00001001, 0b00010000, 0, 0]]);
        let v = [OP_PUSH + 2, 0xff, 0xff, OP_16, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![0, 0]]);
        let v = [OP_PUSH + 2, 0xff, 0xff, OP_PUSH + 1, 17, OP_LSHIFT];
        test_ok_with_stack(&v, vec![vec![0, 0]]);
        test_err(
            &[OP_0, OP_NEG1, OP_LSHIFT],
            ExecuteError::Stack(StackError::BadElement),
        );
        test_err(
            &[OP_0, OP_PUSH + 2, 0xff, 0xff, OP_LSHIFT],
            ExecuteError::Stack(StackError::BadElement),
        );
    }

    #[test]
    fn op_rshift() {
        test_ok_with_stack(&[OP_0, OP_0, OP_RSHIFT], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_RSHIFT], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_16, OP_RSHIFT], vec![vec![]]);
        test_ok_with_stack(&[OP_1, OP_0, OP_RSHIFT], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_PUSH + 1, 0, OP_RSHIFT], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSH + 1, 0, OP_0, OP_RSHIFT], vec![vec![0]]);
        test_ok_with_stack(&[OP_PUSH + 1, 1, OP_0, OP_RSHIFT], vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSH + 1, 255, OP_0, OP_RSHIFT], vec![vec![255]]);
        test_ok_with_stack(&[OP_PUSH + 2, 0, 0, OP_0, OP_RSHIFT], vec![vec![0, 0]]);
        test_ok_with_stack(&[OP_PUSH + 2, 1, 2, OP_0, OP_RSHIFT], vec![vec![1, 2]]);
        let v = [OP_PUSH + 2, 254, 255, OP_0, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![254, 255]]);
        test_ok_with_stack(&[OP_PUSH + 2, 27, 93, OP_8, OP_RSHIFT], vec![vec![0, 27]]);
        let v = [OP_PUSH + 3, 27, 93, 155, OP_8, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0, 27, 93]]);
        let v = [OP_PUSH + 3, 27, 93, 155, OP_16, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0, 0, 27]]);
        let v = [OP_PUSH + 1, 0b11001110, OP_1, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0b01100111]]);
        let v = [OP_PUSH + 1, 0b11001110, OP_3, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0b00011001]]);
        let v = [OP_PUSH + 1, 0b11001101, OP_7, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0b00000001]]);
        let v = [OP_PUSH + 2, 0b10101101, 0b11001110, OP_1, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0b01010110, 0b11100111]]);
        let v = [OP_PUSH + 2, 0b10101101, 0b11001110, OP_3, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0b00010101, 0b10111001]]);
        let v = [OP_PUSH + 2, 0b11001110, 0b10101101, OP_7, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0b00000001, 0b10011101]]);
        let v = [
            OP_PUSH + 3,
            0b00000001,
            0b00000010,
            0b00000100,
            OP_7,
            OP_RSHIFT,
        ];
        test_ok_with_stack(&v, vec![vec![0b00000000, 0b00000010, 0b00000100]]);
        let v = [
            OP_PUSH + 4,
            0b10000001,
            0b10000010,
            0b10000100,
            0b10001000,
            OP_9,
            OP_RSHIFT,
        ];
        test_ok_with_stack(&v, vec![vec![0, 0b01000000, 0b11000001, 0b01000010]]);
        let v = [
            OP_PUSH + 4,
            0b10000001,
            0b10000010,
            0b10000100,
            0b10001000,
            OP_PUSH + 1,
            17,
            OP_RSHIFT,
        ];
        test_ok_with_stack(&v, vec![vec![0, 0, 0b01000000, 0b11000001]]);
        let v = [OP_PUSH + 2, 0xff, 0xff, OP_16, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0, 0]]);
        let v = [OP_PUSH + 2, 0xff, 0xff, OP_PUSH + 1, 17, OP_RSHIFT];
        test_ok_with_stack(&v, vec![vec![0, 0]]);
        test_err(
            &[OP_0, OP_NEG1, OP_RSHIFT],
            ExecuteError::Stack(StackError::BadElement),
        );
        test_err(
            &[OP_0, OP_PUSH + 2, 0xff, 0xff, OP_RSHIFT],
            ExecuteError::Stack(StackError::BadElement),
        );
    }

    #[test]
    fn op_equal() {
        test_ok_with_stack(&[OP_0, OP_0, OP_EQUAL], vec![vec![1]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_EQUAL], vec![vec![]]);
        test_ok_with_stack(&[OP_1, OP_0, OP_EQUAL], vec![vec![]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_EQUAL], vec![vec![1]]);
        let v = [OP_PUSH + 2, 0, 0, OP_PUSH + 2, 0, 0, OP_EQUAL];
        test_ok_with_stack(&v, vec![vec![1]]);
        let v = [OP_PUSH + 2, 0, 0, OP_PUSH + 2, 0, 1, OP_EQUAL];
        test_ok_with_stack(&v, vec![vec![]]);
        let v = [OP_PUSH + 2, 0, 1, OP_PUSH + 2, 0, 0, OP_EQUAL];
        test_ok_with_stack(&v, vec![vec![]]);
        let v = [OP_PUSH + 2, 0, 1, OP_PUSH + 2, 0, 1, OP_EQUAL];
        test_ok_with_stack(&v, vec![vec![1]]);
        test_ok_with_stack(&[OP_PUSH + 3, 0, 0, 0, OP_0, OP_EQUAL], vec![vec![]]);
        test_err(&[OP_EQUAL], ExecuteError::Stack(StackError::Underflow));
        test_err(
            &[OP_0, OP_EQUAL],
            ExecuteError::Stack(StackError::Underflow),
        );
    }

    #[test]
    fn op_add() {
        test_ok_with_stack(&[OP_0, OP_0, OP_ADD], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_ADD], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_0, OP_ADD], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_ADD], vec![vec![2]]);
        test_ok_with_stack(&[OP_1, OP_NEG1, OP_ADD], vec![vec![]]);
        test_ok_with_stack(&[OP_2, OP_NEG1, OP_ADD], vec![vec![1]]);
        let v = [OP_PUSH + 2, 0, 0, OP_PUSH + 2, 0, 0, OP_ADD];
        test_ok_with_stack(&v, vec![vec![]]);
        let v = [OP_PUSH + 2, 1, 0, OP_PUSH + 2, 1, 0, OP_ADD];
        test_ok_with_stack(&v, vec![vec![2]]);
        let v = [OP_PUSH + 2, 0xff, 0, OP_1, OP_ADD];
        test_ok_with_stack(&v, vec![vec![0, 1]]);
        let v = [OP_PUSH + 2, 0xff, 0xff, OP_1, OP_ADD];
        test_ok_with_stack(&v, vec![vec![]]);
        test_err(&[OP_ADD], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_ADD], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_sub() {
        test_ok_with_stack(&[OP_0, OP_0, OP_SUB], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_SUB], vec![vec![0xff]]);
        test_ok_with_stack(&[OP_1, OP_0, OP_SUB], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_SUB], vec![vec![]]);
        test_ok_with_stack(&[OP_1, OP_NEG1, OP_SUB], vec![vec![2]]);
        test_ok_with_stack(&[OP_2, OP_NEG1, OP_SUB], vec![vec![3]]);
        let v = [OP_PUSH + 2, 0, 0, OP_PUSH + 2, 0, 0, OP_SUB];
        test_ok_with_stack(&v, vec![vec![]]);
        let v = [OP_PUSH + 2, 1, 0, OP_PUSH + 2, 1, 0, OP_SUB];
        test_ok_with_stack(&v, vec![vec![]]);
        let v = [OP_PUSH + 2, 0xff, 0, OP_1, OP_SUB];
        test_ok_with_stack(&v, vec![vec![0xfe, 0]]);
        let v = [OP_PUSH + 2, 0xff, 0xff, OP_1, OP_SUB];
        test_ok_with_stack(&v, vec![vec![0xfe]]);
        test_err(&[OP_SUB], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_SUB], ExecuteError::Stack(StackError::Underflow));
    }

    #[test]
    fn op_mul() {
        test_ok_with_stack(&[OP_0, OP_0, OP_MUL], vec![vec![]]);
        test_ok_with_stack(&[OP_0, OP_1, OP_MUL], vec![vec![]]);
        test_ok_with_stack(&[OP_1, OP_0, OP_MUL], vec![vec![]]);
        test_ok_with_stack(&[OP_1, OP_1, OP_MUL], vec![vec![1]]);
        test_ok_with_stack(&[OP_1, OP_NEG1, OP_MUL], vec![vec![0xff]]);
        test_ok_with_stack(&[OP_2, OP_NEG1, OP_MUL], vec![vec![0xfe]]);
        test_ok_with_stack(&[OP_2, OP_2, OP_MUL], vec![vec![4]]);
        test_ok_with_stack(&[OP_2, OP_3, OP_MUL], vec![vec![6]]);
        test_ok_with_stack(&[OP_3, OP_4, OP_MUL], vec![vec![12]]);
        test_ok_with_stack(&[OP_16, OP_16, OP_MUL], vec![vec![0, 1]]);
        let v = [OP_PUSH + 2, 0, 0, OP_PUSH + 2, 0, 0, OP_MUL];
        test_ok_with_stack(&v, vec![vec![]]);
        let v = [OP_PUSH + 2, 1, 0, OP_PUSH + 2, 1, 0, OP_MUL];
        test_ok_with_stack(&v, vec![vec![1]]);
        let v = [OP_PUSH + 2, 0xff, 0, OP_1, OP_MUL];
        test_ok_with_stack(&v, vec![vec![0xff, 0]]);
        let v = [OP_PUSH + 2, 0xff, 0xff, OP_1, OP_MUL];
        test_ok_with_stack(&v, vec![vec![0xff]]);
        test_err(&[OP_MUL], ExecuteError::Stack(StackError::Underflow));
        test_err(&[OP_0, OP_MUL], ExecuteError::Stack(StackError::Underflow));
    }
}
