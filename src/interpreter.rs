use crate::{
    errors::{ExecuteError, ScriptError},
    opcodes::*,
    script::skip_branch,
    sig_verifier::SigVerifier,
    stack::{decode_bool, decode_num, encode_bool, Stack},
    vm::Vm,
};

pub trait Interpreter {
    type SigVerifier: SigVerifier;
    type Vm: Vm;

    fn execute(&mut self, script: &[u8]) -> Result<(), ExecuteError>;
}

pub struct InterpreterImpl<S: SigVerifier, V: Vm> {
    _sig_verifier: S,
    vm: V,
}

impl<S: SigVerifier, V: Vm> InterpreterImpl<S, V> {
    pub fn new(sig_verifier: S, vm: V) -> Self {
        Self {
            _sig_verifier: sig_verifier,
            vm,
        }
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

                /*
                OP_SWAPN => {
                    let n: u64 = decode_num(vm.stack().pop()?)?;
                    vm.stack().swap(n as usize)?;
                }

                OP_SWAP..=OP_SWAP9 => {
                    let n = (opcode - OP_SWAP) as usize + 1;
                    vm.stack().swap(n)?;
                }

                OP_DROP => {
                    vm.stack().pop()?;
                }

                OP_DEPTH => {
                    let len = vm.stack().len();
                    vm.stack().push(encode_bigint(BigInt::from(len)))?;
                }

                OP_TOALTSTACK => {
                    vm.stack().to_altstack()?;
                }

                OP_FROMALTSTACK => {
                    vm.stack().from_altstack()?;
                }

                OP_CAT => {
                    let b: Vec<u8> = vm.stack().pop()?;
                    let a: Vec<u8> = vm.stack().pop()?;
                    vm.stack().push([a, b].concat())?;
                }

                OP_SPLIT => {
                    let n: u64 = decode_num(vm.stack().pop()?)?;
                    let a: Vec<u8> = vm.stack().pop()?;
                    if n as usize > a.len() {
                        Err(StackError::BadArg)?;
                    }
                    let (left, right) = a.split_at(n as usize);
                    vm.stack().push(left.to_vec())?;
                    vm.stack().push(right.to_vec())?;
                }

                OP_SIZE => {
                    let len = vm
                        .stack()
                        .last()
                        .ok_or(ExecuteError::Stack(StackError::Empty))?
                        .len();
                    vm.stack().push(encode_bigint(BigInt::from(len)))?;
                }

                OP_NUM2BIN => {
                    let size: u64 = decode_num(vm.stack().pop()?)?;
                    let n = decode_bigint(vm.stack().pop()?);
                    let mut bytes = if n.sign() == Sign::NoSign {
                        vec![]
                    } else {
                        n.to_signed_bytes_le()
                    };
                    if (size as usize) < bytes.len() {
                        Err(StackError::BadArg)?;
                    }
                    let byte = if n.sign() == Sign::Minus { 0xff } else { 0 };
                    bytes.extend_from_slice(&vec![byte; size as usize - bytes.len()]);
                    vm.stack().push(bytes)?;
                }

                OP_BIN2NUM => {
                    let n = decode_bigint(vm.stack().pop()?);
                    vm.stack().push(encode_bigint(n))?;
                }

                OP_INVERT => {
                    let mut buf: Vec<u8> = vm.stack().pop()?;
                    buf.iter_mut().for_each(|b| *b = !*b);
                    vm.stack().push(buf)?;
                }

                OP_AND | OP_OR | OP_XOR => {
                    let b: Vec<u8> = vm.stack().pop()?;
                    let a: Vec<u8> = vm.stack().pop()?;
                    if a.len() != b.len() {
                        Err(StackError::BadArg)?;
                    }
                    let r = match opcode {
                        OP_AND => a.iter().zip(b.iter()).map(|(x, y)| x & y).collect(),
                        OP_OR => a.iter().zip(b.iter()).map(|(x, y)| x | y).collect(),
                        OP_XOR => a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect(),
                        _ => unreachable!(),
                    };
                    vm.stack().push(r)?;
                }

                OP_LSHIFT => {
                    let b = decode_num::<u64>(vm.stack().pop()?)? as usize;
                    let mut a: Vec<u8> = vm.stack().pop()?;
                    for i in 0..a.len() {
                        if b % 8 == 0 {
                            a[i] = *a.get(i + b / 8).unwrap_or(&0);
                        } else {
                            let l = *a.get(i + b / 8).unwrap_or(&0);
                            let r = *a.get(i + b / 8 + 1).unwrap_or(&0);
                            a[i] = (l << (b % 8)) | (r >> (8 - b % 8));
                        }
                    }
                    vm.stack().push(a)?;
                }

                OP_RSHIFT => {
                    let b = decode_num::<u64>(vm.stack().pop()?)? as usize;
                    let mut a: Vec<u8> = vm.stack().pop()?;
                    for i in (0..a.len()).rev() {
                        if b % 8 == 0 {
                            a[i] = if i >= b / 8 { a[i - b / 8] } else { 0 };
                        } else {
                            let l = if i >= b / 8 + 1 { a[i - b / 8 - 1] } else { 0 };
                            let r = if i >= b / 8 { a[i - b / 8] } else { 0 };
                            a[i] = (l << (8 - b % 8)) | (r >> (b % 8));
                        }
                    }
                    vm.stack().push(a)?;
                }

                OP_EQUAL => {
                    let b: Vec<u8> = vm.stack().pop()?;
                    let a: Vec<u8> = vm.stack().pop()?;
                    vm.stack().push(encode_bool(a == b))?;
                }

                OP_ADD | OP_SUB | OP_MUL | OP_DIV | OP_MOD | OP_NUMEQUAL | OP_LT | OP_GT => {
                    let b = decode_bigint(vm.stack().pop()?);
                    let a = decode_bigint(vm.stack().pop()?);
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
                    vm.stack().push(r)?;
                }

                OP_BLAKE3 => {
                    let data: Vec<u8> = vm.stack().pop()?;
                    vm.stack().push(blake3::hash(&data).as_bytes().to_vec())?;
                }

                OP_SHA256 => {
                    let data: Vec<u8> = vm.stack().pop()?;
                    let mut sha256 = Sha256::new();
                    sha256.update(&data);
                    vm.stack().push(sha256.finalize().as_slice().to_vec())?;
                }

                OP_SPEND => {
                    let location_buf = read(script, &mut i, LOCATION_LEN)?;
                    let location: Location = location_buf.try_into().unwrap();
                    vm.stack().push(location.to_vec())?;
                    vm.spend()?;
                }

                OP_SIGN | OP_SIGNTO => {
                    let index = i - 1;
                    let pubkey_buf = read(script, &mut i, PUBKEY_LEN)?;
                    let sig_buf = read(script, &mut i, SIG_LEN)?;
                    let pubkey: PubKey = pubkey_buf.try_into().unwrap();
                    let sig: Sig = sig_buf.try_into().unwrap();
                    sig_verifier.verify(&pubkey, &sig, index)?;
                    vm.stack().push(pubkey.to_vec())?;
                    vm.auth()?;
                }

                OP_DEPLOY => {
                    vm.deploy()?;
                }

                OP_CREATE => {
                    vm.create()?;
                }

                OP_CALL => {
                    vm.call()?;
                }

                OP_READ => {
                    vm.read()?;
                }

                OP_ASSIGN => {
                    vm.assign()?;
                }

                OP_STATE => {
                    vm.state()?;
                }

                OP_OWNER => {
                    vm.owner()?;
                }

                OP_CLASS => {
                    vm.class()?;
                }

                OP_HEIGHT => {
                    vm.height()?;
                }

                OP_FUND => {
                    vm.fund()?;
                }

                OP_COLLECT => {
                    vm.collect()?;
                }
                */
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
    use crate::{core::Tx, sig_verifier::SigVerifierImpl, stack::StackImpl, vm::VmImpl};

    #[test]
    #[should_panic]
    fn test_interpreter() {
        let tx = Tx {
            version: 1,
            script: vec![0x01, 0x02, 0x03],
        };
        let sig_verifier = SigVerifierImpl::new(&tx);
        let stack = StackImpl::default();
        let vm = VmImpl::new(stack);
        let mut interpreter = InterpreterImpl::new(sig_verifier, vm);
        interpreter.execute(&tx.script).ok();
    }
}
