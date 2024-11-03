use crate::{errors::ExecuteError, sig_verifier::SigVerifier, vm::Vm};

pub trait Interpreter {
    type SigVerifier: SigVerifier;
    type Vm: Vm;

    fn execute(&mut self, script: &[u8]) -> Result<(), ExecuteError>;
}

pub struct InterpreterImpl<S: SigVerifier, V: Vm> {
    _sig_verifier: S,
    _vm: V,
}

impl<S: SigVerifier, V: Vm> InterpreterImpl<S, V> {
    pub fn new(sig_verifier: S, vm: V) -> Self {
        Self {
            _sig_verifier: sig_verifier,
            _vm: vm,
        }
    }
}

impl<S: SigVerifier, V: Vm> Interpreter for InterpreterImpl<S, V> {
    type SigVerifier = S;
    type Vm = V;

    fn execute(&mut self, _script: &[u8]) -> Result<(), ExecuteError> {
        unimplemented!();
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
