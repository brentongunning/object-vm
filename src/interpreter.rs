use crate::{errors::ExecuteError, sig_verifier::SigVerifier, vm::Vm};

pub trait Interpreter {
    type SigVerifier: SigVerifier;
    type Vm: Vm;

    fn execute(script: &[u8]) -> Result<(), ExecuteError>;
}
