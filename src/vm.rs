use crate::{
    core::{Id, PubKey},
    errors::VmError,
    stack::{decode_arr, Stack},
    wasm::Wasm,
};
use std::collections::{HashMap, HashSet};

pub trait Vm {
    type Stack: Stack;

    fn stack(&mut self) -> &mut Self::Stack;

    fn deploy(&mut self) -> Result<(), VmError>; // code -- class_id
    fn create(&mut self) -> Result<(), VmError>; // args.. class_id -- object_id
    fn call(&mut self) -> Result<(), VmError>; // args.. object_id -- result..
    fn state(&mut self) -> Result<(), VmError>; // object_id -- state
    fn class(&mut self) -> Result<(), VmError>; // object_id -- class_id

    fn auth(&mut self) -> Result<(), VmError>; // pubkey --
    fn uniquifier(&mut self) -> Result<(), VmError>; // revision_id --
    fn fund(&mut self) -> Result<(), VmError>; // object_id --

    // TODO: Finalize

    fn caller(&mut self) -> Result<(), VmError>; // index -- object_id
}

pub struct VmImpl<S: Stack, W: Wasm> {
    stack: S,
    wasm: W,
    pending_sigs: HashSet<PubKey>,
    // TODO: outputs
    deployed_code: HashMap<Id, Vec<u8>>,
}

impl<S: Stack, W: Wasm> VmImpl<S, W> {
    pub fn new(stack: S, wasm: W) -> Self {
        Self {
            stack,
            wasm,
            pending_sigs: HashSet::new(),
            deployed_code: HashMap::new(),
        }
    }
}

impl<S: Stack, W: Wasm> Vm for VmImpl<S, W> {
    type Stack = S;

    fn stack(&mut self) -> &mut Self::Stack {
        &mut self.stack
    }

    fn deploy(&mut self) -> Result<(), VmError> {
        let code = self.stack.pop(|x| x.to_vec())?;
        let class_id = self.wasm.deploy(&code)?;
        self.stack.push(&class_id)?;
        self.deployed_code.insert(class_id, code);
        Ok(())
    }

    fn create(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn call(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn state(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn class(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn auth(&mut self) -> Result<(), VmError> {
        let pubkey: PubKey = self.stack().pop(decode_arr)??;
        self.pending_sigs.remove(&pubkey);
        Ok(())
    }

    fn uniquifier(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn fund(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn caller(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{stack::StackImpl, wasm::WasmImpl};

    #[test]
    fn stack() {
        let mut stack = StackImpl::new(1024, 256, 32);
        stack.push(&[1, 2, 3]).ok();
        let wasm = WasmImpl {};
        let mut vm = VmImpl::new(stack, wasm);
        assert_eq!(vm.stack().pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
    }
}
