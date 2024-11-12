use crate::{
    core::{Id, PubKey},
    errors::VmError,
    stack::{decode_arr, Stack},
    wasm::Wasm,
};
use std::collections::{HashMap, HashSet};

const NULL_CALLER: Id = [0; 32];

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
    caller_stack: Vec<Id>,
    pending_sigs: HashSet<PubKey>,
    // TODO: outputs
    deployed_code: HashMap<Id, Vec<u8>>,
}

impl<S: Stack, W: Wasm> VmImpl<S, W> {
    pub fn new(stack: S, wasm: W) -> Self {
        Self {
            stack,
            wasm,
            caller_stack: Vec::new(),
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
        let class_id: Id = self.stack.pop(decode_arr)??;
        let object_id = [0; 32]; // TODO: generate object id
        self.caller_stack.push(object_id);
        self.wasm.create(&class_id, &object_id)?;
        self.stack.push(&object_id)?;
        self.caller_stack.pop().unwrap();
        // TODO: outputs
        Ok(())
    }

    fn call(&mut self) -> Result<(), VmError> {
        let object_id: Id = self.stack.pop(decode_arr)??;
        let different_caller = !self.caller_stack.last().is_some_and(|x| x == &object_id);
        if different_caller {
            self.caller_stack.push(object_id);
            self.wasm.call(&object_id)?;
            self.caller_stack.pop().unwrap();
        } else {
            self.wasm.call(&object_id)?;
        }
        Ok(())
    }

    fn state(&mut self) -> Result<(), VmError> {
        let object_id: Id = self.stack.pop(decode_arr)??;
        self.wasm.state(&object_id)?;
        Ok(())
    }

    fn class(&mut self) -> Result<(), VmError> {
        let object_id: Id = self.stack.pop(decode_arr)??;
        let class_id = self.wasm.class(&object_id)?;
        self.stack.push(&class_id)?;
        Ok(())
    }

    fn auth(&mut self) -> Result<(), VmError> {
        let pubkey: PubKey = self.stack.pop(decode_arr)??;
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
        if let Some(object_id) = self.caller_stack.last() {
            self.stack.push(object_id)?;
        } else {
            self.stack.push(&NULL_CALLER)?;
        }
        Ok(())
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
