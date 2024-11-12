use crate::{
    core::PubKey,
    errors::VmError,
    stack::{decode_arr, Stack},
};
use std::collections::HashSet;

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

pub struct VmImpl<S: Stack> {
    stack: S,
    pending_sigs: HashSet<PubKey>,
}

impl<S: Stack> VmImpl<S> {
    pub fn new(stack: S) -> Self {
        Self {
            stack,
            pending_sigs: HashSet::new(),
        }
    }
}

impl<S: Stack> Vm for VmImpl<S> {
    type Stack = S;

    fn stack(&mut self) -> &mut Self::Stack {
        &mut self.stack
    }

    fn deploy(&mut self) -> Result<(), VmError> {
        unimplemented!();
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
    use crate::stack::StackImpl;

    #[test]
    fn stack() {
        let mut stack = StackImpl::new(1024, 256, 32);
        stack.push(&[1, 2, 3]).ok();
        let mut vm = VmImpl::new(stack);
        assert_eq!(vm.stack().pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
    }
}
