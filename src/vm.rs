use crate::{
    coin::COIN_CLASS_ID,
    core::{Id, Output, PubKey},
    errors::VmError,
    stack::{decode_arr, Stack},
    wasm::Wasm,
};
use std::collections::{HashMap, HashSet};

const NULL_CALLER: Id = [0; 32];

pub trait Vm {
    type Stack: Stack;

    fn begin(&mut self, txid: &Id) -> Result<(), VmError>;
    fn end(&mut self) -> Result<(), VmError>;
    fn outputs(&mut self, f: impl FnMut(&Id, &Output)) -> Result<(), VmError>;
    fn stack(&mut self) -> &mut Self::Stack;

    fn deploy(&mut self) -> Result<(), VmError>; // code -- class_id
    fn create(&mut self) -> Result<(), VmError>; // args.. class_id -- object_id
    fn call(&mut self) -> Result<(), VmError>; // args.. object_id -- result..
    fn state(&mut self) -> Result<(), VmError>; // object_id -- state
    fn class(&mut self) -> Result<(), VmError>; // object_id -- class_id

    fn auth(&mut self) -> Result<(), VmError>; // pubkey --
    fn uniquifier(&mut self) -> Result<(), VmError>; // revision_id --
    fn fund(&mut self) -> Result<(), VmError>; // object_id --

    fn caller(&mut self) -> Result<(), VmError>; // index -- object_id
}

// TODO: Limits

pub struct VmImpl<S: Stack, W: Wasm> {
    stack: S,
    wasm: W,
    txid: Id,
    caller_stack: Vec<Id>,
    pending_sigs: HashSet<PubKey>,
    pending_uniquifiers: HashSet<Id>,
    outputs: HashMap<Id, Output>,
    num_new_objects: u32,
}

impl<S: Stack, W: Wasm> VmImpl<S, W> {
    pub fn new(stack: S, wasm: W) -> Self {
        Self {
            stack,
            wasm,
            txid: [0; 32],
            caller_stack: Vec::new(),
            pending_sigs: HashSet::new(),
            pending_uniquifiers: HashSet::new(),
            outputs: HashMap::new(),
            num_new_objects: 0,
        }
    }

    fn new_object_id(&mut self) -> Id {
        let mut preimage = [0; 36];
        preimage[..32].copy_from_slice(&self.txid);
        preimage[32..].copy_from_slice(&self.num_new_objects.to_le_bytes());
        self.num_new_objects += 1;
        blake3::hash(&preimage).into()
    }
}

impl<S: Stack, W: Wasm> Vm for VmImpl<S, W> {
    type Stack = S;

    fn begin(&mut self, txid: &Id) -> Result<(), VmError> {
        self.stack.clear();
        self.wasm.reset()?;
        self.txid = *txid;
        self.caller_stack.clear();
        self.pending_sigs.clear();
        self.pending_uniquifiers.clear();
        self.outputs.clear();
        self.num_new_objects = 0;
        Ok(())
    }

    fn end(&mut self) -> Result<(), VmError> {
        if !self.pending_sigs.is_empty() {
            return Err(VmError::Unsigned);
        }

        let mut object_ids = vec![];
        self.wasm.objects(|id| object_ids.push(*id))?;
        for id in object_ids {
            let class_id = *self.wasm.class(&id)?;
            let state = self.wasm.state(&id)?.to_vec();
            let mut revision_id = [0; 32];
            (0..32).for_each(|i| revision_id[i] = self.txid[i] ^ id[i]);
            self.outputs.insert(
                id,
                Output::Object {
                    class_id,
                    revision_id,
                    state,
                },
            );
        }

        let mut revision_ids = HashSet::new();
        self.wasm.inputs(|id| {
            revision_ids.insert(*id);
        })?;
        if !self.pending_uniquifiers.is_subset(&revision_ids) {
            return Err(VmError::MissingUniquifier);
        }

        Ok(())
    }

    fn outputs(&mut self, mut f: impl FnMut(&Id, &Output)) -> Result<(), VmError> {
        self.outputs.iter().for_each(|(id, output)| f(id, output));
        Ok(())
    }

    fn stack(&mut self) -> &mut Self::Stack {
        &mut self.stack
    }

    fn deploy(&mut self) -> Result<(), VmError> {
        let code = self.stack.pop(|x| x.to_vec())?;
        let class_id = blake3::hash(&code).into();
        self.wasm.deploy(&code, &class_id)?;
        self.stack.push(&class_id)?;
        let output = Output::Class { code };
        self.outputs.insert(class_id, output);
        Ok(())
    }

    fn create(&mut self) -> Result<(), VmError> {
        let class_id: Id = self.stack.pop(decode_arr)??;
        let object_id = self.new_object_id();
        self.caller_stack.push(object_id);
        self.wasm.create(&class_id, &object_id)?;
        self.stack.push(&object_id)?;
        self.caller_stack.pop().unwrap();
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
        self.stack.push(self.wasm.state(&object_id)?)?;
        Ok(())
    }

    fn class(&mut self) -> Result<(), VmError> {
        let object_id: Id = self.stack.pop(decode_arr)??;
        self.stack.push(self.wasm.class(&object_id)?)?;
        Ok(())
    }

    fn auth(&mut self) -> Result<(), VmError> {
        let pubkey: PubKey = self.stack.pop(decode_arr)??;
        self.pending_sigs.remove(&pubkey);
        Ok(())
    }

    fn uniquifier(&mut self) -> Result<(), VmError> {
        let revision_id: Id = self.stack.pop(decode_arr)??;
        self.pending_uniquifiers.insert(revision_id);
        Ok(())
    }

    fn fund(&mut self) -> Result<(), VmError> {
        let object_id = self.stack.pop(decode_arr)??;
        let class_id = self.wasm.class(&object_id)?;
        if *class_id != COIN_CLASS_ID {
            return Err(VmError::InvalidCoin);
        }
        // TODO: destroy the coin and increase the credits
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
    fn begin() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn end() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn outputs() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn stack() {
        let mut stack = StackImpl::new(1024, 256, 32);
        stack.push(&[1, 2, 3]).ok();
        let wasm = WasmImpl {};
        let mut vm = VmImpl::new(stack, wasm);
        assert_eq!(vm.stack().pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);

        // TODO
        unimplemented!();
    }

    #[test]
    fn deploy() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn create() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn call() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn state() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn class() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn auth() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn uniquifier() {
        // TODO
        unimplemented!();
    }

    #[test]
    fn fund() {
        // TODO
        unimplemented!();
    }
}
