use crate::{errors::VmError, stack::Stack};

pub trait Vm {
    type Stack: Stack;

    fn stack(&mut self) -> &mut Self::Stack;

    fn deploy(&mut self) -> Result<(), VmError>;
    fn create(&mut self) -> Result<(), VmError>;
    fn call(&mut self) -> Result<(), VmError>;
    fn state(&mut self) -> Result<(), VmError>;
    fn contract(&mut self) -> Result<(), VmError>;

    fn uniquifier(&mut self) -> Result<(), VmError>;
    fn fund(&mut self) -> Result<(), VmError>;

    fn sigcheck(&mut self) -> Result<(), VmError>;
    fn caller(&mut self) -> Result<(), VmError>;
}

pub struct VmImpl<S: Stack> {
    stack: S,
}

impl<S: Stack> VmImpl<S> {
    pub fn new(stack: S) -> Self {
        Self { stack }
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

    fn contract(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn uniquifier(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn fund(&mut self) -> Result<(), VmError> {
        unimplemented!();
    }

    fn sigcheck(&mut self) -> Result<(), VmError> {
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
    #[should_panic]
    fn test_vm() {
        let stack = StackImpl::default();
        let mut vm = VmImpl::new(stack);
        vm.deploy().ok();
    }
}
