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
