use crate::stack::{Error as StackError, Stack};

pub trait Vm {
    type Stack: Stack;

    fn stack(&mut self) -> &mut Self::Stack;

    fn deploy(&mut self) -> Result<(), Error>;
    fn create(&mut self) -> Result<(), Error>;
    fn call(&mut self) -> Result<(), Error>;
    fn state(&mut self) -> Result<(), Error>;
    fn contract(&mut self) -> Result<(), Error>;

    fn uniquifier(&mut self) -> Result<(), Error>;
    fn fund(&mut self) -> Result<(), Error>;

    fn sigcheck(&mut self) -> Result<(), Error>;
    fn caller(&mut self) -> Result<(), Error>;
}

pub enum Error {
    Stack(StackError),
}
