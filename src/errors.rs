#[derive(Debug)]
pub enum ExecuteError {}

#[derive(Debug)]
pub enum StackError {
    Underflow,
    Overflow,
}

#[derive(Debug)]
pub enum VerifyError {}

#[derive(Debug)]
pub enum VmError {
    Stack(StackError),
}
