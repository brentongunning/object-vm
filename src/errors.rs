#[derive(Debug)]
pub enum StackError {
    Underflow,
    Overflow,
}

#[derive(Debug)]
pub enum VmError {
    Stack(StackError),
}
