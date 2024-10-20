#[derive(Debug)]
pub enum StackError {
    Underflow,
    Overflow,
}

pub enum VmError {
    Stack(StackError),
}
