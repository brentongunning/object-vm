use crate::errors::StackError;

pub trait Stack {
    fn clear(&mut self);
    fn push(&mut self, buf: &[u8]) -> Result<(), StackError>;
    fn top(&self) -> Option<&[u8]>;
    fn drop(&mut self, index: usize) -> Result<(), StackError>;
    fn swap(&mut self, index: usize) -> Result<(), StackError>;
    fn depth(&self) -> usize;
    fn push_to_alt_stack(&mut self) -> Result<(), StackError>;
    fn pop_from_alt_stack(&mut self) -> Result<(), StackError>;
}

#[derive(Default)]
pub struct StackImpl {
    stack: Vec<Vec<u8>>,
    alt: Vec<Vec<u8>>,
}

impl Stack for StackImpl {
    fn clear(&mut self) {
        self.stack.clear();
        self.alt.clear();
    }

    fn push(&mut self, buf: &[u8]) -> Result<(), StackError> {
        self.stack.push(buf.to_vec());
        Ok(())
    }

    fn top(&self) -> Option<&[u8]> {
        self.stack.last().map(|v| v.as_slice())
    }

    fn drop(&mut self, index: usize) -> Result<(), StackError> {
        if index >= self.stack.len() {
            return Err(StackError::Underflow);
        }
        let index = self.stack.len() - 1 - index;
        self.stack.remove(index);
        Ok(())
    }

    fn swap(&mut self, index: usize) -> Result<(), StackError> {
        if index >= self.stack.len() {
            return Err(StackError::Underflow);
        }
        let index = self.stack.len() - 1 - index;
        let index2 = self.stack.len() - 1;
        self.stack.swap(index, index2);
        Ok(())
    }

    fn depth(&self) -> usize {
        self.stack.len()
    }

    fn push_to_alt_stack(&mut self) -> Result<(), StackError> {
        if let Some(top) = self.stack.pop() {
            self.alt.push(top);
            Ok(())
        } else {
            Err(StackError::Underflow)
        }
    }

    fn pop_from_alt_stack(&mut self) -> Result<(), StackError> {
        if let Some(top) = self.alt.pop() {
            self.stack.push(top);
            Ok(())
        } else {
            Err(StackError::Underflow)
        }
    }
}

pub fn pop_bool(s: &mut impl Stack) -> Result<bool, StackError> {
    let top = s.top().ok_or(StackError::Underflow)?;
    let value = top.iter().any(|&x| x != 0);
    s.drop(0)?;
    Ok(value)
}

pub fn push_bool(s: &mut impl Stack, value: bool) -> Result<(), StackError> {
    if value {
        s.push(&[1])?;
    } else {
        s.push(&[])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stack() {
        let stack = StackImpl::default();
        assert_eq!(stack.depth(), 0);
    }

    #[test]
    fn push() {
        let mut stack = StackImpl::default();
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.top().unwrap(), &[4, 5, 6]);
        stack.drop(0).unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn top() {
        let mut stack = StackImpl::default();
        assert_eq!(stack.top(), None);
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn drop() {
        let mut stack = StackImpl::default();
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.drop(0).unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
        assert!(matches!(stack.drop(1), Err(StackError::Underflow)));
    }

    #[test]
    fn swap() {
        let mut stack = StackImpl::default();
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.swap(1).unwrap();
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
        stack.swap(1).unwrap();
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.top().unwrap(), &[4, 5, 6]);
        assert!(matches!(stack.swap(2), Err(StackError::Underflow)));
    }

    #[test]
    fn depth() {
        let mut stack = StackImpl::default();
        assert_eq!(stack.depth(), 0);
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.depth(), 1);
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.depth(), 2);
        stack.drop(0).unwrap();
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn push_to_alt_stack() {
        let mut stack = StackImpl::default();
        let r = stack.push_to_alt_stack();
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.push(&[1, 2, 3]).unwrap();
        stack.push_to_alt_stack().unwrap();
        assert_eq!(stack.depth(), 0);
        assert_eq!(stack.alt.len(), 1);
        assert_eq!(stack.alt[0], [1, 2, 3]);
    }

    #[test]
    fn pop_from_alt_stack() {
        let mut stack = StackImpl::default();
        let r = stack.pop_from_alt_stack();
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.alt.push([1, 2, 3].to_vec());
        stack.pop_from_alt_stack().unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
        assert_eq!(stack.alt.len(), 0);
    }

    #[test]
    fn clear() {
        let mut stack = StackImpl::default();
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.push_to_alt_stack().unwrap();
        stack.clear();
        assert_eq!(stack.depth(), 0);
        assert_eq!(stack.alt.len(), 0);
    }

    #[test]
    fn pop_bool() {
        use super::pop_bool;
        let mut stack = StackImpl::default();
        let r = pop_bool(&mut stack);
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.push(&[]).unwrap();
        assert_eq!(pop_bool(&mut stack).unwrap(), false);
        stack.push(&[0]).unwrap();
        assert_eq!(pop_bool(&mut stack).unwrap(), false);
        stack.push(&[1]).unwrap();
        assert_eq!(pop_bool(&mut stack).unwrap(), true);
        stack.push(&[0, 0, 0]).unwrap();
        assert_eq!(pop_bool(&mut stack).unwrap(), false);
        stack.push(&[0, 0, 1]).unwrap();
        assert_eq!(pop_bool(&mut stack).unwrap(), true);
    }

    #[test]
    fn push_bool() {
        use super::push_bool;
        let mut stack = StackImpl::default();
        push_bool(&mut stack, false).unwrap();
        assert_eq!(stack.top().unwrap(), &[]);
        push_bool(&mut stack, true).unwrap();
        assert_eq!(stack.top().unwrap(), &[1]);
    }
}
