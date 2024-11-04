use crate::errors::StackError;
use num_bigint::{BigInt, Sign};

pub trait Stack {
    fn clear(&mut self);
    fn push(&mut self, buf: &[u8]) -> Result<(), StackError>;
    fn pop<T>(&mut self, f: impl FnOnce(&[u8]) -> T) -> Result<T, StackError>;
    fn dup(&mut self, index: usize) -> Result<(), StackError>;
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

    fn pop<T>(&mut self, f: impl FnOnce(&[u8]) -> T) -> Result<T, StackError> {
        match self.stack.pop() {
            Some(v) => Ok(f(v.as_slice())),
            None => Err(StackError::Underflow),
        }
    }

    fn dup(&mut self, index: usize) -> Result<(), StackError> {
        if index >= self.stack.len() {
            return Err(StackError::Underflow);
        }
        let index = self.stack.len() - 1 - index;
        let elem = self.stack.get(index).unwrap().clone();
        self.stack.push(elem);
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

pub fn decode_bool(elem: &[u8]) -> bool {
    elem.iter().any(|&x| x != 0)
}

pub fn encode_bool(b: bool) -> Vec<u8> {
    if b {
        vec![1]
    } else {
        vec![]
    }
}

pub fn decode_bigint(elem: &[u8]) -> BigInt {
    BigInt::from_signed_bytes_le(elem)
}

pub fn encode_bigint(n: BigInt) -> Vec<u8> {
    if n.sign() == Sign::NoSign {
        vec![]
    } else {
        n.to_signed_bytes_le()
    }
}

pub fn decode_num<T: TryFrom<u64>>(elem: &[u8]) -> Result<T, StackError> {
    let bigint = decode_bigint(elem);
    let (sign, digits) = bigint.to_u64_digits();
    if sign == Sign::Minus || digits.len() > 1 {
        return Err(StackError::BadElement);
    }
    let num_u64 = *digits.get(0).unwrap_or(&0);
    Ok(num_u64.try_into().map_err(|_| StackError::BadElement)?)
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
        stack.push(&[4, 5, 6]).unwrap();
        stack.push(&[7, 8, 9]).unwrap();
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![7, 8, 9]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn pop() {
        let mut stack = StackImpl::default();
        let r = stack.pop(|x| x.to_vec());
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn dup() {
        let mut stack = StackImpl::default();
        let r = stack.dup(0);
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.dup(0).unwrap();
        stack.dup(2).unwrap();
        assert_eq!(stack.depth(), 4);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
        assert!(matches!(stack.dup(0), Err(StackError::Underflow)));
    }

    #[test]
    fn swap() {
        let mut stack = StackImpl::default();
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.swap(1).unwrap();
        assert_eq!(stack.depth(), 2);
        assert!(matches!(stack.swap(2), Err(StackError::Underflow)));
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert!(matches!(stack.swap(0), Err(StackError::Underflow)));
        assert!(matches!(stack.swap(1), Err(StackError::Underflow)));
    }

    #[test]
    fn depth() {
        let mut stack = StackImpl::default();
        assert_eq!(stack.depth(), 0);
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.depth(), 1);
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.depth(), 2);
        stack.pop(|_| {}).unwrap();
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
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
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
    fn decode_bool() {
        use super::decode_bool;
        assert!(!decode_bool(&[]));
        assert!(!decode_bool(&[0]));
        assert!(decode_bool(&[1]));
        assert!(!decode_bool(&[0, 0, 0]));
        assert!(decode_bool(&[0, 0, 1]));
    }

    #[test]
    fn encode_bool() {
        use super::encode_bool;
        assert_eq!(encode_bool(false), vec![]);
        assert_eq!(encode_bool(true), vec![1]);
    }

    #[test]
    fn decode_bigint() {
        use super::decode_bigint;
        assert_eq!(decode_bigint(&[]), BigInt::from(0));
        assert_eq!(decode_bigint(&[0]), BigInt::from(0));
        assert_eq!(decode_bigint(&[1]), BigInt::from(1));
        assert_eq!(decode_bigint(&[1, 0, 0]), BigInt::from(1));
        assert_eq!(decode_bigint(&[1, 0, 0, 0]), BigInt::from(1));
        assert_eq!(decode_bigint(&[1, 0, 0, 0, 0]), BigInt::from(1));
        assert_eq!(decode_bigint(&[0xff]), BigInt::from(-1));
        assert_eq!(decode_bigint(&[0xff, 0xff]), BigInt::from(-1));
        assert_eq!(decode_bigint(&[0xfe, 0xff, 0xff]), BigInt::from(-2));
    }

    #[test]
    fn encode_bigint() {
        use super::encode_bigint;
        assert_eq!(encode_bigint(BigInt::from(0)), vec![]);
        assert_eq!(encode_bigint(BigInt::from(1)), vec![1]);
        assert_eq!(encode_bigint(BigInt::from(255)), vec![255, 0]);
        assert_eq!(encode_bigint(BigInt::from(256)), vec![0, 1]);
        assert_eq!(encode_bigint(BigInt::from(-1)), vec![0xff]);
        assert_eq!(encode_bigint(BigInt::from(-2)), vec![0xfe]);
    }
}
