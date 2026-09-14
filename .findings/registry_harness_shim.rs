//! Minimal stand-ins for the crate items utils.rs imports, so the registry can
//! be exercised standalone.
use std::fmt;

pub trait MaybeSend: Send {}
impl<T: Send> MaybeSend for T {}
pub trait MaybeSync: Sync {}
impl<T: Sync> MaybeSync for T {}

#[derive(Debug, Clone, PartialEq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}
impl From<CimplError> for Error {
    fn from(e: CimplError) -> Self { Error(e.0) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CimplError(pub String);
impl CimplError {
    pub fn foreign_process() -> Self { CimplError("foreign process".into()) }
    pub fn null_parameter(p: &str) -> Self { CimplError(format!("null parameter: {p}")) }
    pub fn wrong_pointer_type(id: u64) -> Self { CimplError(format!("wrong type 0x{id:x}")) }
    pub fn untracked_pointer(id: u64) -> Self { CimplError(format!("untracked 0x{id:x}")) }
    pub fn pointer_in_use() -> Self { CimplError("pointer in use".into()) }
    pub fn wrong_wrapper_kind() -> Self { CimplError("wrong wrapper".into()) }
    pub fn tracking_refused(m: &str) -> Self { CimplError(format!("refused: {m}")) }
    pub fn invalid_buffer_size(len: usize, n: &str) -> Self { CimplError(format!("bad size {len} {n}")) }
    pub fn other(m: &str) -> Self { CimplError(m.into()) }
    pub fn set_last(self) { LAST.with(|l| *l.borrow_mut() = Some(self)); }
}
impl From<Error> for CimplError {
    fn from(e: Error) -> Self { CimplError(e.0) }
}
impl fmt::Display for CimplError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}
thread_local! {
    static LAST: std::cell::RefCell<Option<CimplError>> = std::cell::RefCell::new(None);
}
