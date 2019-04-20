use failchain::{BoxedError, ChainErrorKind};
use failure::Fail;
use std::result::Result as StdResult;

pub type Error = BoxedError<ErrorKind>;
pub type Result<T> = StdResult<T, Error>;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Json Parse Error: {}", 0)]
    JsonParseError(String),

    #[fail(display = "Other Error: {}", 0)]
    OtherError(String),
}

impl ChainErrorKind for ErrorKind {
    type Error = Error;
}
