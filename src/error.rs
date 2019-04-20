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

pub trait Future01Ext<S, E: Fail>: Sized + futures01::Future<Item = S, Error = E> {
    fn chain_inspect_err_fut<ErrorKindT: ChainErrorKind>(
        self,
        fn_in: impl FnOnce(&mut E) -> ErrorKindT + Send + Sync + 'static,
    ) -> futures01::MapErr<Self, Box<dyn FnOnce(E) -> ErrorKindT::Error + Send + Sync>> {
        self.map_err(Box::new(|mut e| {
            let kind = fn_in(&mut e);
            e.context(kind).into()
        }))
    }

    fn chain_err_fut<ErrorKindT: ChainErrorKind>(
        self,
        fn_in: impl FnOnce() -> ErrorKindT + Send + Sync + 'static,
    ) -> futures01::MapErr<Self, Box<dyn FnOnce(E) -> ErrorKindT::Error + Send + Sync>> {
        self.chain_inspect_err_fut(|_| fn_in())
    }
}

impl<S, E: Fail, F: futures01::Future<Item = S, Error = E>> Future01Ext<S, E> for F {}
