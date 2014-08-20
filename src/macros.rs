//! Macros
#![macro_escape]


#[macro_export]
macro_rules! try_ok_opt(
    ($e:expr) => (match $e { Ok(e) => e, Err(_) => return None })
)

#[macro_export]
macro_rules! try_ok_unit(
    ($e:expr) => (match $e { Ok(e) => e, Err(_) => return Err(()) })
)

#[macro_export]
macro_rules! try_some_err(
    ($e:expr) => (match $e { Some(e) => e, None => return Err(()) })
)

#[macro_export]
macro_rules! try_some(
    ($e:expr) => (match $e { Some(e) => e, None => return None })
)

#[macro_export]
macro_rules! try_some_bool(
    ($e:expr) => (match $e { Some(e) => e, None => return false })
)
