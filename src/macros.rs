//! Macros
#![macro_escape]


#[macro_export]
macro_rules! try_none(
    ($e:expr) => (match $e { Ok(e) => e, Err(_) => return None })
)

#[macro_export]
macro_rules! try_unit(
    ($e:expr) => (match $e { Ok(e) => e, Err(_) => return Err(()) })
)

#[macro_export]
macro_rules! try_err(
    ($e:expr) => (match $e { Some(e) => e, None => return Err(()) })
)

#[macro_export]
macro_rules! try_option(
    ($e:expr) => (match $e { Some(e) => e, None => return None })
)

#[macro_export]
macro_rules! try_opt_bool(
    ($e:expr) => (match $e { Some(e) => e, None => return false })
)
