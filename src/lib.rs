//! Common Rust utilities.
//!
#![crate_name = "common"]
#![comment = "Common Rust utilities"]
#![license = "MIT/ASL2"]
#![experimental]  // Stability
#![doc(html_logo_url = "http://www.rust-lang.org/logos/rust-logo-128x128-blk.png",
       html_favicon_url = "http://www.rust-lang.org/favicon.ico",
       html_root_url = "http://doc.rust-lang.org/")]

#![feature(macro_rules)]
#![feature(unsafe_destructor)]
#![feature(default_type_params)]
#![feature(phase)]

#[cfg(test)] extern crate test;
#[cfg(test)] extern crate debug;
#[cfg(test)] #[phase(plugin, link)] extern crate log;

extern crate alloc;
extern crate libc;
extern crate serialize;

pub mod macros;
pub mod utils;
pub mod sbuf;
