mod callbacks;
mod channel;
mod parsers;
mod types;
mod utils;

// Re-export public interfaces.
pub use channel::Channel;
pub use parsers::{
    parse_a_result,
    parse_aaaa_result,
};
pub use types::{
    AresError,
    AResult,
    AAAAResult,
    INVALID_FD,
};
pub use utils::str_error;
