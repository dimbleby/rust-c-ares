use std::time::Duration;

use c_ares_resolver::Options;

pub fn test_options() -> Options {
    let mut options = Options::new();
    options.set_timeout(Duration::from_secs(5)).set_tries(2);
    options
}
