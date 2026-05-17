use core::ffi::c_int;
use std::error;
use std::fmt;
use std::result;

use crate::utils::c_string_as_str_unchecked;

macro_rules! ares_errors {
    ($($(#[$attr:meta])* $variant:ident => $ares:ident,)*) => {
        /// Error codes that the library might return.
        #[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
        pub enum Error {
            $(
                $(#[$attr])*
                $variant = c_ares_sys::ares_status_t::$ares as isize,
            )*
            /// Unknown error.
            UNKNOWN,
        }

        impl From<i32> for Error {
            fn from(code: i32) -> Self {
                match code {
                    $(x if x == Error::$variant as i32 => Error::$variant,)*
                    _ => Error::UNKNOWN,
                }
            }
        }

        impl TryFrom<c_ares_sys::ares_status_t> for Error {
            type Error = ();

            fn try_from(
                status: c_ares_sys::ares_status_t,
            ) -> std::result::Result<Self, ()> {
                match status {
                    c_ares_sys::ares_status_t::ARES_SUCCESS => Err(()),
                    $(c_ares_sys::ares_status_t::$ares => Ok(Error::$variant),)*
                }
            }
        }
    };
}

ares_errors! {
    /// DNS server returned answer with no data.
    ENODATA => ARES_ENODATA,
    /// DNS server claims query was misformatted.
    EFORMERR => ARES_EFORMERR,
    /// DNS server returned general failure.
    ESERVFAIL => ARES_ESERVFAIL,
    /// Domain name not found.
    ENOTFOUND => ARES_ENOTFOUND,
    /// DNS server does not implement requested operation.
    ENOTIMP => ARES_ENOTIMP,
    /// DNS server refused query.
    EREFUSED => ARES_EREFUSED,
    /// Misformatted DNS query.
    EBADQUERY => ARES_EBADQUERY,
    /// Misformatted domain name.
    EBADNAME => ARES_EBADNAME,
    /// Unsupported address family.
    EBADFAMILY => ARES_EBADFAMILY,
    /// Misformatted DNS reply.
    EBADRESP => ARES_EBADRESP,
    /// Could not contact DNS servers.
    ECONNREFUSED => ARES_ECONNREFUSED,
    /// Timeout while contacting DNS servers.
    ETIMEOUT => ARES_ETIMEOUT,
    /// End of file.
    EOF => ARES_EOF,
    /// Error reading file.
    EFILE => ARES_EFILE,
    /// Out of memory.
    ENOMEM => ARES_ENOMEM,
    /// Channel is being destroyed.
    EDESTRUCTION => ARES_EDESTRUCTION,
    /// Misformatted string.
    EBADSTR => ARES_EBADSTR,
    /// Illegal flags specified.
    EBADFLAGS => ARES_EBADFLAGS,
    /// Given hostname is not numeric.
    ENONAME => ARES_ENONAME,
    /// Illegal hints flags specified.
    EBADHINTS => ARES_EBADHINTS,
    /// c-ares library initialization not yet performed.
    ENOTINITIALIZED => ARES_ENOTINITIALIZED,
    /// Error loading iphlpapi.dll.
    ELOADIPHLPAPI => ARES_ELOADIPHLPAPI,
    /// Could not find GetNetworkParams function.
    EADDRGETNETWORKPARAMS => ARES_EADDRGETNETWORKPARAMS,
    /// DNS query cancelled.
    ECANCELLED => ARES_ECANCELLED,
    /// The textual service name provided could not be dereferenced into a port.
    ESERVICE => ARES_ESERVICE,
    /// No DNS servers were configured.
    ENOSERVER => ARES_ENOSERVER,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        let text = unsafe {
            let ptr = c_ares_sys::ares_strerror(*self as c_int);
            c_string_as_str_unchecked(ptr)
        };
        fmt.write_str(text)
    }
}

/// The type used by this library for methods that might fail.
pub type Result<T> = result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn from_i32_known_codes() {
        assert_eq!(Error::from(1), Error::ENODATA);
        assert_eq!(Error::from(2), Error::EFORMERR);
        assert_eq!(Error::from(3), Error::ESERVFAIL);
        assert_eq!(Error::from(4), Error::ENOTFOUND);
        assert_eq!(Error::from(5), Error::ENOTIMP);
        assert_eq!(Error::from(6), Error::EREFUSED);
    }

    #[test]
    fn from_i32_all_known_codes() {
        assert_eq!(Error::from(Error::EBADQUERY as i32), Error::EBADQUERY);
        assert_eq!(Error::from(Error::EBADNAME as i32), Error::EBADNAME);
        assert_eq!(Error::from(Error::EBADFAMILY as i32), Error::EBADFAMILY);
        assert_eq!(Error::from(Error::EBADRESP as i32), Error::EBADRESP);
        assert_eq!(Error::from(Error::ECONNREFUSED as i32), Error::ECONNREFUSED);
        assert_eq!(Error::from(Error::ETIMEOUT as i32), Error::ETIMEOUT);
        assert_eq!(Error::from(Error::EOF as i32), Error::EOF);
        assert_eq!(Error::from(Error::EFILE as i32), Error::EFILE);
        assert_eq!(Error::from(Error::ENOMEM as i32), Error::ENOMEM);
        assert_eq!(Error::from(Error::EDESTRUCTION as i32), Error::EDESTRUCTION);
        assert_eq!(Error::from(Error::EBADSTR as i32), Error::EBADSTR);
        assert_eq!(Error::from(Error::EBADFLAGS as i32), Error::EBADFLAGS);
        assert_eq!(Error::from(Error::ENONAME as i32), Error::ENONAME);
        assert_eq!(Error::from(Error::EBADHINTS as i32), Error::EBADHINTS);
        assert_eq!(
            Error::from(Error::ENOTINITIALIZED as i32),
            Error::ENOTINITIALIZED
        );
        assert_eq!(
            Error::from(Error::ELOADIPHLPAPI as i32),
            Error::ELOADIPHLPAPI
        );
        assert_eq!(
            Error::from(Error::EADDRGETNETWORKPARAMS as i32),
            Error::EADDRGETNETWORKPARAMS
        );
        assert_eq!(Error::from(Error::ECANCELLED as i32), Error::ECANCELLED);
        assert_eq!(Error::from(Error::ESERVICE as i32), Error::ESERVICE);
        assert_eq!(Error::from(Error::ENOSERVER as i32), Error::ENOSERVER);
    }

    #[test]
    fn from_i32_unknown_code() {
        assert_eq!(Error::from(9999), Error::UNKNOWN);
        assert_eq!(Error::from(-9999), Error::UNKNOWN);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exhaustive table-driven test
    fn try_from_status() {
        assert!(Error::try_from(c_ares_sys::ares_status_t::ARES_SUCCESS).is_err());
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ENODATA),
            Ok(Error::ENODATA)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EFORMERR),
            Ok(Error::EFORMERR)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ESERVFAIL),
            Ok(Error::ESERVFAIL)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ENOTFOUND),
            Ok(Error::ENOTFOUND)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ENOTIMP),
            Ok(Error::ENOTIMP)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EREFUSED),
            Ok(Error::EREFUSED)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EBADQUERY),
            Ok(Error::EBADQUERY)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EBADNAME),
            Ok(Error::EBADNAME)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EBADFAMILY),
            Ok(Error::EBADFAMILY)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EBADRESP),
            Ok(Error::EBADRESP)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ECONNREFUSED),
            Ok(Error::ECONNREFUSED)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ETIMEOUT),
            Ok(Error::ETIMEOUT)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EOF),
            Ok(Error::EOF)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EFILE),
            Ok(Error::EFILE)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ENOMEM),
            Ok(Error::ENOMEM)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EDESTRUCTION),
            Ok(Error::EDESTRUCTION)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EBADSTR),
            Ok(Error::EBADSTR)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EBADFLAGS),
            Ok(Error::EBADFLAGS)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ENONAME),
            Ok(Error::ENONAME)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EBADHINTS),
            Ok(Error::EBADHINTS)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ENOTINITIALIZED),
            Ok(Error::ENOTINITIALIZED)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ELOADIPHLPAPI),
            Ok(Error::ELOADIPHLPAPI)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_EADDRGETNETWORKPARAMS),
            Ok(Error::EADDRGETNETWORKPARAMS)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ECANCELLED),
            Ok(Error::ECANCELLED)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ESERVICE),
            Ok(Error::ESERVICE)
        );
        assert_eq!(
            Error::try_from(c_ares_sys::ares_status_t::ARES_ENOSERVER),
            Ok(Error::ENOSERVER)
        );
    }

    #[test]
    fn is_std_error() {
        fn assert_std_error<T: std::error::Error>() {}
        assert_std_error::<Error>();
    }

    #[test]
    fn display_all_variants() {
        let errors = [
            Error::ENODATA,
            Error::EFORMERR,
            Error::ESERVFAIL,
            Error::ENOTFOUND,
            Error::ENOTIMP,
            Error::EREFUSED,
            Error::EBADQUERY,
            Error::EBADNAME,
            Error::EBADFAMILY,
            Error::EBADRESP,
            Error::ECONNREFUSED,
            Error::ETIMEOUT,
            Error::EOF,
            Error::EFILE,
            Error::ENOMEM,
            Error::EDESTRUCTION,
            Error::EBADSTR,
            Error::EBADFLAGS,
            Error::ENONAME,
            Error::EBADHINTS,
            Error::ENOTINITIALIZED,
            Error::ELOADIPHLPAPI,
            Error::EADDRGETNETWORKPARAMS,
            Error::ECANCELLED,
            Error::ESERVICE,
            Error::ENOSERVER,
            Error::UNKNOWN,
        ];
        for error in &errors {
            let display = format!("{error}");
            assert!(!display.is_empty(), "Error {error:?} has empty display");
        }
    }

    #[test]
    fn debug_format() {
        let error = Error::ETIMEOUT;
        let debug = format!("{error:?}");
        assert!(debug.contains("ETIMEOUT"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn clone_and_copy() {
        let error = Error::EBADNAME;
        let cloned = error.clone();
        let copied = error;
        assert_eq!(error, cloned);
        assert_eq!(error, copied);
    }

    #[test]
    fn eq_and_hash() {
        let mut set = HashSet::new();
        set.insert(Error::ENODATA);
        set.insert(Error::ENOTFOUND);
        set.insert(Error::ENODATA);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn ord() {
        assert!(Error::ENODATA < Error::UNKNOWN);
    }

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Error>();
    }

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Error>();
    }
}
