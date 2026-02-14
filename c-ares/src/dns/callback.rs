use core::ffi::c_void;
use std::mem::ManuallyDrop;

use super::DnsRecord;
use crate::error::{Error, Result};
use crate::panic;

pub(crate) unsafe extern "C" fn dnsrec_callback<F>(
    arg: *mut c_void,
    status: c_ares_sys::ares_status_t,
    _timeouts: usize,
    dnsrec: *const c_ares_sys::ares_dns_record_t,
) where
    F: FnOnce(Result<&DnsRecord>) + Send + 'static,
{
    let handler = unsafe { Box::from_raw(arg.cast::<F>()) };

    panic::catch(|| match Error::try_from(status) {
        Ok(err) => handler(Err(err)),
        Err(()) => {
            // We wrap in ManuallyDrop so we don't call ares_dns_record_destroy
            // — c-ares owns this record and will free it after we return.
            let rec = unsafe { DnsRecord::from_raw(dnsrec as *mut _) };
            let rec = ManuallyDrop::new(rec);
            handler(Ok(&rec))
        }
    });
}
