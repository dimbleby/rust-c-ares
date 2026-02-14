use std::ffi::CString;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::slice;

use crate::error::{Error, Result};
use crate::utils::{dns_string_as_str, ipv4_as_in_addr, ipv4_from_in_addr, status_to_result};

use super::enums::{DnsCls, DnsOptDataType, DnsRecordType, DnsRrKey};

/// A view of a DNS resource record, wrapping `ares_dns_rr_t`.
///
/// This is an unsized type that can only exist behind a reference. Obtain a
/// `&DnsRr` (read-only) via [`DnsRecord::rr()`](super::DnsRecord::rr) or
/// [`DnsRecord::rrs()`](super::DnsRecord::rrs), or a `&mut DnsRr`
/// (read-write) via [`DnsRecord::rr_mut()`](super::DnsRecord::rr_mut),
/// [`DnsRecord::rrs_mut()`](super::DnsRecord::rrs_mut), or
/// [`DnsRecord::rr_add()`](super::DnsRecord::rr_add).
///
/// Field values are read via getter methods on `&self`, and written via setter
/// methods on `&mut self`. The caller must use the correct getter/setter for
/// the key's data type (see [`DnsRrKey`] documentation).
#[repr(transparent)]
pub struct DnsRr(c_ares_sys::ares_dns_rr_t);

impl DnsRr {
    /// Cast a raw const pointer to `&DnsRr`.
    ///
    /// # Safety
    ///
    /// The pointer must be non-null and valid for lifetime `'a`.
    pub(super) unsafe fn from_const_ptr<'a>(rr: *const c_ares_sys::ares_dns_rr_t) -> &'a DnsRr {
        unsafe { &*(rr as *const DnsRr) }
    }

    /// Cast a raw mut pointer to `&mut DnsRr`.
    ///
    /// # Safety
    ///
    /// The pointer must be non-null and valid for lifetime `'a`.
    pub(super) unsafe fn from_mut_ptr<'a>(rr: *mut c_ares_sys::ares_dns_rr_t) -> &'a mut DnsRr {
        unsafe { &mut *(rr as *mut DnsRr) }
    }

    /// Returns a const pointer to the inner C type.
    fn as_ptr(&self) -> *const c_ares_sys::ares_dns_rr_t {
        ptr::from_ref(&self.0)
    }

    /// Returns a mut pointer to the inner C type.
    fn as_mut_ptr(&mut self) -> *mut c_ares_sys::ares_dns_rr_t {
        ptr::from_mut(&mut self.0)
    }

    /// Retrieve the resource record name/hostname.
    pub fn name(&self) -> &str {
        unsafe {
            let ptr = c_ares_sys::ares_dns_rr_get_name(self.as_ptr());
            dns_string_as_str(ptr)
        }
    }

    /// Retrieve the resource record type.
    pub fn rr_type(&self) -> DnsRecordType {
        let raw = unsafe { c_ares_sys::ares_dns_rr_get_type(self.as_ptr()) };
        DnsRecordType::from(raw)
    }

    /// Retrieve the resource record class.
    pub fn dns_class(&self) -> DnsCls {
        let raw = unsafe { c_ares_sys::ares_dns_rr_get_class(self.as_ptr()) };
        DnsCls::from(raw)
    }

    /// Retrieve the resource record TTL.
    pub fn ttl(&self) -> u32 {
        unsafe { c_ares_sys::ares_dns_rr_get_ttl(self.as_ptr()) }
    }

    /// Retrieve the IPv4 address for the given key.
    ///
    /// Can only be used on keys with datatype `INADDR`.
    pub fn get_addr(&self, key: DnsRrKey) -> Option<Ipv4Addr> {
        let ptr = unsafe { c_ares_sys::ares_dns_rr_get_addr(self.as_ptr(), key.into()) };
        (!ptr.is_null()).then(|| ipv4_from_in_addr(unsafe { *ptr }))
    }

    /// Retrieve the IPv6 address for the given key.
    ///
    /// Can only be used on keys with datatype `INADDR6`.
    pub fn get_addr6(&self, key: DnsRrKey) -> Option<Ipv6Addr> {
        let ptr = unsafe { c_ares_sys::ares_dns_rr_get_addr6(self.as_ptr(), key.into()) };
        (!ptr.is_null()).then(|| {
            let bytes = unsafe { (*ptr)._S6_un._S6_u8 };
            Ipv6Addr::from(bytes)
        })
    }

    /// Retrieve the string for the given key.
    ///
    /// Can only be used on keys with datatype `STR` or `NAME`.
    pub fn get_str(&self, key: DnsRrKey) -> Option<&str> {
        let ptr = unsafe { c_ares_sys::ares_dns_rr_get_str(self.as_ptr(), key.into()) };
        (!ptr.is_null()).then(|| unsafe { dns_string_as_str(ptr) })
    }

    /// Retrieve an 8-bit unsigned integer for the given key.
    ///
    /// Can only be used on keys with datatype `U8`.
    pub fn get_u8(&self, key: DnsRrKey) -> u8 {
        unsafe { c_ares_sys::ares_dns_rr_get_u8(self.as_ptr(), key.into()) }
    }

    /// Retrieve a 16-bit unsigned integer for the given key.
    ///
    /// Can only be used on keys with datatype `U16`.
    pub fn get_u16(&self, key: DnsRrKey) -> u16 {
        unsafe { c_ares_sys::ares_dns_rr_get_u16(self.as_ptr(), key.into()) }
    }

    /// Retrieve a 32-bit unsigned integer for the given key.
    ///
    /// Can only be used on keys with datatype `U32`.
    pub fn get_u32(&self, key: DnsRrKey) -> u32 {
        unsafe { c_ares_sys::ares_dns_rr_get_u32(self.as_ptr(), key.into()) }
    }

    /// Retrieve binary data for the given key.
    ///
    /// Can be used on keys with datatype `BIN`, `BINP`, or `ABINP`.
    pub fn get_bin(&self, key: DnsRrKey) -> Option<&[u8]> {
        let mut len: usize = 0;
        let ptr = unsafe { c_ares_sys::ares_dns_rr_get_bin(self.as_ptr(), key.into(), &mut len) };
        (!ptr.is_null()).then(|| unsafe { slice::from_raw_parts(ptr, len) })
    }

    /// Retrieve the count of the array of stored binary values.
    ///
    /// Can only be used on keys with datatype `ABINP`.
    pub fn get_abin_count(&self, key: DnsRrKey) -> usize {
        unsafe { c_ares_sys::ares_dns_rr_get_abin_cnt(self.as_ptr(), key.into()) }
    }

    /// Retrieve a single entry from a binary array (`ABINP`) field by index.
    ///
    /// To get all array members concatenated, use [`get_bin()`](Self::get_bin) instead.
    pub fn get_abin(&self, key: DnsRrKey, idx: usize) -> Option<&[u8]> {
        let mut len: usize = 0;
        let ptr =
            unsafe { c_ares_sys::ares_dns_rr_get_abin(self.as_ptr(), key.into(), idx, &mut len) };
        (!ptr.is_null()).then(|| unsafe { slice::from_raw_parts(ptr, len) })
    }

    /// Returns an iterator over binary array (`ABINP`) entries for the given
    /// key.
    pub fn abins(&self, key: DnsRrKey) -> impl Iterator<Item = &[u8]> {
        (0..self.get_abin_count(key)).map_while(move |i| self.get_abin(key, i))
    }

    /// Retrieve the number of options stored for the given key.
    pub fn get_opt_count(&self, key: DnsRrKey) -> usize {
        unsafe { c_ares_sys::ares_dns_rr_get_opt_cnt(self.as_ptr(), key.into()) }
    }

    /// Retrieve an option by index: `(option_key, value_bytes)`.
    ///
    /// Options may not have values.
    pub fn get_opt(&self, key: DnsRrKey, idx: usize) -> Option<(u16, &[u8])> {
        let mut val: *const core::ffi::c_uchar = ptr::null();
        let mut val_len: usize = 0;
        let opt_key = unsafe {
            c_ares_sys::ares_dns_rr_get_opt(self.as_ptr(), key.into(), idx, &mut val, &mut val_len)
        };
        if opt_key == u16::MAX {
            None
        } else {
            let data = if val.is_null() {
                &[]
            } else {
                unsafe { slice::from_raw_parts(val, val_len) }
            };
            Some((opt_key, data))
        }
    }

    /// Returns an iterator over option entries for the given key.
    ///
    /// Each item is `(option_key, value_bytes)`.
    pub fn opts(&self, key: DnsRrKey) -> impl Iterator<Item = (u16, &[u8])> {
        (0..self.get_opt_count(key)).map_while(move |i| self.get_opt(key, i))
    }

    /// Return the name of an option if known.
    ///
    /// The options/parameters extensions to some RRs can be somewhat opaque;
    /// this is a helper to return the name if the option is known.
    pub fn opt_name(key: DnsRrKey, opt: u16) -> Option<&'static str> {
        let ptr = unsafe { c_ares_sys::ares_dns_opt_get_name(key.into(), opt) };
        (!ptr.is_null()).then(|| unsafe { dns_string_as_str(ptr) })
    }

    /// Return the best match for a datatype for interpreting an option record.
    ///
    /// The options/parameters extensions to some RRs can be somewhat opaque;
    /// this is a helper to return the datatype for a given option.
    pub fn opt_datatype(key: DnsRrKey, opt: u16) -> DnsOptDataType {
        let raw = unsafe { c_ares_sys::ares_dns_opt_get_datatype(key.into(), opt) };
        DnsOptDataType::from(raw)
    }

    /// Set IPv4 address data type for the given key.
    ///
    /// Can only be used on keys with datatype `INADDR`.
    pub fn set_addr(&mut self, key: DnsRrKey, addr: &Ipv4Addr) -> Result<&mut Self> {
        let in_addr = ipv4_as_in_addr(*addr);
        let status =
            unsafe { c_ares_sys::ares_dns_rr_set_addr(self.as_mut_ptr(), key.into(), &in_addr) };
        status_to_result(status)?;
        Ok(self)
    }

    /// Set IPv6 address data type for the given key.
    ///
    /// Can only be used on keys with datatype `INADDR6`.
    pub fn set_addr6(&mut self, key: DnsRrKey, addr: &Ipv6Addr) -> Result<&mut Self> {
        let in6 = c_ares_sys::ares_in6_addr {
            _S6_un: c_ares_sys::ares_in6_addr__bindgen_ty_1 {
                _S6_u8: addr.octets(),
            },
        };
        let status =
            unsafe { c_ares_sys::ares_dns_rr_set_addr6(self.as_mut_ptr(), key.into(), &in6) };
        status_to_result(status)?;
        Ok(self)
    }

    /// Set string data for the given key.
    ///
    /// Can only be used on keys with datatype `STR` or `NAME`.
    pub fn set_str(&mut self, key: DnsRrKey, val: &str) -> Result<&mut Self> {
        let c_val = CString::new(val).map_err(|_| Error::EBADSTR)?;
        let status = unsafe {
            c_ares_sys::ares_dns_rr_set_str(self.as_mut_ptr(), key.into(), c_val.as_ptr())
        };
        status_to_result(status)?;
        Ok(self)
    }

    /// Set 8-bit unsigned integer for the given key.
    ///
    /// Can only be used on keys with datatype `U8`.
    pub fn set_u8(&mut self, key: DnsRrKey, val: u8) -> Result<&mut Self> {
        let status = unsafe { c_ares_sys::ares_dns_rr_set_u8(self.as_mut_ptr(), key.into(), val) };
        status_to_result(status)?;
        Ok(self)
    }

    /// Set 16-bit unsigned integer for the given key.
    ///
    /// Can only be used on keys with datatype `U16`.
    pub fn set_u16(&mut self, key: DnsRrKey, val: u16) -> Result<&mut Self> {
        let status = unsafe { c_ares_sys::ares_dns_rr_set_u16(self.as_mut_ptr(), key.into(), val) };
        status_to_result(status)?;
        Ok(self)
    }

    /// Set 32-bit unsigned integer for the given key.
    ///
    /// Can only be used on keys with datatype `U32`.
    pub fn set_u32(&mut self, key: DnsRrKey, val: u32) -> Result<&mut Self> {
        let status = unsafe { c_ares_sys::ares_dns_rr_set_u32(self.as_mut_ptr(), key.into(), val) };
        status_to_result(status)?;
        Ok(self)
    }

    /// Set binary (`BIN` or `BINP`) data for the given key.
    ///
    /// Can only be used on keys with datatype `BIN` or `BINP`.
    pub fn set_bin(&mut self, key: DnsRrKey, val: &[u8]) -> Result<&mut Self> {
        let status = unsafe {
            c_ares_sys::ares_dns_rr_set_bin(self.as_mut_ptr(), key.into(), val.as_ptr(), val.len())
        };
        status_to_result(status)?;
        Ok(self)
    }

    /// Add a binary array value (`ABINP`) for the given key.
    ///
    /// Can only be used on keys with datatype `ABINP`.  The value will be added
    /// as the last element in the array.
    pub fn add_abin(&mut self, key: DnsRrKey, val: &[u8]) -> Result<&mut Self> {
        let status = unsafe {
            c_ares_sys::ares_dns_rr_add_abin(self.as_mut_ptr(), key.into(), val.as_ptr(), val.len())
        };
        status_to_result(status)?;
        Ok(self)
    }

    /// Delete a binary array value (`ABINP`) at the given index.
    ///
    /// Can only be used on keys with datatype `ABINP`.
    pub fn del_abin(&mut self, key: DnsRrKey, idx: usize) -> Result<&mut Self> {
        let status =
            unsafe { c_ares_sys::ares_dns_rr_del_abin(self.as_mut_ptr(), key.into(), idx) };
        status_to_result(status)?;
        Ok(self)
    }

    /// Set the option for the RR.
    pub fn set_opt(&mut self, key: DnsRrKey, opt: u16, val: &[u8]) -> Result<&mut Self> {
        let status = unsafe {
            c_ares_sys::ares_dns_rr_set_opt(
                self.as_mut_ptr(),
                key.into(),
                opt,
                val.as_ptr(),
                val.len(),
            )
        };
        status_to_result(status)?;
        Ok(self)
    }

    /// Delete the option for the RR by id.
    pub fn del_opt_byid(&mut self, key: DnsRrKey, opt: u16) -> Result<&mut Self> {
        let status =
            unsafe { c_ares_sys::ares_dns_rr_del_opt_byid(self.as_mut_ptr(), key.into(), opt) };
        status_to_result(status)?;
        Ok(self)
    }
}

unsafe impl Send for DnsRr {}
unsafe impl Sync for DnsRr {}

impl fmt::Debug for DnsRr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsRr")
            .field("name", &self.name())
            .field("rr_type", &self.rr_type())
            .field("dns_class", &self.dns_class())
            .field("ttl", &self.ttl())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::dns::*;
    use crate::error::Error;

    #[test]
    fn dns_rr_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<DnsRr>();
    }

    #[test]
    fn dns_rr_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<DnsRr>();
    }

    #[test]
    fn rr_add_and_set_addr() {
        let mut rec = DnsRecord::new(
            0,
            DnsFlags::QR | DnsFlags::RD,
            DnsOpcode::Query,
            DnsRcode::NoError,
        )
        .expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::A,
                DnsCls::IN,
                300,
            )
            .expect("rr_add");
        rr.set_addr(DnsRrKey::A_ADDR, &Ipv4Addr::new(10, 0, 0, 1))
            .expect("set_addr");
        // Read back via &self methods
        assert_eq!(rr.rr_type(), DnsRecordType::A);
        assert_eq!(rr.ttl(), 300);
        let addr = rr.get_addr(DnsRrKey::A_ADDR).expect("get_addr");
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 1));

        // Also read back from the record directly
        assert_eq!(rec.rr_count(DnsSection::Answer), 1);
        let rr = rec.rr(DnsSection::Answer, 0).expect("rr");
        assert_eq!(
            rr.get_addr(DnsRrKey::A_ADDR),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    // --- Coverage: set_addr6 / get_addr6 round-trip ---
    #[test]
    fn set_and_get_addr6() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::AAAA, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::AAAA,
                DnsCls::IN,
                120,
            )
            .expect("rr_add");
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        rr.set_addr6(DnsRrKey::AAAA_ADDR, &addr).expect("set_addr6");
        assert_eq!(rr.get_addr6(DnsRrKey::AAAA_ADDR), Some(addr));

        // Re-read from the record
        let rr = rec.rr(DnsSection::Answer, 0).expect("rr");
        assert_eq!(rr.get_addr6(DnsRrKey::AAAA_ADDR), Some(addr));
    }

    // --- Coverage: set_u8 / get_u8 ---
    #[test]
    fn set_and_get_u8() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::TLSA, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::TLSA,
                DnsCls::IN,
                3600,
            )
            .expect("rr_add");
        rr.set_u8(DnsRrKey::TLSA_CERT_USAGE, 3)
            .expect("set_u8 cert_usage");
        rr.set_u8(DnsRrKey::TLSA_SELECTOR, 1)
            .expect("set_u8 selector");
        rr.set_u8(DnsRrKey::TLSA_MATCH, 1).expect("set_u8 match");
        assert_eq!(rr.get_u8(DnsRrKey::TLSA_CERT_USAGE), 3);
        assert_eq!(rr.get_u8(DnsRrKey::TLSA_SELECTOR), 1);
        assert_eq!(rr.get_u8(DnsRrKey::TLSA_MATCH), 1);
    }

    // --- Coverage: set_u32 / get_u32 ---
    #[test]
    fn set_and_get_u32() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::SOA, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::SOA,
                DnsCls::IN,
                3600,
            )
            .expect("rr_add");
        rr.set_str(DnsRrKey::SOA_MNAME, "ns1.example.com")
            .expect("set mname");
        rr.set_str(DnsRrKey::SOA_RNAME, "admin.example.com")
            .expect("set rname");
        rr.set_u32(DnsRrKey::SOA_SERIAL, 2024010100)
            .expect("set_u32 serial");
        rr.set_u32(DnsRrKey::SOA_REFRESH, 7200)
            .expect("set_u32 refresh");
        rr.set_u32(DnsRrKey::SOA_RETRY, 3600)
            .expect("set_u32 retry");
        rr.set_u32(DnsRrKey::SOA_EXPIRE, 1209600)
            .expect("set_u32 expire");
        rr.set_u32(DnsRrKey::SOA_MINIMUM, 300)
            .expect("set_u32 minimum");
        assert_eq!(rr.get_u32(DnsRrKey::SOA_SERIAL), 2024010100);
        assert_eq!(rr.get_u32(DnsRrKey::SOA_REFRESH), 7200);
        assert_eq!(rr.get_u32(DnsRrKey::SOA_RETRY), 3600);
        assert_eq!(rr.get_u32(DnsRrKey::SOA_EXPIRE), 1209600);
        assert_eq!(rr.get_u32(DnsRrKey::SOA_MINIMUM), 300);
    }

    // --- Coverage: set_bin / get_bin ---
    #[test]
    fn set_and_get_bin() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::TLSA, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::TLSA,
                DnsCls::IN,
                3600,
            )
            .expect("rr_add");
        rr.set_u8(DnsRrKey::TLSA_CERT_USAGE, 3)
            .expect("set cert_usage");
        rr.set_u8(DnsRrKey::TLSA_SELECTOR, 1).expect("set selector");
        rr.set_u8(DnsRrKey::TLSA_MATCH, 1).expect("set match");
        let cert_data = b"\xab\xcd\xef\x01\x23\x45";
        rr.set_bin(DnsRrKey::TLSA_DATA, cert_data).expect("set_bin");
        let got = rr.get_bin(DnsRrKey::TLSA_DATA).expect("get_bin");
        assert_eq!(got, cert_data);
    }

    // --- Coverage: add_abin / get_abin / get_abin_count / del_abin ---
    #[test]
    fn abin_add_get_del() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::TXT, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::TXT,
                DnsCls::IN,
                300,
            )
            .expect("rr_add");

        rr.add_abin(DnsRrKey::TXT_DATA, b"hello world")
            .expect("add_abin 0");
        rr.add_abin(DnsRrKey::TXT_DATA, b"second entry")
            .expect("add_abin 1");
        assert_eq!(rr.get_abin_count(DnsRrKey::TXT_DATA), 2);
        assert_eq!(rr.get_abin(DnsRrKey::TXT_DATA, 0).unwrap(), b"hello world");
        assert_eq!(rr.get_abin(DnsRrKey::TXT_DATA, 1).unwrap(), b"second entry");

        // Exercise the abins() iterator
        let entries: Vec<_> = rr.abins(DnsRrKey::TXT_DATA).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], b"hello world");
        assert_eq!(entries[1], b"second entry");

        // Out of range returns None
        assert!(rr.get_abin(DnsRrKey::TXT_DATA, 99).is_none());

        // Delete first entry
        rr.del_abin(DnsRrKey::TXT_DATA, 0).expect("del_abin");
        assert_eq!(rr.get_abin_count(DnsRrKey::TXT_DATA), 1);
        assert_eq!(rr.get_abin(DnsRrKey::TXT_DATA, 0).unwrap(), b"second entry");
    }

    // --- Coverage: set_opt / get_opt / get_opt_count / del_opt_byid ---
    #[test]
    fn opt_set_get_del() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add(".", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Additional,
                "",
                DnsRecordType::OPT,
                DnsCls::IN,
                0,
            )
            .expect("rr_add OPT");
        rr.set_u16(DnsRrKey::OPT_UDP_SIZE, 4096)
            .expect("set udp size");
        rr.set_u8(DnsRrKey::OPT_VERSION, 0).expect("set version");
        rr.set_u16(DnsRrKey::OPT_FLAGS, 0).expect("set flags");

        // Add options
        let opt_val = b"\x01\x02\x03";
        rr.set_opt(DnsRrKey::OPT_OPTIONS, 10, opt_val)
            .expect("set_opt");
        rr.set_opt(DnsRrKey::OPT_OPTIONS, 20, b"")
            .expect("set_opt empty");

        assert_eq!(rr.get_opt_count(DnsRrKey::OPT_OPTIONS), 2);

        // Exercise the opts() iterator
        let entries: Vec<_> = rr.opts(DnsRrKey::OPT_OPTIONS).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (10, &opt_val[..]));
        assert_eq!(entries[1].0, 20);
        assert!(entries[1].1.is_empty());

        let (key0, val0) = rr.get_opt(DnsRrKey::OPT_OPTIONS, 0).expect("get_opt 0");
        assert_eq!(key0, 10);
        assert_eq!(val0, opt_val);

        let (key1, val1) = rr.get_opt(DnsRrKey::OPT_OPTIONS, 1).expect("get_opt 1");
        assert_eq!(key1, 20);
        assert!(val1.is_empty());

        // Out of range
        assert!(rr.get_opt(DnsRrKey::OPT_OPTIONS, 99).is_none());

        // Delete by id
        rr.del_opt_byid(DnsRrKey::OPT_OPTIONS, 10)
            .expect("del_opt_byid");
        assert_eq!(rr.get_opt_count(DnsRrKey::OPT_OPTIONS), 1);
        let (key, _) = rr
            .get_opt(DnsRrKey::OPT_OPTIONS, 0)
            .expect("get_opt after del");
        assert_eq!(key, 20);
    }

    #[test]
    fn opt_name_known_and_unknown() {
        // EDNS option 10 is COOKIE (well-known)
        let name = DnsRr::opt_name(DnsRrKey::OPT_OPTIONS, 10);
        assert!(name.is_some(), "expected a name for COOKIE option");

        // An unknown option id should return None
        assert!(DnsRr::opt_name(DnsRrKey::OPT_OPTIONS, 65534).is_none());
    }

    #[test]
    fn opt_datatype_known() {
        // EDNS COOKIE (option 10) has binary data
        assert_eq!(
            DnsRr::opt_datatype(DnsRrKey::OPT_OPTIONS, 10),
            DnsOptDataType::Bin
        );
    }

    // --- Coverage: get_addr / get_addr6 / get_str returning None for wrong key type ---
    #[test]
    fn getter_wrong_key_returns_none() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::MX, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::MX,
                DnsCls::IN,
                300,
            )
            .expect("rr_add");
        rr.set_u16(DnsRrKey::MX_PREFERENCE, 10).expect("set_u16");
        rr.set_str(DnsRrKey::MX_EXCHANGE, "mail.example.com")
            .expect("set_str");

        let rr = rec.rr(DnsSection::Answer, 0).expect("rr");
        // These are wrong key types for an MX record
        assert!(rr.get_addr(DnsRrKey::A_ADDR).is_none());
        assert!(rr.get_addr6(DnsRrKey::AAAA_ADDR).is_none());
        assert!(rr.get_bin(DnsRrKey::TLSA_DATA).is_none());
    }

    // --- Coverage: SRV record with multiple u16 fields ---
    #[test]
    fn srv_record_fields() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("_http._tcp.example.com", DnsRecordType::SRV, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "_http._tcp.example.com",
                DnsRecordType::SRV,
                DnsCls::IN,
                60,
            )
            .expect("rr_add");
        rr.set_u16(DnsRrKey::SRV_PRIORITY, 10).expect("priority");
        rr.set_u16(DnsRrKey::SRV_WEIGHT, 60).expect("weight");
        rr.set_u16(DnsRrKey::SRV_PORT, 8080).expect("port");
        rr.set_str(DnsRrKey::SRV_TARGET, "server.example.com")
            .expect("target");

        assert_eq!(rr.get_u16(DnsRrKey::SRV_PRIORITY), 10);
        assert_eq!(rr.get_u16(DnsRrKey::SRV_WEIGHT), 60);
        assert_eq!(rr.get_u16(DnsRrKey::SRV_PORT), 8080);
        assert_eq!(rr.get_str(DnsRrKey::SRV_TARGET), Some("server.example.com"));
    }

    // --- Coverage: CNAME and PTR (get_str for NAME-type keys) ---
    #[test]
    fn cname_and_ptr_records() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("alias.example.com", DnsRecordType::CNAME, DnsCls::IN)
            .expect("query_add");

        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "alias.example.com",
                DnsRecordType::CNAME,
                DnsCls::IN,
                600,
            )
            .expect("rr_add");
        rr.set_str(DnsRrKey::CNAME_CNAME, "real.example.com")
            .expect("set cname");
        assert_eq!(rr.get_str(DnsRrKey::CNAME_CNAME), Some("real.example.com"));

        // PTR
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "1.0.0.10.in-addr.arpa",
                DnsRecordType::PTR,
                DnsCls::IN,
                600,
            )
            .expect("rr_add ptr");
        rr.set_str(DnsRrKey::PTR_DNAME, "host.example.com")
            .expect("set ptr");
        assert_eq!(rr.get_str(DnsRrKey::PTR_DNAME), Some("host.example.com"));
    }

    // --- Coverage: TTL boundary values ---
    #[test]
    fn ttl_boundary_values() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");

        // TTL = 0
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::A,
                DnsCls::IN,
                0,
            )
            .expect("rr_add");
        assert_eq!(rr.ttl(), 0);

        // TTL = max u32
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::A,
                DnsCls::IN,
                u32::MAX,
            )
            .expect("rr_add max");
        assert_eq!(rr.ttl(), u32::MAX);
    }

    // --- Coverage: CAA record with u8 and bin ---
    #[test]
    fn caa_record_fields() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::CAA, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::CAA,
                DnsCls::IN,
                3600,
            )
            .expect("rr_add");
        rr.set_u8(DnsRrKey::CAA_CRITICAL, 0).expect("set critical");
        rr.set_str(DnsRrKey::CAA_TAG, "issue").expect("set tag");
        rr.set_bin(DnsRrKey::CAA_VALUE, b"letsencrypt.org")
            .expect("set value");

        assert_eq!(rr.get_u8(DnsRrKey::CAA_CRITICAL), 0);
        assert_eq!(rr.get_str(DnsRrKey::CAA_TAG), Some("issue"));
        assert_eq!(rr.get_bin(DnsRrKey::CAA_VALUE).unwrap(), b"letsencrypt.org");
    }

    // --- Coverage: read via shared ref, write via mutable ref ---
    #[test]
    fn read_write_same_type() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::A,
                DnsCls::IN,
                300,
            )
            .expect("rr_add");
        rr.set_addr(DnsRrKey::A_ADDR, &Ipv4Addr::new(1, 1, 1, 1))
            .expect("set_addr");

        // Read via &self
        assert_eq!(rr.name(), "example.com");
        assert_eq!(rr.rr_type(), DnsRecordType::A);
        assert_eq!(rr.dns_class(), DnsCls::IN);
        assert_eq!(rr.ttl(), 300);
        assert_eq!(
            rr.get_addr(DnsRrKey::A_ADDR),
            Some(Ipv4Addr::new(1, 1, 1, 1))
        );
    }

    #[test]
    fn set_str_rejects_null_byte() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::MX, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::MX,
                DnsCls::IN,
                300,
            )
            .expect("rr_add");
        rr.set_u16(DnsRrKey::MX_PREFERENCE, 10).expect("set_u16");
        let result = rr.set_str(DnsRrKey::MX_EXCHANGE, "mail\0.example.com");
        assert!(matches!(result, Err(Error::EBADSTR)));
    }

    #[test]
    fn debug_dns_rr() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::A,
                DnsCls::IN,
                300,
            )
            .expect("rr_add");
        let debug = format!("{:?}", rr);
        assert!(debug.contains("DnsRr"));
        assert!(debug.contains("example.com"));
    }
}
