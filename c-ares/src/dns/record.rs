use std::ffi::CString;
use std::fmt;
use std::ptr;

use crate::error::{Error, Result};
use crate::string::AresBuf;
use crate::utils::{dns_string_as_str, status_to_result};

use super::enums::*;
use super::rr::DnsRr;

/// An owned DNS record (message), wrapping `ares_dns_record_t`.
///
/// A `DnsRecord` represents a complete DNS message including header fields,
/// question section, and resource record sections (answer, authority,
/// additional).
///
/// Created by parsing wire-format data with [`DnsRecord::parse()`].
pub struct DnsRecord {
    dnsrec: *mut c_ares_sys::ares_dns_record_t,
}

impl DnsRecord {
    /// Create a `DnsRecord` from a raw pointer.
    ///
    /// # Safety
    ///
    /// The pointer must have been allocated by c-ares (e.g. via
    /// `ares_dns_record_create` or `ares_dns_record_duplicate`) and the caller
    /// transfers ownership to this `DnsRecord`.
    pub(crate) unsafe fn from_raw(dnsrec: *mut c_ares_sys::ares_dns_record_t) -> DnsRecord {
        DnsRecord { dnsrec }
    }

    /// Returns the raw pointer for use in FFI calls.
    pub(crate) fn as_raw(&self) -> *const c_ares_sys::ares_dns_record_t {
        self.dnsrec
    }

    /// Parse a complete DNS message from wire-format bytes.
    ///
    /// `flags` controls parsing behaviour; use `DnsParseFlags::empty()` for
    /// default parsing.
    pub fn parse(data: &[u8], flags: DnsParseFlags) -> Result<DnsRecord> {
        let mut dnsrec: *mut c_ares_sys::ares_dns_record_t = ptr::null_mut();
        let status = unsafe {
            c_ares_sys::ares_dns_parse(data.as_ptr(), data.len(), flags.bits(), &mut dnsrec)
        };
        status_to_result(status)?;
        Ok(DnsRecord { dnsrec })
    }

    /// Returns the DNS query ID.
    pub fn id(&self) -> u16 {
        unsafe { c_ares_sys::ares_dns_record_get_id(self.dnsrec) }
    }

    /// Returns the DNS record flags.
    pub fn flags(&self) -> DnsFlags {
        let raw = unsafe { c_ares_sys::ares_dns_record_get_flags(self.dnsrec) };
        DnsFlags::from_bits_truncate(raw)
    }

    /// Returns the DNS record opcode.
    pub fn opcode(&self) -> DnsOpcode {
        let raw = unsafe { c_ares_sys::ares_dns_record_get_opcode(self.dnsrec) };
        DnsOpcode::from(raw)
    }

    /// Returns the DNS record rcode.
    pub fn rcode(&self) -> DnsRcode {
        let raw = unsafe { c_ares_sys::ares_dns_record_get_rcode(self.dnsrec) };
        DnsRcode::from(raw)
    }

    /// Returns the count of queries in the DNS record.
    pub fn query_count(&self) -> usize {
        unsafe { c_ares_sys::ares_dns_record_query_cnt(self.dnsrec) }
    }

    /// Get the query at the given index.
    ///
    /// Returns `(name, record_type, class)` on success.
    pub fn query_get(&self, idx: usize) -> Result<(&str, DnsRecordType, DnsCls)> {
        let mut name: *const core::ffi::c_char = ptr::null();
        let mut qtype = c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_A;
        let mut qclass = c_ares_sys::ares_dns_class_t::ARES_CLASS_IN;
        let status = unsafe {
            c_ares_sys::ares_dns_record_query_get(
                self.dnsrec,
                idx,
                &mut name,
                &mut qtype,
                &mut qclass,
            )
        };
        status_to_result(status)?;
        let name_str = unsafe { dns_string_as_str(name) };
        Ok((name_str, DnsRecordType::from(qtype), DnsCls::from(qclass)))
    }

    /// Returns an iterator over the queries in the DNS record.
    pub fn queries(&self) -> impl Iterator<Item = (&str, DnsRecordType, DnsCls)> {
        (0..self.query_count()).map_while(move |i| self.query_get(i).ok())
    }

    /// Returns the count of resource records in the given section.
    pub fn rr_count(&self, section: DnsSection) -> usize {
        unsafe { c_ares_sys::ares_dns_record_rr_cnt(self.dnsrec, section.into()) }
    }

    /// Fetch a non-writable resource record by section and index.
    ///
    /// Returns `None` if the index is out of range.
    pub fn rr(&self, section: DnsSection, idx: usize) -> Option<&DnsRr> {
        let rr =
            unsafe { c_ares_sys::ares_dns_record_rr_get_const(self.dnsrec, section.into(), idx) };
        (!rr.is_null()).then(|| unsafe { DnsRr::from_const_ptr(rr) })
    }

    /// Returns an iterator over the resource records in the given section.
    pub fn rrs(&self, section: DnsSection) -> impl Iterator<Item = &DnsRr> {
        (0..self.rr_count(section)).map_while(move |i| self.rr(section, i))
    }

    /// Create a new DNS record object.
    ///
    /// When building a query to send via
    /// [`Channel::send_dnsrec()`](crate::Channel::send_dnsrec), set `id`
    /// to `0`.
    pub fn new(id: u16, flags: DnsFlags, opcode: DnsOpcode, rcode: DnsRcode) -> Result<DnsRecord> {
        let mut dnsrec: *mut c_ares_sys::ares_dns_record_t = ptr::null_mut();
        let status = unsafe {
            c_ares_sys::ares_dns_record_create(
                &mut dnsrec,
                id,
                flags.bits(),
                opcode.into(),
                rcode.into(),
            )
        };
        status_to_result(status)?;
        Ok(DnsRecord { dnsrec })
    }

    /// Overwrite the DNS query id.
    pub fn set_id(&mut self, id: u16) -> &mut Self {
        unsafe { c_ares_sys::ares_dns_record_set_id(self.dnsrec, id) };
        self
    }

    /// Add a query to the DNS record.
    ///
    /// Typically a record will have only one query.  Most DNS servers will
    /// reject queries with more than one question.
    pub fn query_add(
        &mut self,
        name: &str,
        qtype: DnsRecordType,
        qclass: DnsCls,
    ) -> Result<&mut Self> {
        let c_name = CString::new(name).map_err(|_| Error::EBADSTR)?;
        let status = unsafe {
            c_ares_sys::ares_dns_record_query_add(
                self.dnsrec,
                c_name.as_ptr(),
                qtype.into(),
                qclass.into(),
            )
        };
        status_to_result(status)?;
        Ok(self)
    }

    /// Replace the question name at the given index.
    ///
    /// This may be used when performing a search with aliases.
    pub fn query_set_name(&mut self, idx: usize, name: &str) -> Result<&mut Self> {
        let c_name = CString::new(name).map_err(|_| Error::EBADSTR)?;
        let status = unsafe {
            c_ares_sys::ares_dns_record_query_set_name(self.dnsrec, idx, c_name.as_ptr())
        };
        status_to_result(status)?;
        Ok(self)
    }

    /// Replace the question type at the given index.
    ///
    /// This may be used when needing to query more than one address class
    /// (e.g. A and AAAA).
    pub fn query_set_type(&mut self, idx: usize, qtype: DnsRecordType) -> Result<&mut Self> {
        let status =
            unsafe { c_ares_sys::ares_dns_record_query_set_type(self.dnsrec, idx, qtype.into()) };
        status_to_result(status)?;
        Ok(self)
    }

    /// Add a resource record to the DNS record.
    ///
    /// Returns a mutable reference to the created resource record for setting
    /// RR-specific fields.
    pub fn rr_add(
        &mut self,
        section: DnsSection,
        name: &str,
        rr_type: DnsRecordType,
        rclass: DnsCls,
        ttl: u32,
    ) -> Result<&mut DnsRr> {
        let c_name = CString::new(name).map_err(|_| Error::EBADSTR)?;
        let mut rr_out: *mut c_ares_sys::ares_dns_rr_t = ptr::null_mut();
        let status = unsafe {
            c_ares_sys::ares_dns_record_rr_add(
                &mut rr_out,
                self.dnsrec,
                section.into(),
                c_name.as_ptr(),
                rr_type.into(),
                rclass.into(),
                ttl,
            )
        };
        status_to_result(status)?;
        Ok(unsafe { DnsRr::from_mut_ptr(rr_out) })
    }

    /// Fetch a writable resource record by section and index.
    ///
    /// Returns `None` if the index is out of range.
    pub fn rr_mut(&mut self, section: DnsSection, idx: usize) -> Option<&mut DnsRr> {
        let rr = unsafe { c_ares_sys::ares_dns_record_rr_get(self.dnsrec, section.into(), idx) };
        (!rr.is_null()).then(|| unsafe { DnsRr::from_mut_ptr(rr) })
    }

    /// Returns an iterator over mutable resource records in the given section.
    pub fn rrs_mut(&mut self, section: DnsSection) -> impl Iterator<Item = &mut DnsRr> {
        let count = self.rr_count(section);
        let dnsrec = self.dnsrec;
        (0..count).map_while(move |i| {
            let rr = unsafe { c_ares_sys::ares_dns_record_rr_get(dnsrec, section.into(), i) };
            (!rr.is_null()).then(|| unsafe { DnsRr::from_mut_ptr(rr) })
        })
    }

    /// Remove the resource record at the given section and index.
    pub fn rr_del(&mut self, section: DnsSection, idx: usize) -> Result<&mut Self> {
        let status =
            unsafe { c_ares_sys::ares_dns_record_rr_del(self.dnsrec, section.into(), idx) };
        status_to_result(status)?;
        Ok(self)
    }

    /// Write a complete DNS message to wire format.
    pub fn write(&self) -> Result<AresBuf> {
        let mut buf: *mut core::ffi::c_uchar = ptr::null_mut();
        let mut buf_len: usize = 0;
        let status = unsafe { c_ares_sys::ares_dns_write(self.dnsrec, &mut buf, &mut buf_len) };
        status_to_result(status)?;
        Ok(AresBuf::new(buf, buf_len))
    }

    /// Create a deep copy of this DNS record.
    pub fn try_clone(&self) -> Result<DnsRecord> {
        let dup = unsafe { c_ares_sys::ares_dns_record_duplicate(self.dnsrec) };
        if dup.is_null() {
            Err(Error::ENOMEM)
        } else {
            Ok(DnsRecord { dnsrec: dup })
        }
    }
}

impl Drop for DnsRecord {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_dns_record_destroy(self.dnsrec) }
    }
}

unsafe impl Send for DnsRecord {}
unsafe impl Sync for DnsRecord {}

impl fmt::Debug for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsRecord")
            .field("id", &self.id())
            .field("flags", &self.flags())
            .field("opcode", &self.opcode())
            .field("rcode", &self.rcode())
            .field("query_count", &self.query_count())
            .field("answer_count", &self.rr_count(DnsSection::Answer))
            .field("authority_count", &self.rr_count(DnsSection::Authority))
            .field("additional_count", &self.rr_count(DnsSection::Additional))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::dns::*;
    use crate::error::Error;

    #[test]
    fn parse_invalid_data() {
        let result = DnsRecord::parse(&[], DnsParseFlags::empty());
        assert!(result.is_err());
    }

    #[test]
    fn parse_short_data() {
        let result = DnsRecord::parse(&[0; 4], DnsParseFlags::empty());
        assert!(result.is_err());
    }

    // Parse a minimal valid DNS query message (12-byte header + question).
    // This is a query for "." type A class IN.
    #[test]
    fn parse_minimal_query() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x00, 0x01, // ID = 1
            0x01, 0x00, // Flags: RD=1 (standard query)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x00,       // root label (.)
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];
        let rec = DnsRecord::parse(data, DnsParseFlags::empty()).expect("parse should succeed");
        assert_eq!(rec.id(), 1);
        assert!(rec.flags().contains(DnsFlags::RD));
        assert_eq!(rec.opcode(), DnsOpcode::Query);
        assert_eq!(rec.rcode(), DnsRcode::NoError);
        assert_eq!(rec.query_count(), 1);

        let (name, qtype, qclass) = rec.query_get(0).expect("query_get should succeed");
        assert_eq!(name, "");
        assert_eq!(qtype, DnsRecordType::A);
        assert_eq!(qclass, DnsCls::IN);

        assert_eq!(rec.rr_count(DnsSection::Answer), 0);
        assert!(rec.rr(DnsSection::Answer, 0).is_none());
    }

    // Parse a DNS response with an A record answer.
    #[test]
    fn parse_a_response() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x00, 0x02,             // ID = 2
            0x81, 0x80,             // Flags: QR=1 RD=1 RA=1 (standard response)
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x01,             // ANCOUNT = 1
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            // Question: example. A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x00,                   // root
            0x00, 0x01,             // QTYPE = A
            0x00, 0x01,             // QCLASS = IN
            // Answer: example. A IN 300 1.2.3.4
            0xc0, 0x0c,             // pointer to name at offset 12
            0x00, 0x01,             // TYPE = A
            0x00, 0x01,             // CLASS = IN
            0x00, 0x00, 0x01, 0x2c, // TTL = 300
            0x00, 0x04,             // RDLENGTH = 4
            0x01, 0x02, 0x03, 0x04, // RDATA = 1.2.3.4
        ];
        let rec = DnsRecord::parse(data, DnsParseFlags::empty()).expect("parse should succeed");
        assert_eq!(rec.id(), 2);
        assert!(rec.flags().contains(DnsFlags::QR));
        assert!(rec.flags().contains(DnsFlags::RD));
        assert!(rec.flags().contains(DnsFlags::RA));
        assert_eq!(rec.rr_count(DnsSection::Answer), 1);

        let rr = rec.rr(DnsSection::Answer, 0).expect("rr should exist");
        assert_eq!(rr.rr_type(), DnsRecordType::A);
        assert_eq!(rr.dns_class(), DnsCls::IN);
        assert_eq!(rr.ttl(), 300);
        assert_eq!(rr.name(), "example");

        let addr = rr.get_addr(DnsRrKey::A_ADDR).expect("should have addr");
        assert_eq!(addr, Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn dns_record_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<DnsRecord>();
    }

    #[test]
    fn dns_record_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<DnsRecord>();
    }

    #[test]
    fn create_empty_record() {
        let rec = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError)
            .expect("create should succeed");
        assert_eq!(rec.id(), 0);
        assert!(rec.flags().contains(DnsFlags::RD));
        assert_eq!(rec.opcode(), DnsOpcode::Query);
        assert_eq!(rec.rcode(), DnsRcode::NoError);
        assert_eq!(rec.query_count(), 0);
    }

    #[test]
    fn create_and_add_query() {
        let mut rec = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError)
            .expect("create should succeed");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add should succeed");
        assert_eq!(rec.query_count(), 1);
        let (name, qtype, qclass) = rec.query_get(0).expect("query_get should succeed");
        assert_eq!(name, "example.com");
        assert_eq!(qtype, DnsRecordType::A);
        assert_eq!(qclass, DnsCls::IN);
    }

    #[test]
    fn set_id() {
        let mut rec = DnsRecord::new(0, DnsFlags::empty(), DnsOpcode::Query, DnsRcode::NoError)
            .expect("create should succeed");
        assert_eq!(rec.id(), 0);
        rec.set_id(42);
        assert_eq!(rec.id(), 42);
    }

    #[test]
    fn query_set_name_and_type() {
        let mut rec = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError)
            .expect("create should succeed");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        rec.query_set_name(0, "other.com").expect("set_name");
        rec.query_set_type(0, DnsRecordType::AAAA)
            .expect("set_type");
        let (name, qtype, _) = rec.query_get(0).expect("query_get");
        assert_eq!(name, "other.com");
        assert_eq!(qtype, DnsRecordType::AAAA);
    }

    #[test]
    fn rr_mut_and_rr_del() {
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
                600,
            )
            .expect("rr_add");
        rr.set_u16(DnsRrKey::MX_PREFERENCE, 10).expect("set_u16");
        rr.set_str(DnsRrKey::MX_EXCHANGE, "mail.example.com")
            .expect("set_str");

        // Verify via rr_mut
        let rr = rec.rr_mut(DnsSection::Answer, 0).expect("rr_mut");
        assert_eq!(rr.get_u16(DnsRrKey::MX_PREFERENCE), 10);
        assert_eq!(rr.get_str(DnsRrKey::MX_EXCHANGE), Some("mail.example.com"));

        // Delete it
        rec.rr_del(DnsSection::Answer, 0).expect("rr_del");
        assert_eq!(rec.rr_count(DnsSection::Answer), 0);
    }

    #[test]
    fn rrs_mut_update_ttl() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        for i in 0..3u8 {
            let rr = rec
                .rr_add(
                    DnsSection::Answer,
                    "example.com",
                    DnsRecordType::A,
                    DnsCls::IN,
                    300,
                )
                .expect("rr_add");
            rr.set_addr(DnsRrKey::A_ADDR, &Ipv4Addr::new(10, 0, 0, i))
                .expect("set_addr");
        }

        // Use rrs_mut() to update all MX preferences (here, re-set addresses)
        for rr in rec.rrs_mut(DnsSection::Answer) {
            let addr = rr.get_addr(DnsRrKey::A_ADDR).expect("get_addr");
            // Shift each address by adding 100 to the last octet
            let octets = addr.octets();
            rr.set_addr(
                DnsRrKey::A_ADDR,
                &Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3] + 100),
            )
            .expect("set_addr");
        }

        // Verify via read-only iterator
        let addrs: Vec<_> = rec
            .rrs(DnsSection::Answer)
            .map(|rr| rr.get_addr(DnsRrKey::A_ADDR).unwrap())
            .collect();
        assert_eq!(
            addrs,
            vec![
                Ipv4Addr::new(10, 0, 0, 100),
                Ipv4Addr::new(10, 0, 0, 101),
                Ipv4Addr::new(10, 0, 0, 102),
            ]
        );
    }

    #[test]
    fn write_and_reparse() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");

        let wire = rec.write().expect("write");
        assert!(!wire.is_empty());

        // Re-parse and verify
        let rec2 = DnsRecord::parse(&wire, DnsParseFlags::empty()).expect("parse");
        assert_eq!(rec2.query_count(), 1);
        let (name, qtype, qclass) = rec2.query_get(0).expect("query_get");
        assert_eq!(name, "example.com");
        assert_eq!(qtype, DnsRecordType::A);
        assert_eq!(qclass, DnsCls::IN);
    }

    #[test]
    fn duplicate_record() {
        let mut rec =
            DnsRecord::new(42, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("test.org", DnsRecordType::AAAA, DnsCls::IN)
            .expect("query_add");

        let dup = rec.try_clone().expect("try_clone");
        assert_eq!(dup.id(), 42);
        assert_eq!(dup.query_count(), 1);
        let (name, qtype, _) = dup.query_get(0).expect("query_get");
        assert_eq!(name, "test.org");
        assert_eq!(qtype, DnsRecordType::AAAA);
    }

    // --- Coverage: out-of-range rr access ---
    #[test]
    fn rr_out_of_range() {
        let rec =
            DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        assert!(rec.rr(DnsSection::Answer, 0).is_none());
        assert!(rec.rr(DnsSection::Answer, 100).is_none());
        assert!(rec.rr(DnsSection::Authority, 0).is_none());
        assert!(rec.rr(DnsSection::Additional, 0).is_none());
    }

    // --- Coverage: rr_mut out-of-range ---
    #[test]
    fn rr_mut_out_of_range() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        assert!(rec.rr_mut(DnsSection::Answer, 0).is_none());
        assert!(rec.rr_mut(DnsSection::Answer, 100).is_none());
    }

    // --- Coverage: rr_del out-of-range ---
    #[test]
    fn rr_del_out_of_range() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        let result = rec.rr_del(DnsSection::Answer, 0);
        assert!(result.is_err());
    }

    // --- Coverage: multiple queries ---
    #[test]
    fn multiple_queries() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("a.example.com", DnsRecordType::A, DnsCls::IN)
            .expect("add 0");
        rec.query_add("b.example.com", DnsRecordType::AAAA, DnsCls::IN)
            .expect("add 1");
        rec.query_add("c.example.com", DnsRecordType::MX, DnsCls::IN)
            .expect("add 2");
        assert_eq!(rec.query_count(), 3);

        let (n, t, _) = rec.query_get(0).expect("get 0");
        assert_eq!(n, "a.example.com");
        assert_eq!(t, DnsRecordType::A);

        let (n, t, _) = rec.query_get(1).expect("get 1");
        assert_eq!(n, "b.example.com");
        assert_eq!(t, DnsRecordType::AAAA);

        let (n, t, _) = rec.query_get(2).expect("get 2");
        assert_eq!(n, "c.example.com");
        assert_eq!(t, DnsRecordType::MX);
    }

    // --- Coverage: multiple RRs in the same section ---
    #[test]
    fn multiple_rrs_same_section() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        for i in 0..5 {
            let rr = rec
                .rr_add(
                    DnsSection::Answer,
                    "example.com",
                    DnsRecordType::A,
                    DnsCls::IN,
                    300,
                )
                .expect("rr_add");
            rr.set_addr(DnsRrKey::A_ADDR, &Ipv4Addr::new(10, 0, 0, i))
                .expect("set_addr");
        }
        assert_eq!(rec.rr_count(DnsSection::Answer), 5);
        for i in 0..5 {
            let rr = rec.rr(DnsSection::Answer, i).expect("rr");
            assert_eq!(
                rr.get_addr(DnsRrKey::A_ADDR),
                Some(Ipv4Addr::new(10, 0, 0, i as u8))
            );
        }
    }

    // --- Coverage: Authority and Additional sections ---
    #[test]
    fn authority_and_additional_sections() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");

        // Add an NS record in the authority section
        let rr = rec
            .rr_add(
                DnsSection::Authority,
                "example.com",
                DnsRecordType::NS,
                DnsCls::IN,
                3600,
            )
            .expect("rr_add authority");
        rr.set_str(DnsRrKey::NS_NSDNAME, "ns1.example.com")
            .expect("set ns name");

        // Add an A record in the additional section
        let rr = rec
            .rr_add(
                DnsSection::Additional,
                "ns1.example.com",
                DnsRecordType::A,
                DnsCls::IN,
                3600,
            )
            .expect("rr_add additional");
        rr.set_addr(DnsRrKey::A_ADDR, &Ipv4Addr::new(192, 0, 2, 1))
            .expect("set_addr");

        assert_eq!(rec.rr_count(DnsSection::Answer), 0);
        assert_eq!(rec.rr_count(DnsSection::Authority), 1);
        assert_eq!(rec.rr_count(DnsSection::Additional), 1);

        let ns = rec.rr(DnsSection::Authority, 0).expect("rr authority");
        assert_eq!(ns.rr_type(), DnsRecordType::NS);
        assert_eq!(ns.get_str(DnsRrKey::NS_NSDNAME), Some("ns1.example.com"));

        let a = rec.rr(DnsSection::Additional, 0).expect("rr additional");
        assert_eq!(a.rr_type(), DnsRecordType::A);
        assert_eq!(
            a.get_addr(DnsRrKey::A_ADDR),
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
    }

    // --- Coverage: write/reparse with answer RRs (full round trip) ---
    #[test]
    fn write_reparse_with_answer() {
        let mut rec = DnsRecord::new(
            100,
            DnsFlags::QR | DnsFlags::RD | DnsFlags::RA,
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
        rr.set_addr(DnsRrKey::A_ADDR, &Ipv4Addr::new(93, 184, 216, 34))
            .expect("set_addr");

        let wire = rec.write().expect("write");
        let rec2 = DnsRecord::parse(&wire, DnsParseFlags::empty()).expect("reparse");
        assert_eq!(rec2.id(), 100);
        assert!(rec2.flags().contains(DnsFlags::QR));
        assert!(rec2.flags().contains(DnsFlags::RD));
        assert!(rec2.flags().contains(DnsFlags::RA));
        assert_eq!(rec2.rr_count(DnsSection::Answer), 1);
        let rr = rec2.rr(DnsSection::Answer, 0).expect("rr");
        assert_eq!(
            rr.get_addr(DnsRrKey::A_ADDR),
            Some(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    // --- Coverage: SOA full write/reparse round trip ---
    #[test]
    fn soa_write_reparse() {
        let mut rec = DnsRecord::new(
            5,
            DnsFlags::QR | DnsFlags::AA | DnsFlags::RD,
            DnsOpcode::Query,
            DnsRcode::NoError,
        )
        .expect("create");
        rec.query_add("example.com", DnsRecordType::SOA, DnsCls::IN)
            .expect("query_add");
        let rr = rec
            .rr_add(
                DnsSection::Answer,
                "example.com",
                DnsRecordType::SOA,
                DnsCls::IN,
                86400,
            )
            .expect("rr_add");
        rr.set_str(DnsRrKey::SOA_MNAME, "ns1.example.com")
            .expect("mname");
        rr.set_str(DnsRrKey::SOA_RNAME, "hostmaster.example.com")
            .expect("rname");
        rr.set_u32(DnsRrKey::SOA_SERIAL, 1).expect("serial");
        rr.set_u32(DnsRrKey::SOA_REFRESH, 3600).expect("refresh");
        rr.set_u32(DnsRrKey::SOA_RETRY, 900).expect("retry");
        rr.set_u32(DnsRrKey::SOA_EXPIRE, 604800).expect("expire");
        rr.set_u32(DnsRrKey::SOA_MINIMUM, 60).expect("minimum");

        let wire = rec.write().expect("write");
        let rec2 = DnsRecord::parse(&wire, DnsParseFlags::empty()).expect("reparse");
        assert_eq!(rec2.id(), 5);
        assert!(rec2.flags().contains(DnsFlags::AA));
        let rr = rec2.rr(DnsSection::Answer, 0).expect("rr");
        assert_eq!(rr.get_str(DnsRrKey::SOA_MNAME), Some("ns1.example.com"));
        assert_eq!(
            rr.get_str(DnsRrKey::SOA_RNAME),
            Some("hostmaster.example.com")
        );
        assert_eq!(rr.get_u32(DnsRrKey::SOA_SERIAL), 1);
        assert_eq!(rr.get_u32(DnsRrKey::SOA_EXPIRE), 604800);
    }

    // --- Coverage: TXT abin write/reparse round trip ---
    #[test]
    fn txt_abin_write_reparse() {
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
        rr.add_abin(DnsRrKey::TXT_DATA, b"v=spf1 include:example.com ~all")
            .expect("add_abin");

        let wire = rec.write().expect("write");
        let rec2 = DnsRecord::parse(&wire, DnsParseFlags::empty()).expect("reparse");
        let rr = rec2.rr(DnsSection::Answer, 0).expect("rr");
        assert_eq!(rr.get_abin_count(DnsRrKey::TXT_DATA), 1);
        assert_eq!(
            rr.get_abin(DnsRrKey::TXT_DATA, 0).unwrap(),
            b"v=spf1 include:example.com ~all"
        );
    }

    // --- Coverage: CString null byte errors ---
    #[test]
    fn query_add_rejects_null_byte() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        let result = rec.query_add("ex\0ample.com", DnsRecordType::A, DnsCls::IN);
        assert!(matches!(result, Err(Error::EBADSTR)));
    }

    #[test]
    fn query_set_name_rejects_null_byte() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        let result = rec.query_set_name(0, "ex\0ample.com");
        assert!(matches!(result, Err(Error::EBADSTR)));
    }

    #[test]
    fn rr_add_rejects_null_byte() {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        let result = rec.rr_add(
            DnsSection::Answer,
            "ex\0ample.com",
            DnsRecordType::A,
            DnsCls::IN,
            300,
        );
        assert!(matches!(result, Err(Error::EBADSTR)));
    }

    #[test]
    fn debug_dns_record() {
        let rec =
            DnsRecord::new(42, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        let debug = format!("{:?}", rec);
        assert!(debug.contains("DnsRecord"));
        assert!(debug.contains("42"));
    }

    #[test]
    fn clone_dns_record() {
        let mut rec =
            DnsRecord::new(7, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");

        let cloned = rec.try_clone().expect("try_clone");
        assert_eq!(cloned.id(), 7);
        assert_eq!(cloned.query_count(), 1);
        let (name, qtype, _) = cloned.query_get(0).expect("query_get");
        assert_eq!(name, "example.com");
        assert_eq!(qtype, DnsRecordType::A);

        // Mutating the original should not affect the clone.
        rec.set_id(99);
        assert_eq!(cloned.id(), 7);
    }
}
