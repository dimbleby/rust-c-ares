use std::ffi::CString;
use std::fmt;
use std::str::FromStr;

use bitflags::bitflags;

use crate::error::{Error, Result};
use crate::utils::dns_string_as_str;

/// DNS record types handled by c-ares.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
pub enum DnsRecordType {
    /// Host address (A).
    A,
    /// Authoritative server (NS).
    NS,
    /// Canonical name (CNAME).
    CNAME,
    /// Start of authority zone (SOA).
    SOA,
    /// Domain name pointer (PTR).
    PTR,
    /// Host information (HINFO).
    HINFO,
    /// Mail routing information (MX).
    MX,
    /// Text strings (TXT).
    TXT,
    /// SIG record (RFC 2535 / RFC 2931).
    SIG,
    /// IPv6 address (AAAA, RFC 3596).
    AAAA,
    /// Server selection (SRV, RFC 2782).
    SRV,
    /// Naming authority pointer (NAPTR, RFC 3403).
    NAPTR,
    /// EDNS0 option (OPT, RFC 6891).
    OPT,
    /// DANE TLSA (RFC 6698).
    TLSA,
    /// General purpose service binding (SVCB, RFC 9460).
    SVCB,
    /// HTTPS service binding (RFC 9460).
    HTTPS,
    /// Wildcard match (requests only).
    ANY,
    /// URI (RFC 7553).
    URI,
    /// Certification authority authorization (CAA, RFC 6844).
    CAA,
    /// Raw/unparsed RR record.
    RAW_RR,
}

impl From<DnsRecordType> for c_ares_sys::ares_dns_rec_type_t {
    fn from(val: DnsRecordType) -> Self {
        match val {
            DnsRecordType::A => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_A,
            DnsRecordType::NS => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_NS,
            DnsRecordType::CNAME => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_CNAME,
            DnsRecordType::SOA => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_SOA,
            DnsRecordType::PTR => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_PTR,
            DnsRecordType::HINFO => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_HINFO,
            DnsRecordType::MX => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_MX,
            DnsRecordType::TXT => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_TXT,
            DnsRecordType::SIG => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_SIG,
            DnsRecordType::AAAA => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_AAAA,
            DnsRecordType::SRV => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_SRV,
            DnsRecordType::NAPTR => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_NAPTR,
            DnsRecordType::OPT => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_OPT,
            DnsRecordType::TLSA => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_TLSA,
            DnsRecordType::SVCB => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_SVCB,
            DnsRecordType::HTTPS => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_HTTPS,
            DnsRecordType::ANY => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_ANY,
            DnsRecordType::URI => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_URI,
            DnsRecordType::CAA => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_CAA,
            DnsRecordType::RAW_RR => c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_RAW_RR,
        }
    }
}

impl From<c_ares_sys::ares_dns_rec_type_t> for DnsRecordType {
    fn from(val: c_ares_sys::ares_dns_rec_type_t) -> Self {
        match val {
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_A => DnsRecordType::A,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_NS => DnsRecordType::NS,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_CNAME => DnsRecordType::CNAME,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_SOA => DnsRecordType::SOA,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_PTR => DnsRecordType::PTR,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_HINFO => DnsRecordType::HINFO,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_MX => DnsRecordType::MX,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_TXT => DnsRecordType::TXT,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_SIG => DnsRecordType::SIG,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_AAAA => DnsRecordType::AAAA,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_SRV => DnsRecordType::SRV,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_NAPTR => DnsRecordType::NAPTR,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_OPT => DnsRecordType::OPT,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_TLSA => DnsRecordType::TLSA,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_SVCB => DnsRecordType::SVCB,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_HTTPS => DnsRecordType::HTTPS,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_ANY => DnsRecordType::ANY,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_URI => DnsRecordType::URI,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_CAA => DnsRecordType::CAA,
            c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_RAW_RR => DnsRecordType::RAW_RR,
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { c_ares_sys::ares_dns_rec_type_tostr((*self).into()) };
        f.write_str(unsafe { dns_string_as_str(ptr) })
    }
}

impl FromStr for DnsRecordType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let c_str = CString::new(s).map_err(|_| Error::EBADSTR)?;
        let mut qtype = c_ares_sys::ares_dns_rec_type_t::ARES_REC_TYPE_A;
        let ok = unsafe { c_ares_sys::ares_dns_rec_type_fromstr(&mut qtype, c_str.as_ptr()) };
        if ok == c_ares_sys::ares_bool_t::ARES_TRUE {
            Ok(DnsRecordType::from(qtype))
        } else {
            Err(Error::EFORMERR)
        }
    }
}

/// DNS classes for requests and responses.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum DnsCls {
    /// Internet.
    IN,
    /// CHAOS.
    CHAOS,
    /// Hesiod.
    HESIOD,
    /// None (RFC 2136).
    NONE,
    /// Any class (requests only).
    ANY,
}

impl From<DnsCls> for c_ares_sys::ares_dns_class_t {
    fn from(val: DnsCls) -> Self {
        match val {
            DnsCls::IN => c_ares_sys::ares_dns_class_t::ARES_CLASS_IN,
            DnsCls::CHAOS => c_ares_sys::ares_dns_class_t::ARES_CLASS_CHAOS,
            DnsCls::HESIOD => c_ares_sys::ares_dns_class_t::ARES_CLASS_HESOID,
            DnsCls::NONE => c_ares_sys::ares_dns_class_t::ARES_CLASS_NONE,
            DnsCls::ANY => c_ares_sys::ares_dns_class_t::ARES_CLASS_ANY,
        }
    }
}

impl From<c_ares_sys::ares_dns_class_t> for DnsCls {
    fn from(val: c_ares_sys::ares_dns_class_t) -> Self {
        match val {
            c_ares_sys::ares_dns_class_t::ARES_CLASS_IN => DnsCls::IN,
            c_ares_sys::ares_dns_class_t::ARES_CLASS_CHAOS => DnsCls::CHAOS,
            c_ares_sys::ares_dns_class_t::ARES_CLASS_HESOID => DnsCls::HESIOD,
            c_ares_sys::ares_dns_class_t::ARES_CLASS_NONE => DnsCls::NONE,
            c_ares_sys::ares_dns_class_t::ARES_CLASS_ANY => DnsCls::ANY,
        }
    }
}

impl fmt::Display for DnsCls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { c_ares_sys::ares_dns_class_tostr((*self).into()) };
        f.write_str(unsafe { dns_string_as_str(ptr) })
    }
}

impl FromStr for DnsCls {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let c_str = CString::new(s).map_err(|_| Error::EBADSTR)?;
        let mut qclass = c_ares_sys::ares_dns_class_t::ARES_CLASS_IN;
        let ok = unsafe { c_ares_sys::ares_dns_class_fromstr(&mut qclass, c_str.as_ptr()) };
        if ok == c_ares_sys::ares_bool_t::ARES_TRUE {
            Ok(DnsCls::from(qclass))
        } else {
            Err(Error::EFORMERR)
        }
    }
}

/// DNS message sections.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum DnsSection {
    /// Answer section.
    Answer,
    /// Authority section.
    Authority,
    /// Additional information section.
    Additional,
}

impl From<DnsSection> for c_ares_sys::ares_dns_section_t {
    fn from(val: DnsSection) -> Self {
        match val {
            DnsSection::Answer => c_ares_sys::ares_dns_section_t::ARES_SECTION_ANSWER,
            DnsSection::Authority => c_ares_sys::ares_dns_section_t::ARES_SECTION_AUTHORITY,
            DnsSection::Additional => c_ares_sys::ares_dns_section_t::ARES_SECTION_ADDITIONAL,
        }
    }
}

impl From<c_ares_sys::ares_dns_section_t> for DnsSection {
    fn from(val: c_ares_sys::ares_dns_section_t) -> Self {
        match val {
            c_ares_sys::ares_dns_section_t::ARES_SECTION_ANSWER => DnsSection::Answer,
            c_ares_sys::ares_dns_section_t::ARES_SECTION_AUTHORITY => DnsSection::Authority,
            c_ares_sys::ares_dns_section_t::ARES_SECTION_ADDITIONAL => DnsSection::Additional,
        }
    }
}

impl fmt::Display for DnsSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { c_ares_sys::ares_dns_section_tostr((*self).into()) };
        f.write_str(unsafe { dns_string_as_str(ptr) })
    }
}

/// DNS header opcodes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum DnsOpcode {
    /// Standard query.
    Query,
    /// Inverse query (obsolete).
    IQuery,
    /// Name server status query.
    Status,
    /// Zone change notification (RFC 1996).
    Notify,
    /// Zone update message (RFC 2136).
    Update,
}

impl From<DnsOpcode> for c_ares_sys::ares_dns_opcode_t {
    fn from(val: DnsOpcode) -> Self {
        match val {
            DnsOpcode::Query => c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_QUERY,
            DnsOpcode::IQuery => c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_IQUERY,
            DnsOpcode::Status => c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_STATUS,
            DnsOpcode::Notify => c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_NOTIFY,
            DnsOpcode::Update => c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_UPDATE,
        }
    }
}

impl From<c_ares_sys::ares_dns_opcode_t> for DnsOpcode {
    fn from(val: c_ares_sys::ares_dns_opcode_t) -> Self {
        match val {
            c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_QUERY => DnsOpcode::Query,
            c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_IQUERY => DnsOpcode::IQuery,
            c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_STATUS => DnsOpcode::Status,
            c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_NOTIFY => DnsOpcode::Notify,
            c_ares_sys::ares_dns_opcode_t::ARES_OPCODE_UPDATE => DnsOpcode::Update,
        }
    }
}

impl fmt::Display for DnsOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { c_ares_sys::ares_dns_opcode_tostr((*self).into()) };
        f.write_str(unsafe { dns_string_as_str(ptr) })
    }
}

/// DNS response codes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum DnsRcode {
    /// Success.
    NoError,
    /// Format error.
    FormErr,
    /// Server failure.
    ServFail,
    /// Name error (NXDOMAIN).
    NXDomain,
    /// Not implemented.
    NotImp,
    /// Refused.
    Refused,
    /// Name exists when it should not (RFC 2136).
    YXDomain,
    /// RR set exists when it should not (RFC 2136).
    YXRRSet,
    /// RR set that should exist does not (RFC 2136).
    NXRRSet,
    /// Server not authoritative for zone (RFC 2136).
    NotAuth,
    /// Name not in zone (RFC 2136).
    NotZone,
    /// DSO-TYPE not implemented (RFC 8490).
    DSOTypeI,
    /// TSIG signature failure (RFC 8945).
    BadSig,
    /// Key not recognized (RFC 8945).
    BadKey,
    /// Signature out of time window (RFC 8945).
    BadTime,
    /// Bad TKEY mode (RFC 2930).
    BadMode,
    /// Duplicate key name (RFC 2930).
    BadName,
    /// Algorithm not supported (RFC 2930).
    BadAlg,
    /// Bad truncation (RFC 8945).
    BadTrunc,
    /// Bad/missing server cookie (RFC 7873).
    BadCookie,
}

impl From<DnsRcode> for c_ares_sys::ares_dns_rcode_t {
    fn from(val: DnsRcode) -> Self {
        match val {
            DnsRcode::NoError => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NOERROR,
            DnsRcode::FormErr => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_FORMERR,
            DnsRcode::ServFail => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_SERVFAIL,
            DnsRcode::NXDomain => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NXDOMAIN,
            DnsRcode::NotImp => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NOTIMP,
            DnsRcode::Refused => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_REFUSED,
            DnsRcode::YXDomain => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_YXDOMAIN,
            DnsRcode::YXRRSet => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_YXRRSET,
            DnsRcode::NXRRSet => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NXRRSET,
            DnsRcode::NotAuth => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NOTAUTH,
            DnsRcode::NotZone => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NOTZONE,
            DnsRcode::DSOTypeI => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_DSOTYPEI,
            DnsRcode::BadSig => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADSIG,
            DnsRcode::BadKey => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADKEY,
            DnsRcode::BadTime => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADTIME,
            DnsRcode::BadMode => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADMODE,
            DnsRcode::BadName => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADNAME,
            DnsRcode::BadAlg => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADALG,
            DnsRcode::BadTrunc => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADTRUNC,
            DnsRcode::BadCookie => c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADCOOKIE,
        }
    }
}

impl From<c_ares_sys::ares_dns_rcode_t> for DnsRcode {
    fn from(val: c_ares_sys::ares_dns_rcode_t) -> Self {
        match val {
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NOERROR => DnsRcode::NoError,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_FORMERR => DnsRcode::FormErr,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_SERVFAIL => DnsRcode::ServFail,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NXDOMAIN => DnsRcode::NXDomain,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NOTIMP => DnsRcode::NotImp,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_REFUSED => DnsRcode::Refused,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_YXDOMAIN => DnsRcode::YXDomain,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_YXRRSET => DnsRcode::YXRRSet,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NXRRSET => DnsRcode::NXRRSet,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NOTAUTH => DnsRcode::NotAuth,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_NOTZONE => DnsRcode::NotZone,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_DSOTYPEI => DnsRcode::DSOTypeI,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADSIG => DnsRcode::BadSig,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADKEY => DnsRcode::BadKey,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADTIME => DnsRcode::BadTime,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADMODE => DnsRcode::BadMode,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADNAME => DnsRcode::BadName,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADALG => DnsRcode::BadAlg,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADTRUNC => DnsRcode::BadTrunc,
            c_ares_sys::ares_dns_rcode_t::ARES_RCODE_BADCOOKIE => DnsRcode::BadCookie,
        }
    }
}

impl fmt::Display for DnsRcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { c_ares_sys::ares_dns_rcode_tostr((*self).into()) };
        f.write_str(unsafe { dns_string_as_str(ptr) })
    }
}

bitflags!(
    /// DNS message header flags.
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
    pub struct DnsFlags: u16 {
        /// QR — if set, this is a response.
        const QR = c_ares_sys::ares_dns_flags_t::ARES_FLAG_QR as u16;
        /// AA — authoritative answer.
        const AA = c_ares_sys::ares_dns_flags_t::ARES_FLAG_AA as u16;
        /// TC — truncation.
        const TC = c_ares_sys::ares_dns_flags_t::ARES_FLAG_TC as u16;
        /// RD — recursion desired.
        const RD = c_ares_sys::ares_dns_flags_t::ARES_FLAG_RD as u16;
        /// RA — recursion available.
        const RA = c_ares_sys::ares_dns_flags_t::ARES_FLAG_RA as u16;
        /// AD — authentic data (RFC 2065).
        const AD = c_ares_sys::ares_dns_flags_t::ARES_FLAG_AD as u16;
        /// CD — checking disabled (RFC 2065).
        const CD = c_ares_sys::ares_dns_flags_t::ARES_FLAG_CD as u16;
    }
);

bitflags!(
    /// Flags controlling DNS message parsing behaviour.
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
    pub struct DnsParseFlags: u32 {
        /// Parse answers from RFC 1035 (name-compressed) as raw.
        const AN_BASE_RAW = c_ares_sys::ares_dns_parse_flags_t::ARES_DNS_PARSE_AN_BASE_RAW as u32;
        /// Parse authority from RFC 1035 (name-compressed) as raw.
        const NS_BASE_RAW = c_ares_sys::ares_dns_parse_flags_t::ARES_DNS_PARSE_NS_BASE_RAW as u32;
        /// Parse additional from RFC 1035 (name-compressed) as raw.
        const AR_BASE_RAW = c_ares_sys::ares_dns_parse_flags_t::ARES_DNS_PARSE_AR_BASE_RAW as u32;
        /// Parse answers from later RFCs (no name compression) as raw.
        const AN_EXT_RAW = c_ares_sys::ares_dns_parse_flags_t::ARES_DNS_PARSE_AN_EXT_RAW as u32;
        /// Parse authority from later RFCs (no name compression) as raw.
        const NS_EXT_RAW = c_ares_sys::ares_dns_parse_flags_t::ARES_DNS_PARSE_NS_EXT_RAW as u32;
        /// Parse additional from later RFCs (no name compression) as raw.
        const AR_EXT_RAW = c_ares_sys::ares_dns_parse_flags_t::ARES_DNS_PARSE_AR_EXT_RAW as u32;
    }
);

/// DNS resource record field keys.
///
/// Each variant identifies a specific field within a specific record type.
/// The key determines which getter/setter method is appropriate (e.g.
/// `get_addr` for `INADDR` fields, `get_str` for `NAME`/`STR` fields).
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
pub enum DnsRrKey {
    /// A record: address (INADDR).
    A_ADDR,
    /// NS record: name server domain name (NAME).
    NS_NSDNAME,
    /// CNAME record: canonical name (NAME).
    CNAME_CNAME,
    /// SOA record: primary source of data (NAME).
    SOA_MNAME,
    /// SOA record: responsible mailbox (NAME).
    SOA_RNAME,
    /// SOA record: serial number (U32).
    SOA_SERIAL,
    /// SOA record: refresh interval (U32).
    SOA_REFRESH,
    /// SOA record: retry interval (U32).
    SOA_RETRY,
    /// SOA record: expire limit (U32).
    SOA_EXPIRE,
    /// SOA record: minimum TTL (U32).
    SOA_MINIMUM,
    /// PTR record: pointer domain name (NAME).
    PTR_DNAME,
    /// HINFO record: CPU (STR).
    HINFO_CPU,
    /// HINFO record: OS (STR).
    HINFO_OS,
    /// MX record: preference (U16).
    MX_PREFERENCE,
    /// MX record: exchange domain (NAME).
    MX_EXCHANGE,
    /// TXT record: data (ABINP).
    TXT_DATA,
    /// SIG record: type covered (U16).
    SIG_TYPE_COVERED,
    /// SIG record: algorithm (U8).
    SIG_ALGORITHM,
    /// SIG record: labels (U8).
    SIG_LABELS,
    /// SIG record: original TTL (U32).
    SIG_ORIGINAL_TTL,
    /// SIG record: signature expiration (U32).
    SIG_EXPIRATION,
    /// SIG record: signature inception (U32).
    SIG_INCEPTION,
    /// SIG record: key tag (U16).
    SIG_KEY_TAG,
    /// SIG record: signer's name (NAME).
    SIG_SIGNERS_NAME,
    /// SIG record: signature data (BIN).
    SIG_SIGNATURE,
    /// AAAA record: IPv6 address (INADDR6).
    AAAA_ADDR,
    /// SRV record: priority (U16).
    SRV_PRIORITY,
    /// SRV record: weight (U16).
    SRV_WEIGHT,
    /// SRV record: port (U16).
    SRV_PORT,
    /// SRV record: target domain (NAME).
    SRV_TARGET,
    /// NAPTR record: order (U16).
    NAPTR_ORDER,
    /// NAPTR record: preference (U16).
    NAPTR_PREFERENCE,
    /// NAPTR record: flags (STR).
    NAPTR_FLAGS,
    /// NAPTR record: services (STR).
    NAPTR_SERVICES,
    /// NAPTR record: regexp (STR).
    NAPTR_REGEXP,
    /// NAPTR record: replacement (NAME).
    NAPTR_REPLACEMENT,
    /// OPT record: UDP size (U16).
    OPT_UDP_SIZE,
    /// OPT record: version (U8).
    OPT_VERSION,
    /// OPT record: flags (U16).
    OPT_FLAGS,
    /// OPT record: options (OPT).
    OPT_OPTIONS,
    /// TLSA record: certificate usage (U8).
    TLSA_CERT_USAGE,
    /// TLSA record: selector (U8).
    TLSA_SELECTOR,
    /// TLSA record: matching type (U8).
    TLSA_MATCH,
    /// TLSA record: certificate association data (BIN).
    TLSA_DATA,
    /// SVCB record: priority (U16).
    SVCB_PRIORITY,
    /// SVCB record: target name (NAME).
    SVCB_TARGET,
    /// SVCB record: service parameters (OPT).
    SVCB_PARAMS,
    /// HTTPS record: priority (U16).
    HTTPS_PRIORITY,
    /// HTTPS record: target name (NAME).
    HTTPS_TARGET,
    /// HTTPS record: service parameters (OPT).
    HTTPS_PARAMS,
    /// URI record: priority (U16).
    URI_PRIORITY,
    /// URI record: weight (U16).
    URI_WEIGHT,
    /// URI record: target (NAME).
    URI_TARGET,
    /// CAA record: critical flag (U8).
    CAA_CRITICAL,
    /// CAA record: tag/property (STR).
    CAA_TAG,
    /// CAA record: value (BINP).
    CAA_VALUE,
    /// RAW record: RR type (U16).
    RAW_RR_TYPE,
    /// RAW record: RR data (BIN).
    RAW_RR_DATA,
}

impl From<DnsRrKey> for c_ares_sys::ares_dns_rr_key_t {
    fn from(val: DnsRrKey) -> Self {
        match val {
            DnsRrKey::A_ADDR => c_ares_sys::ares_dns_rr_key_t::ARES_RR_A_ADDR,
            DnsRrKey::NS_NSDNAME => c_ares_sys::ares_dns_rr_key_t::ARES_RR_NS_NSDNAME,
            DnsRrKey::CNAME_CNAME => c_ares_sys::ares_dns_rr_key_t::ARES_RR_CNAME_CNAME,
            DnsRrKey::SOA_MNAME => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_MNAME,
            DnsRrKey::SOA_RNAME => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_RNAME,
            DnsRrKey::SOA_SERIAL => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_SERIAL,
            DnsRrKey::SOA_REFRESH => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_REFRESH,
            DnsRrKey::SOA_RETRY => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_RETRY,
            DnsRrKey::SOA_EXPIRE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_EXPIRE,
            DnsRrKey::SOA_MINIMUM => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_MINIMUM,
            DnsRrKey::PTR_DNAME => c_ares_sys::ares_dns_rr_key_t::ARES_RR_PTR_DNAME,
            DnsRrKey::HINFO_CPU => c_ares_sys::ares_dns_rr_key_t::ARES_RR_HINFO_CPU,
            DnsRrKey::HINFO_OS => c_ares_sys::ares_dns_rr_key_t::ARES_RR_HINFO_OS,
            DnsRrKey::MX_PREFERENCE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_MX_PREFERENCE,
            DnsRrKey::MX_EXCHANGE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_MX_EXCHANGE,
            DnsRrKey::TXT_DATA => c_ares_sys::ares_dns_rr_key_t::ARES_RR_TXT_DATA,
            DnsRrKey::SIG_TYPE_COVERED => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_TYPE_COVERED,
            DnsRrKey::SIG_ALGORITHM => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_ALGORITHM,
            DnsRrKey::SIG_LABELS => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_LABELS,
            DnsRrKey::SIG_ORIGINAL_TTL => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_ORIGINAL_TTL,
            DnsRrKey::SIG_EXPIRATION => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_EXPIRATION,
            DnsRrKey::SIG_INCEPTION => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_INCEPTION,
            DnsRrKey::SIG_KEY_TAG => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_KEY_TAG,
            DnsRrKey::SIG_SIGNERS_NAME => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_SIGNERS_NAME,
            DnsRrKey::SIG_SIGNATURE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_SIGNATURE,
            DnsRrKey::AAAA_ADDR => c_ares_sys::ares_dns_rr_key_t::ARES_RR_AAAA_ADDR,
            DnsRrKey::SRV_PRIORITY => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SRV_PRIORITY,
            DnsRrKey::SRV_WEIGHT => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SRV_WEIGHT,
            DnsRrKey::SRV_PORT => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SRV_PORT,
            DnsRrKey::SRV_TARGET => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SRV_TARGET,
            DnsRrKey::NAPTR_ORDER => c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_ORDER,
            DnsRrKey::NAPTR_PREFERENCE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_PREFERENCE,
            DnsRrKey::NAPTR_FLAGS => c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_FLAGS,
            DnsRrKey::NAPTR_SERVICES => c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_SERVICES,
            DnsRrKey::NAPTR_REGEXP => c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_REGEXP,
            DnsRrKey::NAPTR_REPLACEMENT => c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_REPLACEMENT,
            DnsRrKey::OPT_UDP_SIZE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_OPT_UDP_SIZE,
            DnsRrKey::OPT_VERSION => c_ares_sys::ares_dns_rr_key_t::ARES_RR_OPT_VERSION,
            DnsRrKey::OPT_FLAGS => c_ares_sys::ares_dns_rr_key_t::ARES_RR_OPT_FLAGS,
            DnsRrKey::OPT_OPTIONS => c_ares_sys::ares_dns_rr_key_t::ARES_RR_OPT_OPTIONS,
            DnsRrKey::TLSA_CERT_USAGE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_TLSA_CERT_USAGE,
            DnsRrKey::TLSA_SELECTOR => c_ares_sys::ares_dns_rr_key_t::ARES_RR_TLSA_SELECTOR,
            DnsRrKey::TLSA_MATCH => c_ares_sys::ares_dns_rr_key_t::ARES_RR_TLSA_MATCH,
            DnsRrKey::TLSA_DATA => c_ares_sys::ares_dns_rr_key_t::ARES_RR_TLSA_DATA,
            DnsRrKey::SVCB_PRIORITY => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SVCB_PRIORITY,
            DnsRrKey::SVCB_TARGET => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SVCB_TARGET,
            DnsRrKey::SVCB_PARAMS => c_ares_sys::ares_dns_rr_key_t::ARES_RR_SVCB_PARAMS,
            DnsRrKey::HTTPS_PRIORITY => c_ares_sys::ares_dns_rr_key_t::ARES_RR_HTTPS_PRIORITY,
            DnsRrKey::HTTPS_TARGET => c_ares_sys::ares_dns_rr_key_t::ARES_RR_HTTPS_TARGET,
            DnsRrKey::HTTPS_PARAMS => c_ares_sys::ares_dns_rr_key_t::ARES_RR_HTTPS_PARAMS,
            DnsRrKey::URI_PRIORITY => c_ares_sys::ares_dns_rr_key_t::ARES_RR_URI_PRIORITY,
            DnsRrKey::URI_WEIGHT => c_ares_sys::ares_dns_rr_key_t::ARES_RR_URI_WEIGHT,
            DnsRrKey::URI_TARGET => c_ares_sys::ares_dns_rr_key_t::ARES_RR_URI_TARGET,
            DnsRrKey::CAA_CRITICAL => c_ares_sys::ares_dns_rr_key_t::ARES_RR_CAA_CRITICAL,
            DnsRrKey::CAA_TAG => c_ares_sys::ares_dns_rr_key_t::ARES_RR_CAA_TAG,
            DnsRrKey::CAA_VALUE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_CAA_VALUE,
            DnsRrKey::RAW_RR_TYPE => c_ares_sys::ares_dns_rr_key_t::ARES_RR_RAW_RR_TYPE,
            DnsRrKey::RAW_RR_DATA => c_ares_sys::ares_dns_rr_key_t::ARES_RR_RAW_RR_DATA,
        }
    }
}

impl From<c_ares_sys::ares_dns_rr_key_t> for DnsRrKey {
    fn from(val: c_ares_sys::ares_dns_rr_key_t) -> Self {
        match val {
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_A_ADDR => DnsRrKey::A_ADDR,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_NS_NSDNAME => DnsRrKey::NS_NSDNAME,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_CNAME_CNAME => DnsRrKey::CNAME_CNAME,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_MNAME => DnsRrKey::SOA_MNAME,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_RNAME => DnsRrKey::SOA_RNAME,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_SERIAL => DnsRrKey::SOA_SERIAL,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_REFRESH => DnsRrKey::SOA_REFRESH,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_RETRY => DnsRrKey::SOA_RETRY,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_EXPIRE => DnsRrKey::SOA_EXPIRE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SOA_MINIMUM => DnsRrKey::SOA_MINIMUM,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_PTR_DNAME => DnsRrKey::PTR_DNAME,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_HINFO_CPU => DnsRrKey::HINFO_CPU,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_HINFO_OS => DnsRrKey::HINFO_OS,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_MX_PREFERENCE => DnsRrKey::MX_PREFERENCE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_MX_EXCHANGE => DnsRrKey::MX_EXCHANGE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_TXT_DATA => DnsRrKey::TXT_DATA,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_TYPE_COVERED => DnsRrKey::SIG_TYPE_COVERED,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_ALGORITHM => DnsRrKey::SIG_ALGORITHM,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_LABELS => DnsRrKey::SIG_LABELS,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_ORIGINAL_TTL => DnsRrKey::SIG_ORIGINAL_TTL,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_EXPIRATION => DnsRrKey::SIG_EXPIRATION,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_INCEPTION => DnsRrKey::SIG_INCEPTION,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_KEY_TAG => DnsRrKey::SIG_KEY_TAG,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_SIGNERS_NAME => DnsRrKey::SIG_SIGNERS_NAME,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SIG_SIGNATURE => DnsRrKey::SIG_SIGNATURE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_AAAA_ADDR => DnsRrKey::AAAA_ADDR,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SRV_PRIORITY => DnsRrKey::SRV_PRIORITY,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SRV_WEIGHT => DnsRrKey::SRV_WEIGHT,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SRV_PORT => DnsRrKey::SRV_PORT,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SRV_TARGET => DnsRrKey::SRV_TARGET,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_ORDER => DnsRrKey::NAPTR_ORDER,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_PREFERENCE => DnsRrKey::NAPTR_PREFERENCE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_FLAGS => DnsRrKey::NAPTR_FLAGS,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_SERVICES => DnsRrKey::NAPTR_SERVICES,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_REGEXP => DnsRrKey::NAPTR_REGEXP,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_NAPTR_REPLACEMENT => DnsRrKey::NAPTR_REPLACEMENT,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_OPT_UDP_SIZE => DnsRrKey::OPT_UDP_SIZE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_OPT_VERSION => DnsRrKey::OPT_VERSION,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_OPT_FLAGS => DnsRrKey::OPT_FLAGS,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_OPT_OPTIONS => DnsRrKey::OPT_OPTIONS,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_TLSA_CERT_USAGE => DnsRrKey::TLSA_CERT_USAGE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_TLSA_SELECTOR => DnsRrKey::TLSA_SELECTOR,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_TLSA_MATCH => DnsRrKey::TLSA_MATCH,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_TLSA_DATA => DnsRrKey::TLSA_DATA,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SVCB_PRIORITY => DnsRrKey::SVCB_PRIORITY,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SVCB_TARGET => DnsRrKey::SVCB_TARGET,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_SVCB_PARAMS => DnsRrKey::SVCB_PARAMS,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_HTTPS_PRIORITY => DnsRrKey::HTTPS_PRIORITY,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_HTTPS_TARGET => DnsRrKey::HTTPS_TARGET,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_HTTPS_PARAMS => DnsRrKey::HTTPS_PARAMS,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_URI_PRIORITY => DnsRrKey::URI_PRIORITY,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_URI_WEIGHT => DnsRrKey::URI_WEIGHT,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_URI_TARGET => DnsRrKey::URI_TARGET,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_CAA_CRITICAL => DnsRrKey::CAA_CRITICAL,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_CAA_TAG => DnsRrKey::CAA_TAG,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_CAA_VALUE => DnsRrKey::CAA_VALUE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_RAW_RR_TYPE => DnsRrKey::RAW_RR_TYPE,
            c_ares_sys::ares_dns_rr_key_t::ARES_RR_RAW_RR_DATA => DnsRrKey::RAW_RR_DATA,
        }
    }
}

impl fmt::Display for DnsRrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { c_ares_sys::ares_dns_rr_key_tostr((*self).into()) };
        f.write_str(unsafe { dns_string_as_str(ptr) })
    }
}

/// Data types for DNS resource record fields.
///
/// Returned by [`DnsRrKey::datatype()`] to indicate which getter/setter is
/// appropriate for a given key.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum DnsDataType {
    /// IPv4 address (`struct in_addr`).
    InAddr,
    /// IPv6 address (`struct ares_in6_addr`).
    InAddr6,
    /// 8-bit unsigned integer.
    U8,
    /// 16-bit unsigned integer.
    U16,
    /// 32-bit unsigned integer.
    U32,
    /// Domain name (null-terminated string).
    Name,
    /// Null-terminated string.
    Str,
    /// Binary data.
    Bin,
    /// Binary data, likely printable.
    BinP,
    /// Array of options (16-bit key + binary value).
    Opt,
    /// Array of binary data, likely printable.
    ABinP,
}

impl From<c_ares_sys::ares_dns_datatype_t> for DnsDataType {
    fn from(val: c_ares_sys::ares_dns_datatype_t) -> Self {
        match val {
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_INADDR => DnsDataType::InAddr,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_INADDR6 => DnsDataType::InAddr6,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_U8 => DnsDataType::U8,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_U16 => DnsDataType::U16,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_U32 => DnsDataType::U32,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_NAME => DnsDataType::Name,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_STR => DnsDataType::Str,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_BIN => DnsDataType::Bin,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_BINP => DnsDataType::BinP,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_OPT => DnsDataType::Opt,
            c_ares_sys::ares_dns_datatype_t::ARES_DATATYPE_ABINP => DnsDataType::ABinP,
        }
    }
}

/// Data type for option records for keys like `OPT_OPTIONS` and
/// `HTTPS_PARAMS`.
///
/// Returned by [`DnsRrKey::opt_datatype()`] to indicate the best match for
/// interpreting an option record value.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum DnsOptDataType {
    /// No value allowed for this option.
    None,
    /// List of strings, each prefixed with a single octet representing the length.
    StrList,
    /// List of 8-bit integers, concatenated.
    U8List,
    /// 16-bit integer in network byte order.
    U16,
    /// List of 16-bit integers in network byte order, concatenated.
    U16List,
    /// 32-bit integer in network byte order.
    U32,
    /// List of 32-bit integers in network byte order, concatenated.
    U32List,
    /// List of IPv4 addresses in network byte order, concatenated.
    InAddr4List,
    /// List of IPv6 addresses in network byte order, concatenated.
    InAddr6List,
    /// Binary data.
    Bin,
    /// DNS domain name format.
    Name,
}

impl From<c_ares_sys::ares_dns_opt_datatype_t> for DnsOptDataType {
    fn from(val: c_ares_sys::ares_dns_opt_datatype_t) -> Self {
        match val {
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_NONE => DnsOptDataType::None,
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_STR_LIST => {
                DnsOptDataType::StrList
            }
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_U8_LIST => {
                DnsOptDataType::U8List
            }
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_U16 => DnsOptDataType::U16,
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_U16_LIST => {
                DnsOptDataType::U16List
            }
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_U32 => DnsOptDataType::U32,
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_U32_LIST => {
                DnsOptDataType::U32List
            }
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_INADDR4_LIST => {
                DnsOptDataType::InAddr4List
            }
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_INADDR6_LIST => {
                DnsOptDataType::InAddr6List
            }
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_BIN => DnsOptDataType::Bin,
            c_ares_sys::ares_dns_opt_datatype_t::ARES_OPT_DATATYPE_NAME => DnsOptDataType::Name,
        }
    }
}

impl DnsRrKey {
    /// Returns the data type associated with this resource record key.
    ///
    /// This tells the caller which getter/setter method to use (e.g.
    /// `get_addr` for [`DnsDataType::InAddr`], `get_str` for
    /// [`DnsDataType::Str`] or [`DnsDataType::Name`]).
    pub fn datatype(self) -> DnsDataType {
        let raw = unsafe { c_ares_sys::ares_dns_rr_key_datatype(self.into()) };
        DnsDataType::from(raw)
    }

    /// Returns the DNS record type that this key belongs to.
    ///
    /// For example, `DnsRrKey::A_ADDR` returns `DnsRecordType::A`.
    pub fn record_type(self) -> DnsRecordType {
        let raw = unsafe { c_ares_sys::ares_dns_rr_key_to_rec_type(self.into()) };
        DnsRecordType::from(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_round_trip_record_type() {
        let variants = [
            DnsRecordType::A,
            DnsRecordType::NS,
            DnsRecordType::CNAME,
            DnsRecordType::SOA,
            DnsRecordType::PTR,
            DnsRecordType::HINFO,
            DnsRecordType::MX,
            DnsRecordType::TXT,
            DnsRecordType::SIG,
            DnsRecordType::AAAA,
            DnsRecordType::SRV,
            DnsRecordType::NAPTR,
            DnsRecordType::OPT,
            DnsRecordType::TLSA,
            DnsRecordType::SVCB,
            DnsRecordType::HTTPS,
            DnsRecordType::ANY,
            DnsRecordType::URI,
            DnsRecordType::CAA,
            DnsRecordType::RAW_RR,
        ];
        for v in variants {
            let sys: c_ares_sys::ares_dns_rec_type_t = v.into();
            let back: DnsRecordType = sys.into();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn enum_round_trip_dns_class() {
        let variants = [
            DnsCls::IN,
            DnsCls::CHAOS,
            DnsCls::HESIOD,
            DnsCls::NONE,
            DnsCls::ANY,
        ];
        for v in variants {
            let sys: c_ares_sys::ares_dns_class_t = v.into();
            let back: DnsCls = sys.into();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn enum_round_trip_section() {
        let variants = [
            DnsSection::Answer,
            DnsSection::Authority,
            DnsSection::Additional,
        ];
        for v in variants {
            let sys: c_ares_sys::ares_dns_section_t = v.into();
            let back: DnsSection = sys.into();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn enum_round_trip_opcode() {
        let variants = [
            DnsOpcode::Query,
            DnsOpcode::IQuery,
            DnsOpcode::Status,
            DnsOpcode::Notify,
            DnsOpcode::Update,
        ];
        for v in variants {
            let sys: c_ares_sys::ares_dns_opcode_t = v.into();
            let back: DnsOpcode = sys.into();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn enum_round_trip_rcode() {
        let variants = [
            DnsRcode::NoError,
            DnsRcode::FormErr,
            DnsRcode::ServFail,
            DnsRcode::NXDomain,
            DnsRcode::NotImp,
            DnsRcode::Refused,
            DnsRcode::YXDomain,
            DnsRcode::YXRRSet,
            DnsRcode::NXRRSet,
            DnsRcode::NotAuth,
            DnsRcode::NotZone,
            DnsRcode::DSOTypeI,
            DnsRcode::BadSig,
            DnsRcode::BadKey,
            DnsRcode::BadTime,
            DnsRcode::BadMode,
            DnsRcode::BadName,
            DnsRcode::BadAlg,
            DnsRcode::BadTrunc,
            DnsRcode::BadCookie,
        ];
        for v in variants {
            let sys: c_ares_sys::ares_dns_rcode_t = v.into();
            let back: DnsRcode = sys.into();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn enum_round_trip_rr_key() {
        let variants = [
            DnsRrKey::A_ADDR,
            DnsRrKey::NS_NSDNAME,
            DnsRrKey::CNAME_CNAME,
            DnsRrKey::SOA_MNAME,
            DnsRrKey::SOA_RNAME,
            DnsRrKey::SOA_SERIAL,
            DnsRrKey::SOA_REFRESH,
            DnsRrKey::SOA_RETRY,
            DnsRrKey::SOA_EXPIRE,
            DnsRrKey::SOA_MINIMUM,
            DnsRrKey::PTR_DNAME,
            DnsRrKey::HINFO_CPU,
            DnsRrKey::HINFO_OS,
            DnsRrKey::MX_PREFERENCE,
            DnsRrKey::MX_EXCHANGE,
            DnsRrKey::TXT_DATA,
            DnsRrKey::SIG_TYPE_COVERED,
            DnsRrKey::SIG_ALGORITHM,
            DnsRrKey::SIG_LABELS,
            DnsRrKey::SIG_ORIGINAL_TTL,
            DnsRrKey::SIG_EXPIRATION,
            DnsRrKey::SIG_INCEPTION,
            DnsRrKey::SIG_KEY_TAG,
            DnsRrKey::SIG_SIGNERS_NAME,
            DnsRrKey::SIG_SIGNATURE,
            DnsRrKey::AAAA_ADDR,
            DnsRrKey::SRV_PRIORITY,
            DnsRrKey::SRV_WEIGHT,
            DnsRrKey::SRV_PORT,
            DnsRrKey::SRV_TARGET,
            DnsRrKey::NAPTR_ORDER,
            DnsRrKey::NAPTR_PREFERENCE,
            DnsRrKey::NAPTR_FLAGS,
            DnsRrKey::NAPTR_SERVICES,
            DnsRrKey::NAPTR_REGEXP,
            DnsRrKey::NAPTR_REPLACEMENT,
            DnsRrKey::OPT_UDP_SIZE,
            DnsRrKey::OPT_VERSION,
            DnsRrKey::OPT_FLAGS,
            DnsRrKey::OPT_OPTIONS,
            DnsRrKey::TLSA_CERT_USAGE,
            DnsRrKey::TLSA_SELECTOR,
            DnsRrKey::TLSA_MATCH,
            DnsRrKey::TLSA_DATA,
            DnsRrKey::SVCB_PRIORITY,
            DnsRrKey::SVCB_TARGET,
            DnsRrKey::SVCB_PARAMS,
            DnsRrKey::HTTPS_PRIORITY,
            DnsRrKey::HTTPS_TARGET,
            DnsRrKey::HTTPS_PARAMS,
            DnsRrKey::URI_PRIORITY,
            DnsRrKey::URI_WEIGHT,
            DnsRrKey::URI_TARGET,
            DnsRrKey::CAA_CRITICAL,
            DnsRrKey::CAA_TAG,
            DnsRrKey::CAA_VALUE,
            DnsRrKey::RAW_RR_TYPE,
            DnsRrKey::RAW_RR_DATA,
        ];
        for v in variants {
            let sys: c_ares_sys::ares_dns_rr_key_t = v.into();
            let back: DnsRrKey = sys.into();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn dns_flags_bitflags() {
        let flags = DnsFlags::QR | DnsFlags::RD;
        assert!(flags.contains(DnsFlags::QR));
        assert!(flags.contains(DnsFlags::RD));
        assert!(!flags.contains(DnsFlags::AA));
    }

    #[test]
    fn dns_flags_all_bits() {
        let all = DnsFlags::QR
            | DnsFlags::AA
            | DnsFlags::TC
            | DnsFlags::RD
            | DnsFlags::RA
            | DnsFlags::AD
            | DnsFlags::CD;
        assert!(all.contains(DnsFlags::QR));
        assert!(all.contains(DnsFlags::AA));
        assert!(all.contains(DnsFlags::TC));
        assert!(all.contains(DnsFlags::RD));
        assert!(all.contains(DnsFlags::RA));
        assert!(all.contains(DnsFlags::AD));
        assert!(all.contains(DnsFlags::CD));
    }

    #[test]
    fn display_record_type() {
        assert_eq!(DnsRecordType::A.to_string(), "A");
        assert_eq!(DnsRecordType::AAAA.to_string(), "AAAA");
        assert_eq!(DnsRecordType::MX.to_string(), "MX");
        assert_eq!(DnsRecordType::CNAME.to_string(), "CNAME");
        assert_eq!(DnsRecordType::SRV.to_string(), "SRV");
    }

    #[test]
    fn fromstr_record_type() {
        assert_eq!("A".parse::<DnsRecordType>().unwrap(), DnsRecordType::A);
        assert_eq!(
            "AAAA".parse::<DnsRecordType>().unwrap(),
            DnsRecordType::AAAA
        );
        assert_eq!("MX".parse::<DnsRecordType>().unwrap(), DnsRecordType::MX);
        assert!("NOTARECORD".parse::<DnsRecordType>().is_err());
    }

    #[test]
    fn display_dns_class() {
        assert_eq!(DnsCls::IN.to_string(), "IN");
        assert_eq!(DnsCls::CHAOS.to_string(), "CH");
        assert_eq!(DnsCls::ANY.to_string(), "ANY");
    }

    #[test]
    fn fromstr_dns_class() {
        assert_eq!("IN".parse::<DnsCls>().unwrap(), DnsCls::IN);
        assert_eq!("ANY".parse::<DnsCls>().unwrap(), DnsCls::ANY);
        assert!("NOTACLASS".parse::<DnsCls>().is_err());
    }

    #[test]
    fn display_section() {
        assert_eq!(DnsSection::Answer.to_string(), "ANSWER");
        assert_eq!(DnsSection::Authority.to_string(), "AUTHORITY");
        assert_eq!(DnsSection::Additional.to_string(), "ADDITIONAL");
    }

    #[test]
    fn display_opcode() {
        assert_eq!(DnsOpcode::Query.to_string(), "QUERY");
    }

    #[test]
    fn display_rcode() {
        assert_eq!(DnsRcode::NoError.to_string(), "NOERROR");
        assert_eq!(DnsRcode::NXDomain.to_string(), "NXDOMAIN");
        assert_eq!(DnsRcode::ServFail.to_string(), "SERVFAIL");
    }

    #[test]
    fn display_rr_key() {
        assert_eq!(DnsRrKey::A_ADDR.to_string(), "ADDR");
        assert_eq!(DnsRrKey::MX_PREFERENCE.to_string(), "PREFERENCE");
    }

    #[test]
    fn rr_key_datatype() {
        assert_eq!(DnsRrKey::A_ADDR.datatype(), DnsDataType::InAddr);
        assert_eq!(DnsRrKey::AAAA_ADDR.datatype(), DnsDataType::InAddr6);
        assert_eq!(DnsRrKey::MX_PREFERENCE.datatype(), DnsDataType::U16);
        assert_eq!(DnsRrKey::MX_EXCHANGE.datatype(), DnsDataType::Name);
        assert_eq!(DnsRrKey::SOA_SERIAL.datatype(), DnsDataType::U32);
        assert_eq!(DnsRrKey::TXT_DATA.datatype(), DnsDataType::ABinP);
        assert_eq!(DnsRrKey::OPT_OPTIONS.datatype(), DnsDataType::Opt);
    }

    #[test]
    fn rr_key_record_type() {
        assert_eq!(DnsRrKey::A_ADDR.record_type(), DnsRecordType::A);
        assert_eq!(DnsRrKey::AAAA_ADDR.record_type(), DnsRecordType::AAAA);
        assert_eq!(DnsRrKey::MX_PREFERENCE.record_type(), DnsRecordType::MX);
        assert_eq!(DnsRrKey::MX_EXCHANGE.record_type(), DnsRecordType::MX);
        assert_eq!(DnsRrKey::SOA_MNAME.record_type(), DnsRecordType::SOA);
        assert_eq!(DnsRrKey::CAA_TAG.record_type(), DnsRecordType::CAA);
    }
}
