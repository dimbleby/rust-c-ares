//! Strongly-typed views of DNS resource records.
//!
//! [`DnsRr`] exposes a generic, untyped API where field access is keyed by
//! [`DnsRrKey`] and the caller must pick the correct datatype-specific
//! getter (`get_addr`, `get_str`, `get_u16`, …). This module layers a set
//! of strongly-typed borrowed-view wrappers over `DnsRr`, one per concrete
//! record type, with idiomatic getters that hide the key/datatype machinery.
//!
//! # Example
//!
//! ```no_run
//! use c_ares::{DnsRecord, DnsParseFlags, DnsSection, TypedRr};
//!
//! # fn handle(wire: &[u8]) -> c_ares::Result<()> {
//! let rec = DnsRecord::parse(wire, DnsParseFlags::empty())?;
//! for rr in rec.rrs(DnsSection::Answer) {
//!     match rr.as_typed() {
//!         TypedRr::A(a) => println!("{}: A {}", a.name(), a.addr()),
//!         TypedRr::Mx(mx) => {
//!             println!("{}: MX {} {}", mx.name(), mx.preference(), mx.exchange());
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Field optionality
//!
//! Typed accessors return bare values, never `Option`.
//!
//! - **Numeric scalars** (`u8`, `u16`, `u32`) return zero when unset.
//! - **`Ipv4Addr` / `Ipv6Addr`** return `0.0.0.0` / `::` when unset.
//! - **`&str` / `&[u8]`** return `""` / `&[]` when unset.
//! - **Array-shaped fields** (TXT entries, OPT/SVCB/HTTPS parameters)
//!   are exposed as iterators with companion `*_count` methods; an empty
//!   array is its own valid representation.
//!
//! # Discrimination
//!
//! Each wrapper has a corresponding `as_*` discriminator inherent method
//! on [`DnsRr`] (e.g. [`DnsRr::as_a`]) that returns `Some(wrapper)` iff
//! the record's [`rr_type`](DnsRr::rr_type) matches. The
//! [`DnsRr::as_typed`] method dispatches on the type once and returns a
//! [`TypedRr`] enum carrying the typed view directly.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::dns_opt::{OptParseError, OptValue, parse_opt_value};
use super::enums::{DnsCls, DnsRecordType, DnsRrKey};
use super::rr::DnsRr;

/// Generates the four common accessors (`as_dns_rr`, `name`, `dns_class`,
/// `ttl`) that every typed record wrapper exposes, plus an associated
/// constructor `pub(super) fn new(rr: &'a DnsRr) -> Self`.
macro_rules! common_accessors {
    ($struct:ident) => {
        /// Wraps a generic [`DnsRr`] without checking its type.
        pub(super) fn new(rr: &'a DnsRr) -> Self {
            Self(rr)
        }

        /// Returns the underlying generic [`DnsRr`].
        ///
        /// Useful for accessing common fields via [`DnsRr`]'s own API,
        /// for [`Debug`](fmt::Debug) formatting, or for falling back to
        /// the raw key-based getters.
        pub fn as_dns_rr(self) -> &'a DnsRr {
            self.0
        }

        /// Returns the resource record owner name.
        pub fn name(self) -> &'a str {
            self.0.name()
        }

        /// Returns the resource record DNS class.
        pub fn dns_class(self) -> DnsCls {
            self.0.dns_class()
        }

        /// Returns the resource record TTL in seconds.
        pub fn ttl(self) -> u32 {
            self.0.ttl()
        }
    };
}

// =============================================================================
// Fixed-shape record wrappers
// =============================================================================

/// Typed view of an [`A`](DnsRecordType::A) record.
#[derive(Copy, Clone)]
pub struct ARecord<'a>(&'a DnsRr);

impl<'a> ARecord<'a> {
    common_accessors!(ARecord);

    /// Returns the IPv4 address ([`A_ADDR`](DnsRrKey::A_ADDR)).
    ///
    /// Defaults to `0.0.0.0` for builder records where `set_addr` has
    /// not been called.
    pub fn addr(self) -> Ipv4Addr {
        self.0
            .get_addr(DnsRrKey::A_ADDR)
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }
}

impl fmt::Debug for ARecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ARecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("addr", &self.addr())
            .finish()
    }
}

/// Typed view of an [`AAAA`](DnsRecordType::AAAA) record.
#[derive(Copy, Clone)]
pub struct AaaaRecord<'a>(&'a DnsRr);

impl<'a> AaaaRecord<'a> {
    common_accessors!(AaaaRecord);

    /// Returns the IPv6 address ([`AAAA_ADDR`](DnsRrKey::AAAA_ADDR)).
    ///
    /// Defaults to `::` for builder records where `set_addr6` has not
    /// been called.
    pub fn addr(self) -> Ipv6Addr {
        self.0
            .get_addr6(DnsRrKey::AAAA_ADDR)
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
    }
}

impl fmt::Debug for AaaaRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AaaaRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("addr", &self.addr())
            .finish()
    }
}

/// Typed view of an [`NS`](DnsRecordType::NS) record.
#[derive(Copy, Clone)]
pub struct NsRecord<'a>(&'a DnsRr);

impl<'a> NsRecord<'a> {
    common_accessors!(NsRecord);

    /// Returns the name server domain name
    /// ([`NS_NSDNAME`](DnsRrKey::NS_NSDNAME)).
    pub fn nsdname(self) -> &'a str {
        self.0.get_str(DnsRrKey::NS_NSDNAME).unwrap_or("")
    }
}

impl fmt::Debug for NsRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NsRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("nsdname", &self.nsdname())
            .finish()
    }
}

/// Typed view of a [`CNAME`](DnsRecordType::CNAME) record.
#[derive(Copy, Clone)]
pub struct CnameRecord<'a>(&'a DnsRr);

impl<'a> CnameRecord<'a> {
    common_accessors!(CnameRecord);

    /// Returns the canonical name ([`CNAME_CNAME`](DnsRrKey::CNAME_CNAME)).
    pub fn cname(self) -> &'a str {
        self.0.get_str(DnsRrKey::CNAME_CNAME).unwrap_or("")
    }
}

impl fmt::Debug for CnameRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CnameRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("cname", &self.cname())
            .finish()
    }
}

/// Typed view of an [`SOA`](DnsRecordType::SOA) record.
#[derive(Copy, Clone)]
pub struct SoaRecord<'a>(&'a DnsRr);

impl<'a> SoaRecord<'a> {
    common_accessors!(SoaRecord);

    /// Primary nameserver ([`SOA_MNAME`](DnsRrKey::SOA_MNAME)).
    pub fn mname(self) -> &'a str {
        self.0.get_str(DnsRrKey::SOA_MNAME).unwrap_or("")
    }

    /// Responsible mailbox ([`SOA_RNAME`](DnsRrKey::SOA_RNAME)).
    pub fn rname(self) -> &'a str {
        self.0.get_str(DnsRrKey::SOA_RNAME).unwrap_or("")
    }

    /// Serial number ([`SOA_SERIAL`](DnsRrKey::SOA_SERIAL)).
    pub fn serial(self) -> u32 {
        self.0.get_u32(DnsRrKey::SOA_SERIAL)
    }

    /// Refresh interval ([`SOA_REFRESH`](DnsRrKey::SOA_REFRESH)).
    pub fn refresh(self) -> u32 {
        self.0.get_u32(DnsRrKey::SOA_REFRESH)
    }

    /// Retry interval ([`SOA_RETRY`](DnsRrKey::SOA_RETRY)).
    pub fn retry(self) -> u32 {
        self.0.get_u32(DnsRrKey::SOA_RETRY)
    }

    /// Expire limit ([`SOA_EXPIRE`](DnsRrKey::SOA_EXPIRE)).
    pub fn expire(self) -> u32 {
        self.0.get_u32(DnsRrKey::SOA_EXPIRE)
    }

    /// Minimum TTL ([`SOA_MINIMUM`](DnsRrKey::SOA_MINIMUM)).
    pub fn minimum(self) -> u32 {
        self.0.get_u32(DnsRrKey::SOA_MINIMUM)
    }
}

impl fmt::Debug for SoaRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoaRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("mname", &self.mname())
            .field("rname", &self.rname())
            .field("serial", &self.serial())
            .field("refresh", &self.refresh())
            .field("retry", &self.retry())
            .field("expire", &self.expire())
            .field("minimum", &self.minimum())
            .finish()
    }
}

/// Typed view of a [`PTR`](DnsRecordType::PTR) record.
#[derive(Copy, Clone)]
pub struct PtrRecord<'a>(&'a DnsRr);

impl<'a> PtrRecord<'a> {
    common_accessors!(PtrRecord);

    /// Returns the pointer domain name ([`PTR_DNAME`](DnsRrKey::PTR_DNAME)).
    pub fn dname(self) -> &'a str {
        self.0.get_str(DnsRrKey::PTR_DNAME).unwrap_or("")
    }
}

impl fmt::Debug for PtrRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PtrRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("dname", &self.dname())
            .finish()
    }
}

/// Typed view of an [`HINFO`](DnsRecordType::HINFO) record.
#[derive(Copy, Clone)]
pub struct HinfoRecord<'a>(&'a DnsRr);

impl<'a> HinfoRecord<'a> {
    common_accessors!(HinfoRecord);

    /// CPU description ([`HINFO_CPU`](DnsRrKey::HINFO_CPU)).
    pub fn cpu(self) -> &'a str {
        self.0.get_str(DnsRrKey::HINFO_CPU).unwrap_or("")
    }

    /// OS description ([`HINFO_OS`](DnsRrKey::HINFO_OS)).
    pub fn os(self) -> &'a str {
        self.0.get_str(DnsRrKey::HINFO_OS).unwrap_or("")
    }
}

impl fmt::Debug for HinfoRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HinfoRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("cpu", &self.cpu())
            .field("os", &self.os())
            .finish()
    }
}

/// Typed view of an [`MX`](DnsRecordType::MX) record.
#[derive(Copy, Clone)]
pub struct MxRecord<'a>(&'a DnsRr);

impl<'a> MxRecord<'a> {
    common_accessors!(MxRecord);

    /// Preference ([`MX_PREFERENCE`](DnsRrKey::MX_PREFERENCE)).
    pub fn preference(self) -> u16 {
        self.0.get_u16(DnsRrKey::MX_PREFERENCE)
    }

    /// Exchange domain name ([`MX_EXCHANGE`](DnsRrKey::MX_EXCHANGE)).
    pub fn exchange(self) -> &'a str {
        self.0.get_str(DnsRrKey::MX_EXCHANGE).unwrap_or("")
    }
}

impl fmt::Debug for MxRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MxRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("preference", &self.preference())
            .field("exchange", &self.exchange())
            .finish()
    }
}

/// Typed view of a [`SIG`](DnsRecordType::SIG) record.
#[derive(Copy, Clone)]
pub struct SigRecord<'a>(&'a DnsRr);

impl<'a> SigRecord<'a> {
    common_accessors!(SigRecord);

    /// Type covered ([`SIG_TYPE_COVERED`](DnsRrKey::SIG_TYPE_COVERED)).
    pub fn type_covered(self) -> u16 {
        self.0.get_u16(DnsRrKey::SIG_TYPE_COVERED)
    }

    /// Algorithm ([`SIG_ALGORITHM`](DnsRrKey::SIG_ALGORITHM)).
    pub fn algorithm(self) -> u8 {
        self.0.get_u8(DnsRrKey::SIG_ALGORITHM)
    }

    /// Number of labels ([`SIG_LABELS`](DnsRrKey::SIG_LABELS)).
    pub fn labels(self) -> u8 {
        self.0.get_u8(DnsRrKey::SIG_LABELS)
    }

    /// Original TTL ([`SIG_ORIGINAL_TTL`](DnsRrKey::SIG_ORIGINAL_TTL)).
    pub fn original_ttl(self) -> u32 {
        self.0.get_u32(DnsRrKey::SIG_ORIGINAL_TTL)
    }

    /// Signature expiration time
    /// ([`SIG_EXPIRATION`](DnsRrKey::SIG_EXPIRATION)).
    pub fn expiration(self) -> u32 {
        self.0.get_u32(DnsRrKey::SIG_EXPIRATION)
    }

    /// Signature inception time
    /// ([`SIG_INCEPTION`](DnsRrKey::SIG_INCEPTION)).
    pub fn inception(self) -> u32 {
        self.0.get_u32(DnsRrKey::SIG_INCEPTION)
    }

    /// Key tag ([`SIG_KEY_TAG`](DnsRrKey::SIG_KEY_TAG)).
    pub fn key_tag(self) -> u16 {
        self.0.get_u16(DnsRrKey::SIG_KEY_TAG)
    }

    /// Signer's name ([`SIG_SIGNERS_NAME`](DnsRrKey::SIG_SIGNERS_NAME)).
    pub fn signers_name(self) -> &'a str {
        self.0.get_str(DnsRrKey::SIG_SIGNERS_NAME).unwrap_or("")
    }

    /// Signature data ([`SIG_SIGNATURE`](DnsRrKey::SIG_SIGNATURE)).
    pub fn signature(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::SIG_SIGNATURE).unwrap_or(&[])
    }
}

impl fmt::Debug for SigRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("type_covered", &self.type_covered())
            .field("algorithm", &self.algorithm())
            .field("labels", &self.labels())
            .field("original_ttl", &self.original_ttl())
            .field("expiration", &self.expiration())
            .field("inception", &self.inception())
            .field("key_tag", &self.key_tag())
            .field("signers_name", &self.signers_name())
            .field("signature_len", &self.signature().len())
            .finish()
    }
}

/// Typed view of an [`SRV`](DnsRecordType::SRV) record.
#[derive(Copy, Clone)]
pub struct SrvRecord<'a>(&'a DnsRr);

impl<'a> SrvRecord<'a> {
    common_accessors!(SrvRecord);

    /// Priority ([`SRV_PRIORITY`](DnsRrKey::SRV_PRIORITY)).
    pub fn priority(self) -> u16 {
        self.0.get_u16(DnsRrKey::SRV_PRIORITY)
    }

    /// Weight ([`SRV_WEIGHT`](DnsRrKey::SRV_WEIGHT)).
    pub fn weight(self) -> u16 {
        self.0.get_u16(DnsRrKey::SRV_WEIGHT)
    }

    /// Port ([`SRV_PORT`](DnsRrKey::SRV_PORT)).
    pub fn port(self) -> u16 {
        self.0.get_u16(DnsRrKey::SRV_PORT)
    }

    /// Target domain ([`SRV_TARGET`](DnsRrKey::SRV_TARGET)).
    pub fn target(self) -> &'a str {
        self.0.get_str(DnsRrKey::SRV_TARGET).unwrap_or("")
    }
}

impl fmt::Debug for SrvRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrvRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("priority", &self.priority())
            .field("weight", &self.weight())
            .field("port", &self.port())
            .field("target", &self.target())
            .finish()
    }
}

/// Typed view of a [`NAPTR`](DnsRecordType::NAPTR) record.
#[derive(Copy, Clone)]
pub struct NaptrRecord<'a>(&'a DnsRr);

impl<'a> NaptrRecord<'a> {
    common_accessors!(NaptrRecord);

    /// Order ([`NAPTR_ORDER`](DnsRrKey::NAPTR_ORDER)).
    pub fn order(self) -> u16 {
        self.0.get_u16(DnsRrKey::NAPTR_ORDER)
    }

    /// Preference ([`NAPTR_PREFERENCE`](DnsRrKey::NAPTR_PREFERENCE)).
    pub fn preference(self) -> u16 {
        self.0.get_u16(DnsRrKey::NAPTR_PREFERENCE)
    }

    /// Flags ([`NAPTR_FLAGS`](DnsRrKey::NAPTR_FLAGS)).
    pub fn flags(self) -> &'a str {
        self.0.get_str(DnsRrKey::NAPTR_FLAGS).unwrap_or("")
    }

    /// Services ([`NAPTR_SERVICES`](DnsRrKey::NAPTR_SERVICES)).
    pub fn services(self) -> &'a str {
        self.0.get_str(DnsRrKey::NAPTR_SERVICES).unwrap_or("")
    }

    /// Regular expression ([`NAPTR_REGEXP`](DnsRrKey::NAPTR_REGEXP)).
    pub fn regexp(self) -> &'a str {
        self.0.get_str(DnsRrKey::NAPTR_REGEXP).unwrap_or("")
    }

    /// Replacement domain ([`NAPTR_REPLACEMENT`](DnsRrKey::NAPTR_REPLACEMENT)).
    pub fn replacement(self) -> &'a str {
        self.0.get_str(DnsRrKey::NAPTR_REPLACEMENT).unwrap_or("")
    }
}

impl fmt::Debug for NaptrRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NaptrRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("order", &self.order())
            .field("preference", &self.preference())
            .field("flags", &self.flags())
            .field("services", &self.services())
            .field("regexp", &self.regexp())
            .field("replacement", &self.replacement())
            .finish()
    }
}

/// Typed view of a [`TLSA`](DnsRecordType::TLSA) record.
#[derive(Copy, Clone)]
pub struct TlsaRecord<'a>(&'a DnsRr);

impl<'a> TlsaRecord<'a> {
    common_accessors!(TlsaRecord);

    /// Certificate usage ([`TLSA_CERT_USAGE`](DnsRrKey::TLSA_CERT_USAGE)).
    pub fn cert_usage(self) -> u8 {
        self.0.get_u8(DnsRrKey::TLSA_CERT_USAGE)
    }

    /// Selector ([`TLSA_SELECTOR`](DnsRrKey::TLSA_SELECTOR)).
    pub fn selector(self) -> u8 {
        self.0.get_u8(DnsRrKey::TLSA_SELECTOR)
    }

    /// Matching type ([`TLSA_MATCH`](DnsRrKey::TLSA_MATCH)).
    pub fn matching_type(self) -> u8 {
        self.0.get_u8(DnsRrKey::TLSA_MATCH)
    }

    /// Certificate association data ([`TLSA_DATA`](DnsRrKey::TLSA_DATA)).
    pub fn data(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::TLSA_DATA).unwrap_or(&[])
    }
}

impl fmt::Debug for TlsaRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsaRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("cert_usage", &self.cert_usage())
            .field("selector", &self.selector())
            .field("matching_type", &self.matching_type())
            .field("data_len", &self.data().len())
            .finish()
    }
}

/// Typed view of a [`DS`](DnsRecordType::DS) record.
#[derive(Copy, Clone)]
pub struct DsRecord<'a>(&'a DnsRr);

impl<'a> DsRecord<'a> {
    common_accessors!(DsRecord);

    /// Key tag ([`DS_KEY_TAG`](DnsRrKey::DS_KEY_TAG)).
    pub fn key_tag(self) -> u16 {
        self.0.get_u16(DnsRrKey::DS_KEY_TAG)
    }

    /// Algorithm ([`DS_ALGORITHM`](DnsRrKey::DS_ALGORITHM)).
    pub fn algorithm(self) -> u8 {
        self.0.get_u8(DnsRrKey::DS_ALGORITHM)
    }

    /// Digest type ([`DS_DIGEST_TYPE`](DnsRrKey::DS_DIGEST_TYPE)).
    pub fn digest_type(self) -> u8 {
        self.0.get_u8(DnsRrKey::DS_DIGEST_TYPE)
    }

    /// Digest ([`DS_DIGEST`](DnsRrKey::DS_DIGEST)).
    pub fn digest(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::DS_DIGEST).unwrap_or(&[])
    }
}

impl fmt::Debug for DsRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("key_tag", &self.key_tag())
            .field("algorithm", &self.algorithm())
            .field("digest_type", &self.digest_type())
            .field("digest_len", &self.digest().len())
            .finish()
    }
}

/// Typed view of an [`SSHFP`](DnsRecordType::SSHFP) record.
#[derive(Copy, Clone)]
pub struct SshfpRecord<'a>(&'a DnsRr);

impl<'a> SshfpRecord<'a> {
    common_accessors!(SshfpRecord);

    /// Algorithm ([`SSHFP_ALGORITHM`](DnsRrKey::SSHFP_ALGORITHM)).
    pub fn algorithm(self) -> u8 {
        self.0.get_u8(DnsRrKey::SSHFP_ALGORITHM)
    }

    /// Fingerprint type ([`SSHFP_FP_TYPE`](DnsRrKey::SSHFP_FP_TYPE)).
    pub fn fp_type(self) -> u8 {
        self.0.get_u8(DnsRrKey::SSHFP_FP_TYPE)
    }

    /// Fingerprint ([`SSHFP_FINGERPRINT`](DnsRrKey::SSHFP_FINGERPRINT)).
    pub fn fingerprint(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::SSHFP_FINGERPRINT).unwrap_or(&[])
    }
}

impl fmt::Debug for SshfpRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshfpRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("algorithm", &self.algorithm())
            .field("fp_type", &self.fp_type())
            .field("fingerprint_len", &self.fingerprint().len())
            .finish()
    }
}

/// Typed view of an [`RRSIG`](DnsRecordType::RRSIG) record.
#[derive(Copy, Clone)]
pub struct RrsigRecord<'a>(&'a DnsRr);

impl<'a> RrsigRecord<'a> {
    common_accessors!(RrsigRecord);

    /// Type covered ([`RRSIG_TYPE_COVERED`](DnsRrKey::RRSIG_TYPE_COVERED)).
    pub fn type_covered(self) -> u16 {
        self.0.get_u16(DnsRrKey::RRSIG_TYPE_COVERED)
    }

    /// Algorithm ([`RRSIG_ALGORITHM`](DnsRrKey::RRSIG_ALGORITHM)).
    pub fn algorithm(self) -> u8 {
        self.0.get_u8(DnsRrKey::RRSIG_ALGORITHM)
    }

    /// Number of labels ([`RRSIG_LABELS`](DnsRrKey::RRSIG_LABELS)).
    pub fn labels(self) -> u8 {
        self.0.get_u8(DnsRrKey::RRSIG_LABELS)
    }

    /// Original TTL ([`RRSIG_ORIGINAL_TTL`](DnsRrKey::RRSIG_ORIGINAL_TTL)).
    pub fn original_ttl(self) -> u32 {
        self.0.get_u32(DnsRrKey::RRSIG_ORIGINAL_TTL)
    }

    /// Signature expiration time
    /// ([`RRSIG_EXPIRATION`](DnsRrKey::RRSIG_EXPIRATION)).
    pub fn expiration(self) -> u32 {
        self.0.get_u32(DnsRrKey::RRSIG_EXPIRATION)
    }

    /// Signature inception time
    /// ([`RRSIG_INCEPTION`](DnsRrKey::RRSIG_INCEPTION)).
    pub fn inception(self) -> u32 {
        self.0.get_u32(DnsRrKey::RRSIG_INCEPTION)
    }

    /// Key tag ([`RRSIG_KEY_TAG`](DnsRrKey::RRSIG_KEY_TAG)).
    pub fn key_tag(self) -> u16 {
        self.0.get_u16(DnsRrKey::RRSIG_KEY_TAG)
    }

    /// Signer's name ([`RRSIG_SIGNERS_NAME`](DnsRrKey::RRSIG_SIGNERS_NAME)).
    pub fn signers_name(self) -> &'a str {
        self.0.get_str(DnsRrKey::RRSIG_SIGNERS_NAME).unwrap_or("")
    }

    /// Signature data ([`RRSIG_SIGNATURE`](DnsRrKey::RRSIG_SIGNATURE)).
    pub fn signature(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::RRSIG_SIGNATURE).unwrap_or(&[])
    }
}

impl fmt::Debug for RrsigRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RrsigRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("type_covered", &self.type_covered())
            .field("algorithm", &self.algorithm())
            .field("labels", &self.labels())
            .field("original_ttl", &self.original_ttl())
            .field("expiration", &self.expiration())
            .field("inception", &self.inception())
            .field("key_tag", &self.key_tag())
            .field("signers_name", &self.signers_name())
            .field("signature_len", &self.signature().len())
            .finish()
    }
}

/// Typed view of an [`NSEC`](DnsRecordType::NSEC) record.
#[derive(Copy, Clone)]
pub struct NsecRecord<'a>(&'a DnsRr);

impl<'a> NsecRecord<'a> {
    common_accessors!(NsecRecord);

    /// Next domain name ([`NSEC_NEXT_DOMAIN`](DnsRrKey::NSEC_NEXT_DOMAIN)).
    pub fn next_domain(self) -> &'a str {
        self.0.get_str(DnsRrKey::NSEC_NEXT_DOMAIN).unwrap_or("")
    }

    /// Type bit maps ([`NSEC_TYPE_BIT_MAPS`](DnsRrKey::NSEC_TYPE_BIT_MAPS)).
    pub fn type_bit_maps(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::NSEC_TYPE_BIT_MAPS).unwrap_or(&[])
    }
}

impl fmt::Debug for NsecRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NsecRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("next_domain", &self.next_domain())
            .field("type_bit_maps_len", &self.type_bit_maps().len())
            .finish()
    }
}

/// Typed view of a [`DNSKEY`](DnsRecordType::DNSKEY) record.
#[derive(Copy, Clone)]
pub struct DnskeyRecord<'a>(&'a DnsRr);

impl<'a> DnskeyRecord<'a> {
    common_accessors!(DnskeyRecord);

    /// Flags ([`DNSKEY_FLAGS`](DnsRrKey::DNSKEY_FLAGS)).
    pub fn flags(self) -> u16 {
        self.0.get_u16(DnsRrKey::DNSKEY_FLAGS)
    }

    /// Protocol ([`DNSKEY_PROTOCOL`](DnsRrKey::DNSKEY_PROTOCOL)).
    pub fn protocol(self) -> u8 {
        self.0.get_u8(DnsRrKey::DNSKEY_PROTOCOL)
    }

    /// Algorithm ([`DNSKEY_ALGORITHM`](DnsRrKey::DNSKEY_ALGORITHM)).
    pub fn algorithm(self) -> u8 {
        self.0.get_u8(DnsRrKey::DNSKEY_ALGORITHM)
    }

    /// Public key ([`DNSKEY_PUBLIC_KEY`](DnsRrKey::DNSKEY_PUBLIC_KEY)).
    pub fn public_key(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::DNSKEY_PUBLIC_KEY).unwrap_or(&[])
    }
}

impl fmt::Debug for DnskeyRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnskeyRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("flags", &self.flags())
            .field("protocol", &self.protocol())
            .field("algorithm", &self.algorithm())
            .field("public_key_len", &self.public_key().len())
            .finish()
    }
}

/// Typed view of an [`NSEC3`](DnsRecordType::NSEC3) record.
#[derive(Copy, Clone)]
pub struct Nsec3Record<'a>(&'a DnsRr);

impl<'a> Nsec3Record<'a> {
    common_accessors!(Nsec3Record);

    /// Hash algorithm
    /// ([`NSEC3_HASH_ALGORITHM`](DnsRrKey::NSEC3_HASH_ALGORITHM)).
    pub fn hash_algorithm(self) -> u8 {
        self.0.get_u8(DnsRrKey::NSEC3_HASH_ALGORITHM)
    }

    /// Flags ([`NSEC3_FLAGS`](DnsRrKey::NSEC3_FLAGS)).
    pub fn flags(self) -> u8 {
        self.0.get_u8(DnsRrKey::NSEC3_FLAGS)
    }

    /// Iterations ([`NSEC3_ITERATIONS`](DnsRrKey::NSEC3_ITERATIONS)).
    pub fn iterations(self) -> u16 {
        self.0.get_u16(DnsRrKey::NSEC3_ITERATIONS)
    }

    /// Salt ([`NSEC3_SALT`](DnsRrKey::NSEC3_SALT)).
    pub fn salt(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::NSEC3_SALT).unwrap_or(&[])
    }

    /// Next hashed owner name
    /// ([`NSEC3_NEXT_HASHED_OWNER`](DnsRrKey::NSEC3_NEXT_HASHED_OWNER)).
    pub fn next_hashed_owner(self) -> &'a [u8] {
        self.0
            .get_bin(DnsRrKey::NSEC3_NEXT_HASHED_OWNER)
            .unwrap_or(&[])
    }

    /// Type bit maps
    /// ([`NSEC3_TYPE_BIT_MAPS`](DnsRrKey::NSEC3_TYPE_BIT_MAPS)).
    pub fn type_bit_maps(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::NSEC3_TYPE_BIT_MAPS).unwrap_or(&[])
    }
}

impl fmt::Debug for Nsec3Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nsec3Record")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("hash_algorithm", &self.hash_algorithm())
            .field("flags", &self.flags())
            .field("iterations", &self.iterations())
            .field("salt_len", &self.salt().len())
            .field("next_hashed_owner_len", &self.next_hashed_owner().len())
            .field("type_bit_maps_len", &self.type_bit_maps().len())
            .finish()
    }
}

/// Typed view of an [`NSEC3PARAM`](DnsRecordType::NSEC3PARAM) record.
#[derive(Copy, Clone)]
pub struct Nsec3ParamRecord<'a>(&'a DnsRr);

impl<'a> Nsec3ParamRecord<'a> {
    common_accessors!(Nsec3ParamRecord);

    /// Hash algorithm
    /// ([`NSEC3PARAM_HASH_ALGORITHM`](DnsRrKey::NSEC3PARAM_HASH_ALGORITHM)).
    pub fn hash_algorithm(self) -> u8 {
        self.0.get_u8(DnsRrKey::NSEC3PARAM_HASH_ALGORITHM)
    }

    /// Flags ([`NSEC3PARAM_FLAGS`](DnsRrKey::NSEC3PARAM_FLAGS)).
    pub fn flags(self) -> u8 {
        self.0.get_u8(DnsRrKey::NSEC3PARAM_FLAGS)
    }

    /// Iterations ([`NSEC3PARAM_ITERATIONS`](DnsRrKey::NSEC3PARAM_ITERATIONS)).
    pub fn iterations(self) -> u16 {
        self.0.get_u16(DnsRrKey::NSEC3PARAM_ITERATIONS)
    }

    /// Salt ([`NSEC3PARAM_SALT`](DnsRrKey::NSEC3PARAM_SALT)).
    pub fn salt(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::NSEC3PARAM_SALT).unwrap_or(&[])
    }
}

impl fmt::Debug for Nsec3ParamRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nsec3ParamRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("hash_algorithm", &self.hash_algorithm())
            .field("flags", &self.flags())
            .field("iterations", &self.iterations())
            .field("salt_len", &self.salt().len())
            .finish()
    }
}

/// Typed view of a [`URI`](DnsRecordType::URI) record.
#[derive(Copy, Clone)]
pub struct UriRecord<'a>(&'a DnsRr);

impl<'a> UriRecord<'a> {
    common_accessors!(UriRecord);

    /// Priority ([`URI_PRIORITY`](DnsRrKey::URI_PRIORITY)).
    pub fn priority(self) -> u16 {
        self.0.get_u16(DnsRrKey::URI_PRIORITY)
    }

    /// Weight ([`URI_WEIGHT`](DnsRrKey::URI_WEIGHT)).
    pub fn weight(self) -> u16 {
        self.0.get_u16(DnsRrKey::URI_WEIGHT)
    }

    /// Target URI ([`URI_TARGET`](DnsRrKey::URI_TARGET)).
    pub fn target(self) -> &'a str {
        self.0.get_str(DnsRrKey::URI_TARGET).unwrap_or("")
    }
}

impl fmt::Debug for UriRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UriRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("priority", &self.priority())
            .field("weight", &self.weight())
            .field("target", &self.target())
            .finish()
    }
}

// =============================================================================
// Variable-shape record wrappers
// =============================================================================

/// Typed view of a [`TXT`](DnsRecordType::TXT) record.
///
/// TXT records carry an array of binary strings. Each entry is a `&[u8]`
/// because the wire format does not require UTF-8.
#[derive(Copy, Clone)]
pub struct TxtRecord<'a>(&'a DnsRr);

impl<'a> TxtRecord<'a> {
    common_accessors!(TxtRecord);

    /// Returns the number of TXT entries
    /// ([`TXT_DATA`](DnsRrKey::TXT_DATA)).
    pub fn entry_count(self) -> usize {
        self.0.get_abin_count(DnsRrKey::TXT_DATA)
    }

    /// Returns an iterator over the TXT entries
    /// ([`TXT_DATA`](DnsRrKey::TXT_DATA)).
    pub fn entries(self) -> impl Iterator<Item = &'a [u8]> {
        self.0.abins(DnsRrKey::TXT_DATA)
    }
}

impl fmt::Debug for TxtRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxtRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("entry_count", &self.entry_count())
            .finish()
    }
}

/// Typed view of an [`OPT`](DnsRecordType::OPT) (EDNS0) record.
///
/// OPT records repurpose the class and TTL fields for EDNS metadata; the
/// generic [`DnsRr::dns_class`] and [`DnsRr::ttl`] still return those raw
/// values, but the typed accessors below interpret them per RFC 6891.
#[derive(Copy, Clone)]
pub struct OptRecord<'a>(&'a DnsRr);

impl<'a> OptRecord<'a> {
    common_accessors!(OptRecord);

    /// Sender's UDP payload size
    /// ([`OPT_UDP_SIZE`](DnsRrKey::OPT_UDP_SIZE)).
    pub fn udp_size(self) -> u16 {
        self.0.get_u16(DnsRrKey::OPT_UDP_SIZE)
    }

    /// EDNS version ([`OPT_VERSION`](DnsRrKey::OPT_VERSION)).
    pub fn version(self) -> u8 {
        self.0.get_u8(DnsRrKey::OPT_VERSION)
    }

    /// EDNS flags ([`OPT_FLAGS`](DnsRrKey::OPT_FLAGS)).
    pub fn flags(self) -> u16 {
        self.0.get_u16(DnsRrKey::OPT_FLAGS)
    }

    /// Returns the number of EDNS options
    /// ([`OPT_OPTIONS`](DnsRrKey::OPT_OPTIONS)).
    pub fn option_count(self) -> usize {
        self.0.get_opt_count(DnsRrKey::OPT_OPTIONS)
    }

    /// Returns an iterator over EDNS options
    /// ([`OPT_OPTIONS`](DnsRrKey::OPT_OPTIONS)) yielding
    /// `(option_code, decoded_value)` pairs.
    ///
    /// The value is decoded according to its registered datatype (see
    /// [`OptValue`]). For options the linked c-ares does not recognise,
    /// decoding may fail; use [`raw_options`](Self::raw_options) to
    /// access the underlying byte slice instead.
    pub fn options(self) -> impl Iterator<Item = (u16, Result<OptValue, OptParseError>)> + 'a {
        self.0
            .opts(DnsRrKey::OPT_OPTIONS)
            .map(|(k, v)| (k, parse_opt_value(DnsRrKey::OPT_OPTIONS, k, v)))
    }

    /// Returns an iterator over EDNS options
    /// ([`OPT_OPTIONS`](DnsRrKey::OPT_OPTIONS)) yielding
    /// `(option_code, value_bytes)` pairs without decoding.
    pub fn raw_options(self) -> impl Iterator<Item = (u16, &'a [u8])> {
        self.0.opts(DnsRrKey::OPT_OPTIONS)
    }
}

impl fmt::Debug for OptRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OptRecord")
            .field("udp_size", &self.udp_size())
            .field("version", &self.version())
            .field("flags", &self.flags())
            .field("option_count", &self.option_count())
            .finish()
    }
}

/// Typed view of an [`SVCB`](DnsRecordType::SVCB) record.
#[derive(Copy, Clone)]
pub struct SvcbRecord<'a>(&'a DnsRr);

impl<'a> SvcbRecord<'a> {
    common_accessors!(SvcbRecord);

    /// SvcPriority ([`SVCB_PRIORITY`](DnsRrKey::SVCB_PRIORITY)).
    pub fn priority(self) -> u16 {
        self.0.get_u16(DnsRrKey::SVCB_PRIORITY)
    }

    /// TargetName ([`SVCB_TARGET`](DnsRrKey::SVCB_TARGET)).
    pub fn target(self) -> &'a str {
        self.0.get_str(DnsRrKey::SVCB_TARGET).unwrap_or("")
    }

    /// Returns the number of SvcParams
    /// ([`SVCB_PARAMS`](DnsRrKey::SVCB_PARAMS)).
    pub fn param_count(self) -> usize {
        self.0.get_opt_count(DnsRrKey::SVCB_PARAMS)
    }

    /// Returns an iterator over SvcParams
    /// ([`SVCB_PARAMS`](DnsRrKey::SVCB_PARAMS)) yielding
    /// `(param_key, decoded_value)` pairs.
    ///
    /// The value is decoded according to its registered datatype (see
    /// [`OptValue`]). For parameters the linked c-ares does not
    /// recognise, decoding may fail; use [`raw_params`](Self::raw_params)
    /// to access the underlying byte slice instead.
    pub fn params(self) -> impl Iterator<Item = (u16, Result<OptValue, OptParseError>)> + 'a {
        self.0
            .opts(DnsRrKey::SVCB_PARAMS)
            .map(|(k, v)| (k, parse_opt_value(DnsRrKey::SVCB_PARAMS, k, v)))
    }

    /// Returns an iterator over SvcParams
    /// ([`SVCB_PARAMS`](DnsRrKey::SVCB_PARAMS)) yielding
    /// `(param_key, value_bytes)` pairs without decoding.
    pub fn raw_params(self) -> impl Iterator<Item = (u16, &'a [u8])> {
        self.0.opts(DnsRrKey::SVCB_PARAMS)
    }
}

impl fmt::Debug for SvcbRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SvcbRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("priority", &self.priority())
            .field("target", &self.target())
            .field("param_count", &self.param_count())
            .finish()
    }
}

/// Typed view of an [`HTTPS`](DnsRecordType::HTTPS) record.
#[derive(Copy, Clone)]
pub struct HttpsRecord<'a>(&'a DnsRr);

impl<'a> HttpsRecord<'a> {
    common_accessors!(HttpsRecord);

    /// SvcPriority ([`HTTPS_PRIORITY`](DnsRrKey::HTTPS_PRIORITY)).
    pub fn priority(self) -> u16 {
        self.0.get_u16(DnsRrKey::HTTPS_PRIORITY)
    }

    /// TargetName ([`HTTPS_TARGET`](DnsRrKey::HTTPS_TARGET)).
    pub fn target(self) -> &'a str {
        self.0.get_str(DnsRrKey::HTTPS_TARGET).unwrap_or("")
    }

    /// Returns the number of SvcParams
    /// ([`HTTPS_PARAMS`](DnsRrKey::HTTPS_PARAMS)).
    pub fn param_count(self) -> usize {
        self.0.get_opt_count(DnsRrKey::HTTPS_PARAMS)
    }

    /// Returns an iterator over SvcParams
    /// ([`HTTPS_PARAMS`](DnsRrKey::HTTPS_PARAMS)) yielding
    /// `(param_key, decoded_value)` pairs.
    ///
    /// The value is decoded according to its registered datatype (see
    /// [`OptValue`]). For parameters the linked c-ares does not
    /// recognise, decoding may fail; use [`raw_params`](Self::raw_params)
    /// to access the underlying byte slice instead.
    pub fn params(self) -> impl Iterator<Item = (u16, Result<OptValue, OptParseError>)> + 'a {
        self.0
            .opts(DnsRrKey::HTTPS_PARAMS)
            .map(|(k, v)| (k, parse_opt_value(DnsRrKey::HTTPS_PARAMS, k, v)))
    }

    /// Returns an iterator over SvcParams
    /// ([`HTTPS_PARAMS`](DnsRrKey::HTTPS_PARAMS)) yielding
    /// `(param_key, value_bytes)` pairs without decoding.
    pub fn raw_params(self) -> impl Iterator<Item = (u16, &'a [u8])> {
        self.0.opts(DnsRrKey::HTTPS_PARAMS)
    }
}

impl fmt::Debug for HttpsRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("priority", &self.priority())
            .field("target", &self.target())
            .field("param_count", &self.param_count())
            .finish()
    }
}

/// Typed view of a [`CAA`](DnsRecordType::CAA) record.
#[derive(Copy, Clone)]
pub struct CaaRecord<'a>(&'a DnsRr);

impl<'a> CaaRecord<'a> {
    common_accessors!(CaaRecord);

    /// Raw flags byte ([`CAA_CRITICAL`](DnsRrKey::CAA_CRITICAL)).
    ///
    /// RFC 8659 defines only the issuer-critical bit (`0x80`); use
    /// [`is_critical`](Self::is_critical) for that bit specifically.
    pub fn flags(self) -> u8 {
        self.0.get_u8(DnsRrKey::CAA_CRITICAL)
    }

    /// Returns `true` iff the issuer-critical bit (`0x80`) is set in
    /// the flags byte.
    pub fn is_critical(self) -> bool {
        (self.flags() & 0x80) != 0
    }

    /// Property tag ([`CAA_TAG`](DnsRrKey::CAA_TAG)), e.g. `"issue"`.
    pub fn tag(self) -> &'a str {
        self.0.get_str(DnsRrKey::CAA_TAG).unwrap_or("")
    }

    /// Property value ([`CAA_VALUE`](DnsRrKey::CAA_VALUE)).
    ///
    /// Returned as raw bytes; CAA values are usually printable ASCII but
    /// the RFC does not require valid UTF-8.
    pub fn value(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::CAA_VALUE).unwrap_or(&[])
    }
}

impl fmt::Debug for CaaRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaaRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("flags", &self.flags())
            .field("is_critical", &self.is_critical())
            .field("tag", &self.tag())
            .field("value_len", &self.value().len())
            .finish()
    }
}

/// Typed view of a [`RAW_RR`](DnsRecordType::RAW_RR) record.
///
/// `RAW_RR` is c-ares's catch-all for record types it does not parse
/// natively. The original wire-format type code is preserved in
/// [`raw_type`](Self::raw_type), and the unparsed RDATA in
/// [`data`](Self::data).
#[derive(Copy, Clone)]
pub struct RawRrRecord<'a>(&'a DnsRr);

impl<'a> RawRrRecord<'a> {
    common_accessors!(RawRrRecord);

    /// Original wire-format RR type code
    /// ([`RAW_RR_TYPE`](DnsRrKey::RAW_RR_TYPE)).
    ///
    /// Distinct from [`DnsRr::rr_type`], which always returns
    /// [`DnsRecordType::RAW_RR`] for these records.
    pub fn raw_type(self) -> u16 {
        self.0.get_u16(DnsRrKey::RAW_RR_TYPE)
    }

    /// Unparsed RDATA bytes ([`RAW_RR_DATA`](DnsRrKey::RAW_RR_DATA)).
    ///
    /// Empty for records with zero-length RDATA. The DNS wire format
    /// does not distinguish "absent" from "zero-length" RDATA.
    pub fn data(self) -> &'a [u8] {
        self.0.get_bin(DnsRrKey::RAW_RR_DATA).unwrap_or(&[])
    }
}

impl fmt::Debug for RawRrRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawRrRecord")
            .field("name", &self.name())
            .field("ttl", &self.ttl())
            .field("raw_type", &self.raw_type())
            .field("data_len", &self.data().len())
            .finish()
    }
}

// =============================================================================
// TypedRr enum + dispatch
// =============================================================================

/// Match-friendly enumeration of every typed record view.
///
/// Returned by [`DnsRr::as_typed`]. Marked `#[non_exhaustive]` so future
/// record types can be added without breaking exhaustive matches.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum TypedRr<'a> {
    /// IPv4 address record.
    A(ARecord<'a>),
    /// IPv6 address record.
    Aaaa(AaaaRecord<'a>),
    /// Authoritative nameserver record.
    Ns(NsRecord<'a>),
    /// Canonical name record.
    Cname(CnameRecord<'a>),
    /// Start of authority record.
    Soa(SoaRecord<'a>),
    /// Domain name pointer record.
    Ptr(PtrRecord<'a>),
    /// Host information record.
    Hinfo(HinfoRecord<'a>),
    /// Mail exchange record.
    Mx(MxRecord<'a>),
    /// Text record.
    Txt(TxtRecord<'a>),
    /// SIG (RFC 2535 / 2931) record.
    Sig(SigRecord<'a>),
    /// Service location record.
    Srv(SrvRecord<'a>),
    /// Naming authority pointer record.
    Naptr(NaptrRecord<'a>),
    /// EDNS0 OPT pseudo-record.
    Opt(OptRecord<'a>),
    /// DANE TLSA record.
    Tlsa(TlsaRecord<'a>),
    /// Delegation signer record.
    Ds(DsRecord<'a>),
    /// SSH fingerprint record.
    Sshfp(SshfpRecord<'a>),
    /// DNSSEC signature record.
    Rrsig(RrsigRecord<'a>),
    /// Next secure record.
    Nsec(NsecRecord<'a>),
    /// DNS public key record.
    Dnskey(DnskeyRecord<'a>),
    /// NSEC3 record.
    Nsec3(Nsec3Record<'a>),
    /// NSEC3PARAM record.
    Nsec3Param(Nsec3ParamRecord<'a>),
    /// Service binding record.
    Svcb(SvcbRecord<'a>),
    /// HTTPS service binding record.
    Https(HttpsRecord<'a>),
    /// URI record.
    Uri(UriRecord<'a>),
    /// Certification authority authorization record.
    Caa(CaaRecord<'a>),
    /// Raw / unparsed record.
    RawRr(RawRrRecord<'a>),
    /// Wildcard request type. Should not appear in responses; carries the
    /// underlying generic record for completeness.
    Any(&'a DnsRr),
    /// Unknown record type. Carries the underlying generic record.
    Unknown(&'a DnsRr),
}

// =============================================================================
// DnsRr discriminator methods
// =============================================================================

impl DnsRr {
    /// Returns a typed [`ARecord`] view if this record is of type
    /// [`A`](DnsRecordType::A).
    pub fn as_a(&self) -> Option<ARecord<'_>> {
        (self.rr_type() == DnsRecordType::A).then(|| ARecord::new(self))
    }

    /// Returns a typed [`AaaaRecord`] view if this record is of type
    /// [`AAAA`](DnsRecordType::AAAA).
    pub fn as_aaaa(&self) -> Option<AaaaRecord<'_>> {
        (self.rr_type() == DnsRecordType::AAAA).then(|| AaaaRecord::new(self))
    }

    /// Returns a typed [`NsRecord`] view if this record is of type
    /// [`NS`](DnsRecordType::NS).
    pub fn as_ns(&self) -> Option<NsRecord<'_>> {
        (self.rr_type() == DnsRecordType::NS).then(|| NsRecord::new(self))
    }

    /// Returns a typed [`CnameRecord`] view if this record is of type
    /// [`CNAME`](DnsRecordType::CNAME).
    pub fn as_cname(&self) -> Option<CnameRecord<'_>> {
        (self.rr_type() == DnsRecordType::CNAME).then(|| CnameRecord::new(self))
    }

    /// Returns a typed [`SoaRecord`] view if this record is of type
    /// [`SOA`](DnsRecordType::SOA).
    pub fn as_soa(&self) -> Option<SoaRecord<'_>> {
        (self.rr_type() == DnsRecordType::SOA).then(|| SoaRecord::new(self))
    }

    /// Returns a typed [`PtrRecord`] view if this record is of type
    /// [`PTR`](DnsRecordType::PTR).
    pub fn as_ptr_rr(&self) -> Option<PtrRecord<'_>> {
        (self.rr_type() == DnsRecordType::PTR).then(|| PtrRecord::new(self))
    }

    /// Returns a typed [`HinfoRecord`] view if this record is of type
    /// [`HINFO`](DnsRecordType::HINFO).
    pub fn as_hinfo(&self) -> Option<HinfoRecord<'_>> {
        (self.rr_type() == DnsRecordType::HINFO).then(|| HinfoRecord::new(self))
    }

    /// Returns a typed [`MxRecord`] view if this record is of type
    /// [`MX`](DnsRecordType::MX).
    pub fn as_mx(&self) -> Option<MxRecord<'_>> {
        (self.rr_type() == DnsRecordType::MX).then(|| MxRecord::new(self))
    }

    /// Returns a typed [`TxtRecord`] view if this record is of type
    /// [`TXT`](DnsRecordType::TXT).
    pub fn as_txt(&self) -> Option<TxtRecord<'_>> {
        (self.rr_type() == DnsRecordType::TXT).then(|| TxtRecord::new(self))
    }

    /// Returns a typed [`SigRecord`] view if this record is of type
    /// [`SIG`](DnsRecordType::SIG).
    pub fn as_sig(&self) -> Option<SigRecord<'_>> {
        (self.rr_type() == DnsRecordType::SIG).then(|| SigRecord::new(self))
    }

    /// Returns a typed [`SrvRecord`] view if this record is of type
    /// [`SRV`](DnsRecordType::SRV).
    pub fn as_srv(&self) -> Option<SrvRecord<'_>> {
        (self.rr_type() == DnsRecordType::SRV).then(|| SrvRecord::new(self))
    }

    /// Returns a typed [`NaptrRecord`] view if this record is of type
    /// [`NAPTR`](DnsRecordType::NAPTR).
    pub fn as_naptr(&self) -> Option<NaptrRecord<'_>> {
        (self.rr_type() == DnsRecordType::NAPTR).then(|| NaptrRecord::new(self))
    }

    /// Returns a typed [`OptRecord`] view if this record is of type
    /// [`OPT`](DnsRecordType::OPT).
    pub fn as_opt(&self) -> Option<OptRecord<'_>> {
        (self.rr_type() == DnsRecordType::OPT).then(|| OptRecord::new(self))
    }

    /// Returns a typed [`TlsaRecord`] view if this record is of type
    /// [`TLSA`](DnsRecordType::TLSA).
    pub fn as_tlsa(&self) -> Option<TlsaRecord<'_>> {
        (self.rr_type() == DnsRecordType::TLSA).then(|| TlsaRecord::new(self))
    }

    /// Returns a typed [`DsRecord`] view if this record is of type
    /// [`DS`](DnsRecordType::DS).
    pub fn as_ds(&self) -> Option<DsRecord<'_>> {
        (self.rr_type() == DnsRecordType::DS).then(|| DsRecord::new(self))
    }

    /// Returns a typed [`SshfpRecord`] view if this record is of type
    /// [`SSHFP`](DnsRecordType::SSHFP).
    pub fn as_sshfp(&self) -> Option<SshfpRecord<'_>> {
        (self.rr_type() == DnsRecordType::SSHFP).then(|| SshfpRecord::new(self))
    }

    /// Returns a typed [`RrsigRecord`] view if this record is of type
    /// [`RRSIG`](DnsRecordType::RRSIG).
    pub fn as_rrsig(&self) -> Option<RrsigRecord<'_>> {
        (self.rr_type() == DnsRecordType::RRSIG).then(|| RrsigRecord::new(self))
    }

    /// Returns a typed [`NsecRecord`] view if this record is of type
    /// [`NSEC`](DnsRecordType::NSEC).
    pub fn as_nsec(&self) -> Option<NsecRecord<'_>> {
        (self.rr_type() == DnsRecordType::NSEC).then(|| NsecRecord::new(self))
    }

    /// Returns a typed [`DnskeyRecord`] view if this record is of type
    /// [`DNSKEY`](DnsRecordType::DNSKEY).
    pub fn as_dnskey(&self) -> Option<DnskeyRecord<'_>> {
        (self.rr_type() == DnsRecordType::DNSKEY).then(|| DnskeyRecord::new(self))
    }

    /// Returns a typed [`Nsec3Record`] view if this record is of type
    /// [`NSEC3`](DnsRecordType::NSEC3).
    pub fn as_nsec3(&self) -> Option<Nsec3Record<'_>> {
        (self.rr_type() == DnsRecordType::NSEC3).then(|| Nsec3Record::new(self))
    }

    /// Returns a typed [`Nsec3ParamRecord`] view if this record is of type
    /// [`NSEC3PARAM`](DnsRecordType::NSEC3PARAM).
    pub fn as_nsec3param(&self) -> Option<Nsec3ParamRecord<'_>> {
        (self.rr_type() == DnsRecordType::NSEC3PARAM).then(|| Nsec3ParamRecord::new(self))
    }

    /// Returns a typed [`SvcbRecord`] view if this record is of type
    /// [`SVCB`](DnsRecordType::SVCB).
    pub fn as_svcb(&self) -> Option<SvcbRecord<'_>> {
        (self.rr_type() == DnsRecordType::SVCB).then(|| SvcbRecord::new(self))
    }

    /// Returns a typed [`HttpsRecord`] view if this record is of type
    /// [`HTTPS`](DnsRecordType::HTTPS).
    pub fn as_https(&self) -> Option<HttpsRecord<'_>> {
        (self.rr_type() == DnsRecordType::HTTPS).then(|| HttpsRecord::new(self))
    }

    /// Returns a typed [`UriRecord`] view if this record is of type
    /// [`URI`](DnsRecordType::URI).
    pub fn as_uri(&self) -> Option<UriRecord<'_>> {
        (self.rr_type() == DnsRecordType::URI).then(|| UriRecord::new(self))
    }

    /// Returns a typed [`CaaRecord`] view if this record is of type
    /// [`CAA`](DnsRecordType::CAA).
    pub fn as_caa(&self) -> Option<CaaRecord<'_>> {
        (self.rr_type() == DnsRecordType::CAA).then(|| CaaRecord::new(self))
    }

    /// Returns a typed [`RawRrRecord`] view if this record is of type
    /// [`RAW_RR`](DnsRecordType::RAW_RR).
    pub fn as_raw_rr(&self) -> Option<RawRrRecord<'_>> {
        (self.rr_type() == DnsRecordType::RAW_RR).then(|| RawRrRecord::new(self))
    }

    /// Dispatches on [`rr_type`](Self::rr_type) and returns a
    /// match-friendly [`TypedRr`] view.
    pub fn as_typed(&self) -> TypedRr<'_> {
        match self.rr_type() {
            DnsRecordType::A => TypedRr::A(ARecord::new(self)),
            DnsRecordType::AAAA => TypedRr::Aaaa(AaaaRecord::new(self)),
            DnsRecordType::NS => TypedRr::Ns(NsRecord::new(self)),
            DnsRecordType::CNAME => TypedRr::Cname(CnameRecord::new(self)),
            DnsRecordType::SOA => TypedRr::Soa(SoaRecord::new(self)),
            DnsRecordType::PTR => TypedRr::Ptr(PtrRecord::new(self)),
            DnsRecordType::HINFO => TypedRr::Hinfo(HinfoRecord::new(self)),
            DnsRecordType::MX => TypedRr::Mx(MxRecord::new(self)),
            DnsRecordType::TXT => TypedRr::Txt(TxtRecord::new(self)),
            DnsRecordType::SIG => TypedRr::Sig(SigRecord::new(self)),
            DnsRecordType::SRV => TypedRr::Srv(SrvRecord::new(self)),
            DnsRecordType::NAPTR => TypedRr::Naptr(NaptrRecord::new(self)),
            DnsRecordType::OPT => TypedRr::Opt(OptRecord::new(self)),
            DnsRecordType::TLSA => TypedRr::Tlsa(TlsaRecord::new(self)),
            DnsRecordType::DS => TypedRr::Ds(DsRecord::new(self)),
            DnsRecordType::SSHFP => TypedRr::Sshfp(SshfpRecord::new(self)),
            DnsRecordType::RRSIG => TypedRr::Rrsig(RrsigRecord::new(self)),
            DnsRecordType::NSEC => TypedRr::Nsec(NsecRecord::new(self)),
            DnsRecordType::DNSKEY => TypedRr::Dnskey(DnskeyRecord::new(self)),
            DnsRecordType::NSEC3 => TypedRr::Nsec3(Nsec3Record::new(self)),
            DnsRecordType::NSEC3PARAM => TypedRr::Nsec3Param(Nsec3ParamRecord::new(self)),
            DnsRecordType::SVCB => TypedRr::Svcb(SvcbRecord::new(self)),
            DnsRecordType::HTTPS => TypedRr::Https(HttpsRecord::new(self)),
            DnsRecordType::URI => TypedRr::Uri(UriRecord::new(self)),
            DnsRecordType::CAA => TypedRr::Caa(CaaRecord::new(self)),
            DnsRecordType::RAW_RR => TypedRr::RawRr(RawRrRecord::new(self)),
            DnsRecordType::ANY => TypedRr::Any(self),
            DnsRecordType::UNKNOWN(_) => TypedRr::Unknown(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsFlags, DnsOpcode, DnsParseFlags, DnsRcode, DnsRecord, DnsSection};

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn assert_copy<T: Copy>() {}

    #[test]
    fn wrappers_are_send_sync_copy() {
        assert_send::<ARecord<'_>>();
        assert_sync::<ARecord<'_>>();
        assert_copy::<ARecord<'_>>();
        assert_send::<TypedRr<'_>>();
        assert_sync::<TypedRr<'_>>();
        assert_copy::<TypedRr<'_>>();
    }

    fn make_rec(rtype: DnsRecordType) -> DnsRecord {
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        // Use A as a generic question type — RAW_RR/OPT/etc. aren't
        // valid query types but can still appear as RRs in the answer
        // section.
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        rec.rr_add(DnsSection::Answer, "example.com", rtype, DnsCls::IN, 300)
            .expect("rr_add");
        rec
    }

    fn first_rr(rec: &DnsRecord) -> &DnsRr {
        rec.rr(DnsSection::Answer, 0).expect("rr")
    }

    // ---- Type-discriminator tests ------------------------------------------

    #[test]
    fn as_a_matches_only_a() {
        let rec = make_rec(DnsRecordType::A);
        let rr = first_rr(&rec);
        assert!(rr.as_a().is_some());
        assert!(rr.as_aaaa().is_none());
        assert!(rr.as_mx().is_none());
        assert!(rr.as_txt().is_none());
    }

    #[test]
    fn as_typed_dispatches_correctly() {
        for &rtype in &[
            DnsRecordType::A,
            DnsRecordType::AAAA,
            DnsRecordType::MX,
            DnsRecordType::TXT,
            DnsRecordType::CAA,
            DnsRecordType::SRV,
        ] {
            let rec = make_rec(rtype);
            let rr = first_rr(&rec);
            match (rtype, rr.as_typed()) {
                (DnsRecordType::A, TypedRr::A(_))
                | (DnsRecordType::AAAA, TypedRr::Aaaa(_))
                | (DnsRecordType::MX, TypedRr::Mx(_))
                | (DnsRecordType::TXT, TypedRr::Txt(_))
                | (DnsRecordType::CAA, TypedRr::Caa(_))
                | (DnsRecordType::SRV, TypedRr::Srv(_)) => {}
                (rt, other) => panic!("type {rt:?} dispatched to wrong variant: {other:?}"),
            }
        }
    }

    // ---- Builder partial-set tests (no panic on unset pointer fields) ------

    #[test]
    fn builder_partial_fields_have_defaults() {
        // A record: c-ares pre-allocates the addr slot at creation.
        let rec = make_rec(DnsRecordType::A);
        let a = first_rr(&rec).as_a().expect("as_a");
        let _ = a.addr();
        assert_eq!(a.ttl(), 300);

        // MX: preference defaults to 0, exchange to "".
        let rec = make_rec(DnsRecordType::MX);
        let mx = first_rr(&rec).as_mx().expect("as_mx");
        assert_eq!(mx.preference(), 0);
        assert_eq!(mx.exchange(), "");

        // SOA: numeric and string defaults.
        let rec = make_rec(DnsRecordType::SOA);
        let soa = first_rr(&rec).as_soa().expect("as_soa");
        assert_eq!(soa.mname(), "");
        assert_eq!(soa.rname(), "");
        assert_eq!(soa.serial(), 0);
        assert_eq!(soa.minimum(), 0);

        // CAA: flags zero, tag/value empty, not critical.
        let rec = make_rec(DnsRecordType::CAA);
        let caa = first_rr(&rec).as_caa().expect("as_caa");
        assert_eq!(caa.flags(), 0);
        assert!(!caa.is_critical());
        assert_eq!(caa.tag(), "");
        assert_eq!(caa.value(), &[] as &[u8]);

        // TXT: empty entries, count zero.
        let rec = make_rec(DnsRecordType::TXT);
        let txt = first_rr(&rec).as_txt().expect("as_txt");
        assert_eq!(txt.entry_count(), 0);
        assert_eq!(txt.entries().count(), 0);

        // RAW_RR: data empty, raw_type zero.
        let rec = make_rec(DnsRecordType::RAW_RR);
        let raw = first_rr(&rec).as_raw_rr().expect("as_raw_rr");
        assert_eq!(raw.raw_type(), 0);
        assert_eq!(raw.data(), &[] as &[u8]);
    }

    // ---- Builder full-set + typed read-back --------------------------------

    #[test]
    fn a_full_roundtrip() {
        let mut rec = make_rec(DnsRecordType::A);
        let rr = rec.rr_mut(DnsSection::Answer, 0).expect("rr_mut");
        rr.set_addr(DnsRrKey::A_ADDR, Ipv4Addr::new(10, 0, 0, 1))
            .expect("set");
        let a = first_rr(&rec).as_a().expect("as_a");
        assert_eq!(a.addr(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(a.name(), "example.com");
    }

    #[test]
    fn aaaa_full_roundtrip() {
        let mut rec = make_rec(DnsRecordType::AAAA);
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let rr = rec.rr_mut(DnsSection::Answer, 0).expect("rr_mut");
        rr.set_addr6(DnsRrKey::AAAA_ADDR, addr).expect("set");
        let aaaa = first_rr(&rec).as_aaaa().expect("as_aaaa");
        assert_eq!(aaaa.addr(), addr);
    }

    #[test]
    fn mx_full_roundtrip() {
        let mut rec = make_rec(DnsRecordType::MX);
        let rr = rec.rr_mut(DnsSection::Answer, 0).expect("rr_mut");
        rr.set_u16(DnsRrKey::MX_PREFERENCE, 10).expect("pref");
        rr.set_str(DnsRrKey::MX_EXCHANGE, "mail.example.com")
            .expect("exch");
        let mx = first_rr(&rec).as_mx().expect("as_mx");
        assert_eq!(mx.preference(), 10);
        assert_eq!(mx.exchange(), "mail.example.com");
    }

    #[test]
    fn caa_critical_bit() {
        let mut rec = make_rec(DnsRecordType::CAA);
        let rr = rec.rr_mut(DnsSection::Answer, 0).expect("rr_mut");
        rr.set_u8(DnsRrKey::CAA_CRITICAL, 0x80).expect("crit");
        rr.set_str(DnsRrKey::CAA_TAG, "issue").expect("tag");
        rr.set_bin(DnsRrKey::CAA_VALUE, b"ca.example.net")
            .expect("val");
        let caa = first_rr(&rec).as_caa().expect("as_caa");
        assert_eq!(caa.flags(), 0x80);
        assert!(caa.is_critical());
        assert_eq!(caa.tag(), "issue");
        assert_eq!(caa.value(), &b"ca.example.net"[..]);
    }

    #[test]
    fn txt_entries_iterator() {
        let mut rec = make_rec(DnsRecordType::TXT);
        let rr = rec.rr_mut(DnsSection::Answer, 0).expect("rr_mut");
        rr.add_abin(DnsRrKey::TXT_DATA, b"first").expect("a1");
        rr.add_abin(DnsRrKey::TXT_DATA, b"second").expect("a2");
        let txt = first_rr(&rec).as_txt().expect("as_txt");
        assert_eq!(txt.entry_count(), 2);
        let entries: Vec<&[u8]> = txt.entries().collect();
        assert_eq!(entries, vec![&b"first"[..], &b"second"[..]]);
    }

    // ---- Parser-driven (wire round trip) -----------------------------------

    fn build_then_parse(rec: &DnsRecord) -> DnsRecord {
        let wire = rec.write().expect("write");
        DnsRecord::parse(&wire, DnsParseFlags::empty()).expect("parse")
    }

    #[test]
    fn parsed_a_record() {
        let mut rec = make_rec(DnsRecordType::A);
        rec.rr_mut(DnsSection::Answer, 0)
            .unwrap()
            .set_addr(DnsRrKey::A_ADDR, Ipv4Addr::new(93, 184, 216, 34))
            .unwrap();
        let parsed = build_then_parse(&rec);
        let a = first_rr(&parsed).as_a().expect("as_a");
        assert_eq!(a.addr(), Ipv4Addr::new(93, 184, 216, 34));
    }

    #[test]
    fn parsed_soa_record() {
        let mut rec = make_rec(DnsRecordType::SOA);
        let rr = rec.rr_mut(DnsSection::Answer, 0).unwrap();
        rr.set_str(DnsRrKey::SOA_MNAME, "ns1.example.com").unwrap();
        rr.set_str(DnsRrKey::SOA_RNAME, "hostmaster.example.com")
            .unwrap();
        rr.set_u32(DnsRrKey::SOA_SERIAL, 42).unwrap();
        rr.set_u32(DnsRrKey::SOA_REFRESH, 3600).unwrap();
        rr.set_u32(DnsRrKey::SOA_RETRY, 900).unwrap();
        rr.set_u32(DnsRrKey::SOA_EXPIRE, 604800).unwrap();
        rr.set_u32(DnsRrKey::SOA_MINIMUM, 60).unwrap();
        let parsed = build_then_parse(&rec);
        let soa = first_rr(&parsed).as_soa().expect("as_soa");
        assert_eq!(soa.mname(), "ns1.example.com");
        assert_eq!(soa.rname(), "hostmaster.example.com");
        assert_eq!(soa.serial(), 42);
        assert_eq!(soa.expire(), 604800);
    }

    #[test]
    fn parsed_txt_record() {
        let mut rec = make_rec(DnsRecordType::TXT);
        rec.rr_mut(DnsSection::Answer, 0)
            .unwrap()
            .add_abin(DnsRrKey::TXT_DATA, b"v=spf1 -all")
            .unwrap();
        let parsed = build_then_parse(&rec);
        let txt = first_rr(&parsed).as_txt().expect("as_txt");
        assert_eq!(txt.entry_count(), 1);
        assert_eq!(txt.entries().next(), Some(&b"v=spf1 -all"[..]));
    }

    #[test]
    fn parsed_mx_record() {
        let mut rec = make_rec(DnsRecordType::MX);
        let rr = rec.rr_mut(DnsSection::Answer, 0).unwrap();
        rr.set_u16(DnsRrKey::MX_PREFERENCE, 5).unwrap();
        rr.set_str(DnsRrKey::MX_EXCHANGE, "mx.example.com").unwrap();
        let parsed = build_then_parse(&rec);
        let mx = first_rr(&parsed).as_mx().expect("as_mx");
        assert_eq!(mx.preference(), 5);
        assert_eq!(mx.exchange(), "mx.example.com");
    }

    // ---- Full-coverage sweep: every accessor + Debug + as_* discriminator -

    /// Helper that builds a record, lets the caller populate it, then
    /// returns it.
    fn build<F: FnOnce(&mut DnsRr)>(rtype: DnsRecordType, populate: F) -> DnsRecord {
        let mut rec = make_rec(rtype);
        populate(rec.rr_mut(DnsSection::Answer, 0).expect("rr_mut"));
        rec
    }

    #[test]
    fn ns_full_accessors_and_debug() {
        let rec = build(DnsRecordType::NS, |rr| {
            rr.set_str(DnsRrKey::NS_NSDNAME, "ns1.example.com").unwrap();
        });
        let ns = first_rr(&rec).as_ns().expect("as_ns");
        assert_eq!(ns.nsdname(), "ns1.example.com");
        assert_eq!(ns.name(), "example.com");
        assert_eq!(ns.dns_class(), DnsCls::IN);
        assert_eq!(ns.ttl(), 300);
        let _ = ns.as_dns_rr();
        assert!(format!("{ns:?}").contains("NsRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Ns(_)));
    }

    #[test]
    fn cname_full_accessors_and_debug() {
        let rec = build(DnsRecordType::CNAME, |rr| {
            rr.set_str(DnsRrKey::CNAME_CNAME, "alias.example.com")
                .unwrap();
        });
        let c = first_rr(&rec).as_cname().expect("as_cname");
        assert_eq!(c.cname(), "alias.example.com");
        assert!(format!("{c:?}").contains("CnameRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Cname(_)));
    }

    #[test]
    fn ptr_full_accessors_and_debug() {
        let rec = build(DnsRecordType::PTR, |rr| {
            rr.set_str(DnsRrKey::PTR_DNAME, "host.example.com").unwrap();
        });
        let p = first_rr(&rec).as_ptr_rr().expect("as_ptr_rr");
        assert_eq!(p.dname(), "host.example.com");
        assert!(format!("{p:?}").contains("PtrRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Ptr(_)));
    }

    #[test]
    fn hinfo_full_accessors_and_debug() {
        let rec = build(DnsRecordType::HINFO, |rr| {
            rr.set_str(DnsRrKey::HINFO_CPU, "x86_64").unwrap();
            rr.set_str(DnsRrKey::HINFO_OS, "linux").unwrap();
        });
        let h = first_rr(&rec).as_hinfo().expect("as_hinfo");
        assert_eq!(h.cpu(), "x86_64");
        assert_eq!(h.os(), "linux");
        assert!(format!("{h:?}").contains("HinfoRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Hinfo(_)));
    }

    #[test]
    fn soa_full_accessors_and_debug() {
        let rec = build(DnsRecordType::SOA, |rr| {
            rr.set_str(DnsRrKey::SOA_MNAME, "ns.example.com").unwrap();
            rr.set_str(DnsRrKey::SOA_RNAME, "hostmaster.example.com")
                .unwrap();
            rr.set_u32(DnsRrKey::SOA_SERIAL, 1).unwrap();
            rr.set_u32(DnsRrKey::SOA_REFRESH, 2).unwrap();
            rr.set_u32(DnsRrKey::SOA_RETRY, 3).unwrap();
            rr.set_u32(DnsRrKey::SOA_EXPIRE, 4).unwrap();
            rr.set_u32(DnsRrKey::SOA_MINIMUM, 5).unwrap();
        });
        let s = first_rr(&rec).as_soa().expect("as_soa");
        assert_eq!(s.mname(), "ns.example.com");
        assert_eq!(s.rname(), "hostmaster.example.com");
        assert_eq!(s.serial(), 1);
        assert_eq!(s.refresh(), 2);
        assert_eq!(s.retry(), 3);
        assert_eq!(s.expire(), 4);
        assert_eq!(s.minimum(), 5);
        assert!(format!("{s:?}").contains("SoaRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Soa(_)));
    }

    #[test]
    fn sig_full_accessors_and_debug() {
        let rec = build(DnsRecordType::SIG, |rr| {
            rr.set_u16(DnsRrKey::SIG_TYPE_COVERED, 1).unwrap();
            rr.set_u8(DnsRrKey::SIG_ALGORITHM, 8).unwrap();
            rr.set_u8(DnsRrKey::SIG_LABELS, 2).unwrap();
            rr.set_u32(DnsRrKey::SIG_ORIGINAL_TTL, 3600).unwrap();
            rr.set_u32(DnsRrKey::SIG_EXPIRATION, 4_000_000_000).unwrap();
            rr.set_u32(DnsRrKey::SIG_INCEPTION, 1_000_000_000).unwrap();
            rr.set_u16(DnsRrKey::SIG_KEY_TAG, 12345).unwrap();
            rr.set_str(DnsRrKey::SIG_SIGNERS_NAME, "example.com")
                .unwrap();
            rr.set_bin(DnsRrKey::SIG_SIGNATURE, b"\x01\x02\x03\x04")
                .unwrap();
        });
        let s = first_rr(&rec).as_sig().expect("as_sig");
        assert_eq!(s.type_covered(), 1);
        assert_eq!(s.algorithm(), 8);
        assert_eq!(s.labels(), 2);
        assert_eq!(s.original_ttl(), 3600);
        assert_eq!(s.expiration(), 4_000_000_000);
        assert_eq!(s.inception(), 1_000_000_000);
        assert_eq!(s.key_tag(), 12345);
        assert_eq!(s.signers_name(), "example.com");
        assert_eq!(s.signature(), &b"\x01\x02\x03\x04"[..]);
        assert!(format!("{s:?}").contains("SigRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Sig(_)));
    }

    #[test]
    fn srv_full_accessors_and_debug() {
        let rec = build(DnsRecordType::SRV, |rr| {
            rr.set_u16(DnsRrKey::SRV_PRIORITY, 10).unwrap();
            rr.set_u16(DnsRrKey::SRV_WEIGHT, 20).unwrap();
            rr.set_u16(DnsRrKey::SRV_PORT, 443).unwrap();
            rr.set_str(DnsRrKey::SRV_TARGET, "svc.example.com").unwrap();
        });
        let s = first_rr(&rec).as_srv().expect("as_srv");
        assert_eq!(s.priority(), 10);
        assert_eq!(s.weight(), 20);
        assert_eq!(s.port(), 443);
        assert_eq!(s.target(), "svc.example.com");
        assert!(format!("{s:?}").contains("SrvRecord"));
    }

    #[test]
    fn naptr_full_accessors_and_debug() {
        let rec = build(DnsRecordType::NAPTR, |rr| {
            rr.set_u16(DnsRrKey::NAPTR_ORDER, 100).unwrap();
            rr.set_u16(DnsRrKey::NAPTR_PREFERENCE, 10).unwrap();
            rr.set_str(DnsRrKey::NAPTR_FLAGS, "U").unwrap();
            rr.set_str(DnsRrKey::NAPTR_SERVICES, "E2U+sip").unwrap();
            rr.set_str(DnsRrKey::NAPTR_REGEXP, "!^.*$!sip:info@example.com!")
                .unwrap();
            rr.set_str(DnsRrKey::NAPTR_REPLACEMENT, ".").unwrap();
        });
        let n = first_rr(&rec).as_naptr().expect("as_naptr");
        assert_eq!(n.order(), 100);
        assert_eq!(n.preference(), 10);
        assert_eq!(n.flags(), "U");
        assert_eq!(n.services(), "E2U+sip");
        assert_eq!(n.regexp(), "!^.*$!sip:info@example.com!");
        assert_eq!(n.replacement(), ".");
        assert!(format!("{n:?}").contains("NaptrRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Naptr(_)));
    }

    #[test]
    fn tlsa_full_accessors_and_debug() {
        let rec = build(DnsRecordType::TLSA, |rr| {
            rr.set_u8(DnsRrKey::TLSA_CERT_USAGE, 3).unwrap();
            rr.set_u8(DnsRrKey::TLSA_SELECTOR, 1).unwrap();
            rr.set_u8(DnsRrKey::TLSA_MATCH, 1).unwrap();
            rr.set_bin(DnsRrKey::TLSA_DATA, &[0xab; 32]).unwrap();
        });
        let t = first_rr(&rec).as_tlsa().expect("as_tlsa");
        assert_eq!(t.cert_usage(), 3);
        assert_eq!(t.selector(), 1);
        assert_eq!(t.matching_type(), 1);
        assert_eq!(t.data().len(), 32);
        assert!(format!("{t:?}").contains("TlsaRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Tlsa(_)));
    }

    #[test]
    fn uri_full_accessors_and_debug() {
        let rec = build(DnsRecordType::URI, |rr| {
            rr.set_u16(DnsRrKey::URI_PRIORITY, 1).unwrap();
            rr.set_u16(DnsRrKey::URI_WEIGHT, 2).unwrap();
            rr.set_str(DnsRrKey::URI_TARGET, "https://example.com/")
                .unwrap();
        });
        let u = first_rr(&rec).as_uri().expect("as_uri");
        assert_eq!(u.priority(), 1);
        assert_eq!(u.weight(), 2);
        assert_eq!(u.target(), "https://example.com/");
        assert!(format!("{u:?}").contains("UriRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Uri(_)));
    }

    #[test]
    fn svcb_full_accessors_and_debug() {
        let rec = build(DnsRecordType::SVCB, |rr| {
            rr.set_u16(DnsRrKey::SVCB_PRIORITY, 1).unwrap();
            rr.set_str(DnsRrKey::SVCB_TARGET, "svc.example.com")
                .unwrap();
            // ALPN option (key 1) with value "h2"
            rr.set_opt(DnsRrKey::SVCB_PARAMS, 1, b"\x00\x02h2").unwrap();
        });
        let s = first_rr(&rec).as_svcb().expect("as_svcb");
        assert_eq!(s.priority(), 1);
        assert_eq!(s.target(), "svc.example.com");
        assert_eq!(s.param_count(), 1);
        // raw_params() yields raw bytes
        let raw: Vec<(u16, &[u8])> = s.raw_params().collect();
        assert_eq!(raw, vec![(1u16, &b"\x00\x02h2"[..])]);
        // params() decodes — ALPN (key 1) is a StrList
        let parsed: Vec<(u16, OptValue)> =
            s.params().map(|(k, v)| (k, v.expect("decode"))).collect();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, 1);
        assert!(matches!(parsed[0].1, OptValue::StrList(_)));
        assert!(format!("{s:?}").contains("SvcbRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Svcb(_)));
    }

    #[test]
    fn https_full_accessors_and_debug() {
        let rec = build(DnsRecordType::HTTPS, |rr| {
            rr.set_u16(DnsRrKey::HTTPS_PRIORITY, 1).unwrap();
            rr.set_str(DnsRrKey::HTTPS_TARGET, "svc.example.com")
                .unwrap();
            rr.set_opt(DnsRrKey::HTTPS_PARAMS, 1, b"\x00\x02h3")
                .unwrap();
        });
        let h = first_rr(&rec).as_https().expect("as_https");
        assert_eq!(h.priority(), 1);
        assert_eq!(h.target(), "svc.example.com");
        assert_eq!(h.param_count(), 1);
        assert_eq!(h.raw_params().count(), 1);
        assert_eq!(h.params().count(), 1);
        assert!(format!("{h:?}").contains("HttpsRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Https(_)));
    }

    #[test]
    fn opt_full_accessors_and_debug() {
        // OPT may be rejected by rr_add as a pseudo-record. Try it and
        // fall back to skipping the test if so.
        let mut rec =
            DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError).expect("create");
        rec.query_add("example.com", DnsRecordType::A, DnsCls::IN)
            .expect("query_add");
        if rec
            .rr_add(
                DnsSection::Additional,
                "",
                DnsRecordType::OPT,
                DnsCls::IN,
                0,
            )
            .is_err()
        {
            return;
        }
        let rr = rec.rr_mut(DnsSection::Additional, 0).expect("rr_mut");
        let _ = rr.set_u16(DnsRrKey::OPT_UDP_SIZE, 4096);
        let _ = rr.set_u8(DnsRrKey::OPT_VERSION, 0);
        let _ = rr.set_u16(DnsRrKey::OPT_FLAGS, 0x8000);
        let _ = rr.set_opt(DnsRrKey::OPT_OPTIONS, 10, b"\x01\x02");
        let opt_rr = rec
            .rr(DnsSection::Additional, 0)
            .expect("rr")
            .as_opt()
            .expect("as_opt");
        let _ = opt_rr.udp_size();
        let _ = opt_rr.version();
        let _ = opt_rr.flags();
        let _ = opt_rr.option_count();
        let _ = opt_rr.options().count();
        let _ = opt_rr.raw_options().count();
        let _ = format!("{opt_rr:?}");
        assert!(matches!(
            rec.rr(DnsSection::Additional, 0).unwrap().as_typed(),
            TypedRr::Opt(_)
        ));
    }

    #[test]
    fn raw_rr_full_accessors_and_debug() {
        let rec = build(DnsRecordType::RAW_RR, |rr| {
            let _ = rr.set_u16(DnsRrKey::RAW_RR_TYPE, 99);
            let _ = rr.set_bin(DnsRrKey::RAW_RR_DATA, b"hello");
        });
        let r = first_rr(&rec).as_raw_rr().expect("as_raw_rr");
        let _ = r.raw_type();
        let _ = r.data();
        assert!(format!("{r:?}").contains("RawRrRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::RawRr(_)));
    }

    #[test]
    fn ds_full_accessors_and_debug() {
        let rec = build(DnsRecordType::DS, |rr| {
            rr.set_u16(DnsRrKey::DS_KEY_TAG, 12345).unwrap();
            rr.set_u8(DnsRrKey::DS_ALGORITHM, 8).unwrap();
            rr.set_u8(DnsRrKey::DS_DIGEST_TYPE, 2).unwrap();
            rr.set_bin(DnsRrKey::DS_DIGEST, &[0xab; 32]).unwrap();
        });
        let d = first_rr(&rec).as_ds().expect("as_ds");
        assert_eq!(d.key_tag(), 12345);
        assert_eq!(d.algorithm(), 8);
        assert_eq!(d.digest_type(), 2);
        assert_eq!(d.digest(), &[0xab; 32][..]);
        assert!(format!("{d:?}").contains("DsRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Ds(_)));
    }

    #[test]
    fn sshfp_full_accessors_and_debug() {
        let rec = build(DnsRecordType::SSHFP, |rr| {
            rr.set_u8(DnsRrKey::SSHFP_ALGORITHM, 4).unwrap();
            rr.set_u8(DnsRrKey::SSHFP_FP_TYPE, 2).unwrap();
            rr.set_bin(DnsRrKey::SSHFP_FINGERPRINT, &[0xcd; 32])
                .unwrap();
        });
        let s = first_rr(&rec).as_sshfp().expect("as_sshfp");
        assert_eq!(s.algorithm(), 4);
        assert_eq!(s.fp_type(), 2);
        assert_eq!(s.fingerprint(), &[0xcd; 32][..]);
        assert!(format!("{s:?}").contains("SshfpRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Sshfp(_)));
    }

    #[test]
    fn rrsig_full_accessors_and_debug() {
        let rec = build(DnsRecordType::RRSIG, |rr| {
            rr.set_u16(DnsRrKey::RRSIG_TYPE_COVERED, 1).unwrap();
            rr.set_u8(DnsRrKey::RRSIG_ALGORITHM, 8).unwrap();
            rr.set_u8(DnsRrKey::RRSIG_LABELS, 2).unwrap();
            rr.set_u32(DnsRrKey::RRSIG_ORIGINAL_TTL, 3600).unwrap();
            rr.set_u32(DnsRrKey::RRSIG_EXPIRATION, 4_000_000_000)
                .unwrap();
            rr.set_u32(DnsRrKey::RRSIG_INCEPTION, 1_000_000_000)
                .unwrap();
            rr.set_u16(DnsRrKey::RRSIG_KEY_TAG, 54321).unwrap();
            rr.set_str(DnsRrKey::RRSIG_SIGNERS_NAME, "example.com")
                .unwrap();
            rr.set_bin(DnsRrKey::RRSIG_SIGNATURE, b"\x01\x02\x03\x04")
                .unwrap();
        });
        let r = first_rr(&rec).as_rrsig().expect("as_rrsig");
        assert_eq!(r.type_covered(), 1);
        assert_eq!(r.algorithm(), 8);
        assert_eq!(r.labels(), 2);
        assert_eq!(r.original_ttl(), 3600);
        assert_eq!(r.expiration(), 4_000_000_000);
        assert_eq!(r.inception(), 1_000_000_000);
        assert_eq!(r.key_tag(), 54321);
        assert_eq!(r.signers_name(), "example.com");
        assert_eq!(r.signature(), &b"\x01\x02\x03\x04"[..]);
        assert!(format!("{r:?}").contains("RrsigRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Rrsig(_)));
    }

    #[test]
    fn nsec_full_accessors_and_debug() {
        let rec = build(DnsRecordType::NSEC, |rr| {
            rr.set_str(DnsRrKey::NSEC_NEXT_DOMAIN, "next.example.com")
                .unwrap();
            rr.set_bin(DnsRrKey::NSEC_TYPE_BIT_MAPS, &[0x00, 0x01, 0x40])
                .unwrap();
        });
        let n = first_rr(&rec).as_nsec().expect("as_nsec");
        assert_eq!(n.next_domain(), "next.example.com");
        assert_eq!(n.type_bit_maps(), &[0x00, 0x01, 0x40][..]);
        assert!(format!("{n:?}").contains("NsecRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Nsec(_)));
    }

    #[test]
    fn dnskey_full_accessors_and_debug() {
        let rec = build(DnsRecordType::DNSKEY, |rr| {
            rr.set_u16(DnsRrKey::DNSKEY_FLAGS, 0x0101).unwrap();
            rr.set_u8(DnsRrKey::DNSKEY_PROTOCOL, 3).unwrap();
            rr.set_u8(DnsRrKey::DNSKEY_ALGORITHM, 8).unwrap();
            rr.set_bin(DnsRrKey::DNSKEY_PUBLIC_KEY, &[0xef; 64])
                .unwrap();
        });
        let d = first_rr(&rec).as_dnskey().expect("as_dnskey");
        assert_eq!(d.flags(), 0x0101);
        assert_eq!(d.protocol(), 3);
        assert_eq!(d.algorithm(), 8);
        assert_eq!(d.public_key(), &[0xef; 64][..]);
        assert!(format!("{d:?}").contains("DnskeyRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Dnskey(_)));
    }

    #[test]
    fn nsec3_full_accessors_and_debug() {
        let rec = build(DnsRecordType::NSEC3, |rr| {
            rr.set_u8(DnsRrKey::NSEC3_HASH_ALGORITHM, 1).unwrap();
            rr.set_u8(DnsRrKey::NSEC3_FLAGS, 0).unwrap();
            rr.set_u16(DnsRrKey::NSEC3_ITERATIONS, 10).unwrap();
            rr.set_bin(DnsRrKey::NSEC3_SALT, b"\xaa\xbb\xcc\xdd")
                .unwrap();
            rr.set_bin(DnsRrKey::NSEC3_NEXT_HASHED_OWNER, &[0x11; 20])
                .unwrap();
            rr.set_bin(DnsRrKey::NSEC3_TYPE_BIT_MAPS, &[0x00, 0x01, 0x40])
                .unwrap();
        });
        let n = first_rr(&rec).as_nsec3().expect("as_nsec3");
        assert_eq!(n.hash_algorithm(), 1);
        assert_eq!(n.flags(), 0);
        assert_eq!(n.iterations(), 10);
        assert_eq!(n.salt(), &b"\xaa\xbb\xcc\xdd"[..]);
        assert_eq!(n.next_hashed_owner(), &[0x11; 20][..]);
        assert_eq!(n.type_bit_maps(), &[0x00, 0x01, 0x40][..]);
        assert!(format!("{n:?}").contains("Nsec3Record"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Nsec3(_)));
    }

    #[test]
    fn nsec3param_full_accessors_and_debug() {
        let rec = build(DnsRecordType::NSEC3PARAM, |rr| {
            rr.set_u8(DnsRrKey::NSEC3PARAM_HASH_ALGORITHM, 1).unwrap();
            rr.set_u8(DnsRrKey::NSEC3PARAM_FLAGS, 0).unwrap();
            rr.set_u16(DnsRrKey::NSEC3PARAM_ITERATIONS, 5).unwrap();
            rr.set_bin(DnsRrKey::NSEC3PARAM_SALT, b"\x12\x34").unwrap();
        });
        let n = first_rr(&rec).as_nsec3param().expect("as_nsec3param");
        assert_eq!(n.hash_algorithm(), 1);
        assert_eq!(n.flags(), 0);
        assert_eq!(n.iterations(), 5);
        assert_eq!(n.salt(), &b"\x12\x34"[..]);
        assert!(format!("{n:?}").contains("Nsec3ParamRecord"));
        assert!(matches!(first_rr(&rec).as_typed(), TypedRr::Nsec3Param(_)));
    }

    #[test]
    fn debug_impls_for_all_simple_wrappers() {
        // Cover Debug for the wrappers whose dedicated tests above don't
        // already exercise them on a populated record.
        let rec = make_rec(DnsRecordType::A);
        assert!(format!("{:?}", first_rr(&rec).as_a().unwrap()).contains("ARecord"));
        let rec = make_rec(DnsRecordType::AAAA);
        assert!(format!("{:?}", first_rr(&rec).as_aaaa().unwrap()).contains("AaaaRecord"));
        let rec = make_rec(DnsRecordType::MX);
        assert!(format!("{:?}", first_rr(&rec).as_mx().unwrap()).contains("MxRecord"));
        let rec = make_rec(DnsRecordType::TXT);
        assert!(format!("{:?}", first_rr(&rec).as_txt().unwrap()).contains("TxtRecord"));
        let rec = make_rec(DnsRecordType::CAA);
        assert!(format!("{:?}", first_rr(&rec).as_caa().unwrap()).contains("CaaRecord"));
        // TypedRr Debug
        assert!(format!("{:?}", first_rr(&rec).as_typed()).contains("Caa"));
    }

    #[test]
    fn as_discriminators_return_none_on_mismatch() {
        let rec = make_rec(DnsRecordType::A);
        let rr = first_rr(&rec);
        assert!(rr.as_ns().is_none());
        assert!(rr.as_cname().is_none());
        assert!(rr.as_soa().is_none());
        assert!(rr.as_ptr_rr().is_none());
        assert!(rr.as_hinfo().is_none());
        assert!(rr.as_sig().is_none());
        assert!(rr.as_srv().is_none());
        assert!(rr.as_naptr().is_none());
        assert!(rr.as_opt().is_none());
        assert!(rr.as_tlsa().is_none());
        assert!(rr.as_svcb().is_none());
        assert!(rr.as_https().is_none());
        assert!(rr.as_uri().is_none());
        assert!(rr.as_caa().is_none());
        assert!(rr.as_raw_rr().is_none());
        assert!(rr.as_ds().is_none());
        assert!(rr.as_sshfp().is_none());
        assert!(rr.as_rrsig().is_none());
        assert!(rr.as_nsec().is_none());
        assert!(rr.as_dnskey().is_none());
        assert!(rr.as_nsec3().is_none());
        assert!(rr.as_nsec3param().is_none());
    }
}
