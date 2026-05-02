pub(crate) mod callback;
mod dns_opt;
mod enums;
mod record;
mod rr;
mod typed;

pub use dns_opt::{OptParseError, OptValue, parse_opt_value};
pub use enums::{
    DnsCls, DnsDataType, DnsFlags, DnsOpcode, DnsOptDataType, DnsParseFlags, DnsRcode,
    DnsRecordType, DnsRrKey, DnsSection,
};
pub use record::DnsRecord;
pub use rr::DnsRr;
pub use typed::{
    ARecord, AaaaRecord, CaaRecord, CnameRecord, HinfoRecord, HttpsRecord, MxRecord, NaptrRecord,
    NsRecord, OptRecord, PtrRecord, RawRrRecord, SigRecord, SoaRecord, SrvRecord, SvcbRecord,
    TlsaRecord, TxtRecord, TypedRr, UriRecord,
};
