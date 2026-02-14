pub(crate) mod callback;
mod enums;
mod record;
mod rr;

pub use enums::{
    DnsCls, DnsDataType, DnsFlags, DnsOpcode, DnsOptDataType, DnsParseFlags, DnsRcode,
    DnsRecordType, DnsRrKey, DnsSection,
};
pub use record::DnsRecord;
pub use rr::DnsRr;
