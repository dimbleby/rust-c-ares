// Demonstrates issuing an arbitrary DNS query via `send_dnsrec` and
// printing the parsed response using the strongly-typed record view API
// (`DnsRr::as_typed`, `TypedRr`, the per-type wrappers like `ARecord`,
// `MxRecord`, …).
//
// Requires c-ares >= 1.28.

#[cfg(cares1_28)]
mod inner {
    use c_ares::{DnsCls, DnsRecord, DnsRecordType, DnsRr, DnsSection, TypedRr};
    use c_ares_resolver::Resolver;
    use std::sync::mpsc;

    fn print_rr(rr: &DnsRr) {
        println!(
            "    {} {} {} TTL={}",
            rr.name(),
            rr.rr_type(),
            rr.dns_class(),
            rr.ttl(),
        );
        match rr.as_typed() {
            TypedRr::A(a) => {
                println!("      A {}", a.addr());
            }
            TypedRr::Aaaa(aaaa) => {
                println!("      AAAA {}", aaaa.addr());
            }
            TypedRr::Cname(cname) => {
                println!("      CNAME {}", cname.cname());
            }
            TypedRr::Ns(ns) => {
                println!("      NS {}", ns.nsdname());
            }
            TypedRr::Ptr(ptr) => {
                println!("      PTR {}", ptr.dname());
            }
            TypedRr::Mx(mx) => {
                println!(
                    "      MX preference={} exchange={}",
                    mx.preference(),
                    mx.exchange(),
                );
            }
            TypedRr::Txt(txt) => {
                for entry in txt.entries() {
                    let text = std::str::from_utf8(entry).unwrap_or("<not utf-8>");
                    println!("      TXT {text}");
                }
            }
            TypedRr::Soa(soa) => {
                println!(
                    "      SOA mname={} rname={} serial={} refresh={} retry={} expire={} minimum={}",
                    soa.mname(),
                    soa.rname(),
                    soa.serial(),
                    soa.refresh(),
                    soa.retry(),
                    soa.expire(),
                    soa.minimum(),
                );
            }
            TypedRr::Srv(srv) => {
                println!(
                    "      SRV priority={} weight={} port={} target={}",
                    srv.priority(),
                    srv.weight(),
                    srv.port(),
                    srv.target(),
                );
            }
            TypedRr::Naptr(n) => {
                println!(
                    "      NAPTR order={} preference={} flags={:?} services={:?} regexp={:?} replacement={:?}",
                    n.order(),
                    n.preference(),
                    n.flags(),
                    n.services(),
                    n.regexp(),
                    n.replacement(),
                );
            }
            TypedRr::Hinfo(h) => {
                println!("      HINFO cpu={:?} os={:?}", h.cpu(), h.os());
            }
            TypedRr::Caa(caa) => {
                let value = std::str::from_utf8(caa.value()).unwrap_or("<not utf-8>");
                println!(
                    "      CAA flags={} critical={} tag={} value={}",
                    caa.flags(),
                    caa.is_critical(),
                    caa.tag(),
                    value,
                );
            }
            TypedRr::Tlsa(t) => {
                println!(
                    "      TLSA cert_usage={} selector={} matching_type={} data_len={}",
                    t.cert_usage(),
                    t.selector(),
                    t.matching_type(),
                    t.data().len(),
                );
            }
            TypedRr::Sig(s) => {
                println!(
                    "      SIG type_covered={} algorithm={} labels={} key_tag={} signers_name={:?}",
                    s.type_covered(),
                    s.algorithm(),
                    s.labels(),
                    s.key_tag(),
                    s.signers_name(),
                );
            }
            TypedRr::Uri(u) => {
                println!(
                    "      URI priority={} weight={} target={:?}",
                    u.priority(),
                    u.weight(),
                    u.target(),
                );
            }
            TypedRr::Svcb(s) => {
                println!(
                    "      SVCB priority={} target={:?} param_count={}",
                    s.priority(),
                    s.target(),
                    s.param_count(),
                );
                for (key, value) in s.params() {
                    let parsed = value
                        .map(|v| v.to_string())
                        .unwrap_or_else(|e| format!("<error: {e}>"));
                    println!("        param {key}: {parsed}");
                }
            }
            TypedRr::Https(h) => {
                println!(
                    "      HTTPS priority={} target={:?} param_count={}",
                    h.priority(),
                    h.target(),
                    h.param_count(),
                );
                for (key, value) in h.params() {
                    let parsed = value
                        .map(|v| v.to_string())
                        .unwrap_or_else(|e| format!("<error: {e}>"));
                    println!("        param {key}: {parsed}");
                }
            }
            TypedRr::Opt(o) => {
                println!(
                    "      OPT udp_size={} version={} flags={:#06x} option_count={}",
                    o.udp_size(),
                    o.version(),
                    o.flags(),
                    o.option_count(),
                );
            }
            TypedRr::RawRr(r) => {
                println!(
                    "      RAW_RR raw_type={} data_len={}",
                    r.raw_type(),
                    r.data().len(),
                );
            }
            TypedRr::Any(_) => {}
            _ => {}
        }
    }

    fn print_section(record: &DnsRecord, section: DnsSection, label: &str) {
        let count = record.rr_count(section);
        if count == 0 {
            return;
        }
        println!("  {label} ({count}):");
        for rr in record.rrs(section) {
            print_rr(rr);
        }
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(windows)]
        let _ = std::net::UdpSocket::bind("127.0.0.1:0");

        let domain = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "google.com".to_string());

        let query_type: DnsRecordType = match std::env::args().nth(2) {
            Some(s) => s
                .parse()
                .map_err(|_| format!("unknown record type '{s}'"))?,
            None => DnsRecordType::A,
        };

        let mut query = DnsRecord::new(
            0,
            c_ares::DnsFlags::RD,
            c_ares::DnsOpcode::Query,
            c_ares::DnsRcode::NoError,
        )?;
        query.query_add(&domain, query_type, DnsCls::IN)?;

        let (tx, rx) = mpsc::channel();
        let resolver = Resolver::new()?;

        resolver.send_dnsrec(&query, move |result| {
            match result {
                Err(e) => println!("Query failed with error '{e}'"),
                Ok(record) => {
                    println!("Response for {domain} {query_type} (id={}):", record.id());
                    print_section(record, DnsSection::Answer, "Answer");
                    print_section(record, DnsSection::Authority, "Authority");
                    print_section(record, DnsSection::Additional, "Additional");
                }
            }
            tx.send(()).unwrap();
        })?;

        rx.recv()?;
        Ok(())
    }
}

#[cfg(cares1_28)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    inner::run()
}

#[cfg(not(cares1_28))]
fn main() {
    eprintln!("This example requires c-ares >= 1.28.");
}
