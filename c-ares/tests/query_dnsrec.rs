//! Integration tests for the DnsRecord-based query methods (query_dnsrec, send_dnsrec,
//! search_dnsrec).

#![cfg(all(cares1_28, unix, any(target_os = "linux", target_os = "android")))]

mod common;

use c_ares::*;
use common::process_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
#[ignore = "requires network"]
fn query_dnsrec_a_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8", "8.8.4.4"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec("google.com", DnsCls::IN, DnsRecordType::A, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            let record = result.expect("Query failed");

            // Verify header fields.
            assert!(record.flags().contains(DnsFlags::QR));
            assert_eq!(record.opcode(), DnsOpcode::Query);
            assert_eq!(record.rcode(), DnsRcode::NoError);

            // Verify question section.
            assert_eq!(record.query_count(), 1);
            let (name, qtype, qclass) = record.queries().next().unwrap();
            assert!(name.contains("google"));
            assert_eq!(qtype, DnsRecordType::A);
            assert_eq!(qclass, DnsCls::IN);

            // Verify answer section has A records.
            let mut answer_count = 0;
            for rr in record.rrs(DnsSection::Answer) {
                assert_eq!(rr.rr_type(), DnsRecordType::A);
                let addr = rr.get_addr(DnsRrKey::A_ADDR).expect("get_addr");
                assert!(!addr.is_unspecified());
                answer_count += 1;
            }
            assert!(answer_count > 0, "No answer RRs returned");
        })
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_aaaa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec(
            "google.com",
            DnsCls::IN,
            DnsRecordType::AAAA,
            move |result| {
                completed_clone.store(true, Ordering::SeqCst);
                let record = result.expect("Query failed");
                assert_eq!(record.rcode(), DnsRcode::NoError);

                let mut count = 0;
                for rr in record.rrs(DnsSection::Answer) {
                    assert_eq!(rr.rr_type(), DnsRecordType::AAAA);
                    let addr = rr.get_addr6(DnsRrKey::AAAA_ADDR).expect("get_addr6");
                    assert!(!addr.is_unspecified());
                    count += 1;
                }
                assert!(count > 0, "No AAAA records returned");
            },
        )
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_mx_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec("google.com", DnsCls::IN, DnsRecordType::MX, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            let record = result.expect("Query failed");
            assert_eq!(record.rcode(), DnsRcode::NoError);

            let mut count = 0;
            for rr in record.rrs(DnsSection::Answer) {
                assert_eq!(rr.rr_type(), DnsRecordType::MX);
                let _pref = rr.get_u16(DnsRrKey::MX_PREFERENCE);
                let exchange = rr.get_str(DnsRrKey::MX_EXCHANGE).expect("exchange");
                assert!(!exchange.is_empty());
                count += 1;
            }
            assert!(count > 0, "No MX records returned");
        })
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_txt_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec(
            "google.com",
            DnsCls::IN,
            DnsRecordType::TXT,
            move |result| {
                completed_clone.store(true, Ordering::SeqCst);
                let record = result.expect("Query failed");
                assert_eq!(record.rcode(), DnsRcode::NoError);

                let mut count = 0;
                for rr in record.rrs(DnsSection::Answer) {
                    assert_eq!(rr.rr_type(), DnsRecordType::TXT);
                    let mut abin_count = 0;
                    for data in rr.abins(DnsRrKey::TXT_DATA) {
                        assert!(!data.is_empty());
                        abin_count += 1;
                    }
                    assert!(abin_count > 0, "No TXT data entries");
                    count += 1;
                }
                assert!(count > 0, "No TXT records returned");
            },
        )
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn send_dnsrec_a_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    // Build a query manually using DnsRecord.
    let mut query = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError)
        .expect("Failed to create DnsRecord");
    query
        .query_add("google.com", DnsRecordType::A, DnsCls::IN)
        .expect("query_add failed");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .send_dnsrec(&query, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            let record = result.expect("send_dnsrec query failed");
            assert!(record.flags().contains(DnsFlags::QR));
            assert_eq!(record.rcode(), DnsRcode::NoError);

            let mut count = 0;
            for rr in record.rrs(DnsSection::Answer) {
                assert_eq!(rr.rr_type(), DnsRecordType::A);
                let addr = rr.get_addr(DnsRrKey::A_ADDR).expect("get_addr");
                assert!(!addr.is_unspecified());
                count += 1;
            }
            assert!(count > 0, "No answer RRs returned");
        })
        .expect("send_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_dnsrec_a_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let mut query = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError)
        .expect("Failed to create DnsRecord");
    query
        .query_add("google.com", DnsRecordType::A, DnsCls::IN)
        .expect("query_add failed");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .search_dnsrec(&query, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            let record = result.expect("search_dnsrec query failed");
            assert!(record.flags().contains(DnsFlags::QR));
            assert_eq!(record.rcode(), DnsRcode::NoError);

            assert!(
                record.rrs(DnsSection::Answer).count() > 0,
                "No answer RRs returned"
            );
        })
        .expect("search_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn write_and_reparse_roundtrip() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec("google.com", DnsCls::IN, DnsRecordType::A, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            let record = result.expect("Query failed");

            // Write to wire format and re-parse.
            let wire = record.write().expect("write failed");
            assert!(!wire.is_empty());
            let reparsed =
                DnsRecord::parse(&wire, DnsParseFlags::empty()).expect("re-parse failed");

            // Verify the round-trip preserves key data.
            assert_eq!(reparsed.id(), record.id());
            assert_eq!(reparsed.opcode(), record.opcode());
            assert_eq!(reparsed.rcode(), record.rcode());
            assert_eq!(reparsed.query_count(), record.query_count());
            assert_eq!(
                reparsed.rr_count(DnsSection::Answer),
                record.rr_count(DnsSection::Answer)
            );
        })
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_soa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec(
            "google.com",
            DnsCls::IN,
            DnsRecordType::SOA,
            move |result| {
                completed_clone.store(true, Ordering::SeqCst);
                let record = result.expect("Query failed");
                assert_eq!(record.rcode(), DnsRcode::NoError);

                // SOA may be in answer or authority section.
                let ans_count = record.rrs(DnsSection::Answer).count();
                let auth_count = record.rrs(DnsSection::Authority).count();
                assert!(
                    ans_count > 0 || auth_count > 0,
                    "No SOA in answer or authority"
                );

                let soa_rr = if ans_count > 0 {
                    record.rrs(DnsSection::Answer).next().unwrap()
                } else {
                    record
                        .rrs(DnsSection::Authority)
                        .find(|rr| rr.rr_type() == DnsRecordType::SOA)
                        .expect("No SOA in authority")
                };

                assert_eq!(soa_rr.rr_type(), DnsRecordType::SOA);
                let mname = soa_rr.get_str(DnsRrKey::SOA_MNAME).expect("mname");
                assert!(!mname.is_empty());
                let rname = soa_rr.get_str(DnsRrKey::SOA_RNAME).expect("rname");
                assert!(!rname.is_empty());
                assert!(soa_rr.get_u32(DnsRrKey::SOA_SERIAL) > 0);
                assert!(soa_rr.get_u32(DnsRrKey::SOA_REFRESH) > 0);
                assert!(soa_rr.get_u32(DnsRrKey::SOA_RETRY) > 0);
                assert!(soa_rr.get_u32(DnsRrKey::SOA_EXPIRE) > 0);
            },
        )
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_ns_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec("google.com", DnsCls::IN, DnsRecordType::NS, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            let record = result.expect("Query failed");
            assert_eq!(record.rcode(), DnsRcode::NoError);

            let mut count = 0;
            for rr in record.rrs(DnsSection::Answer) {
                assert_eq!(rr.rr_type(), DnsRecordType::NS);
                let nsdname = rr.get_str(DnsRrKey::NS_NSDNAME).expect("nsdname");
                assert!(!nsdname.is_empty());
                count += 1;
            }
            assert!(count > 0, "No NS records returned");
        })
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_cname_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec(
            "www.google.com",
            DnsCls::IN,
            DnsRecordType::CNAME,
            move |result| {
                completed_clone.store(true, Ordering::SeqCst);
                // query_dnsrec translates rcode+ancount to status:
                //   NOERROR + 0 answers → ENODATA
                //   NOERROR + answers   → SUCCESS
                // www.google.com typically has a CNAME, but the resolver
                // may follow the chain and return no CNAME-typed answers,
                // triggering ENODATA. Both outcomes are correct.
                match result {
                    Ok(record) => {
                        assert_eq!(record.rcode(), DnsRcode::NoError);
                        let rr = record
                            .rrs(DnsSection::Answer)
                            .next()
                            .expect("at least one answer");
                        assert_eq!(rr.rr_type(), DnsRecordType::CNAME);
                        let cname = rr.get_str(DnsRrKey::CNAME_CNAME).expect("cname");
                        assert!(!cname.is_empty());
                    }
                    Err(Error::ENODATA) => {
                        // query_dnsrec correctly translated NOERROR + 0 answers
                    }
                    Err(e) => panic!("Unexpected error: {}", e),
                }
            },
        )
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_nonexistent_domain() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .query_dnsrec(
            "this-domain-does-not-exist-12345.invalid",
            DnsCls::IN,
            DnsRecordType::A,
            move |result| {
                completed_clone.store(true, Ordering::SeqCst);
                assert!(matches!(result, Err(Error::ENOTFOUND)));
            },
        )
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn send_dnsrec_nonexistent_domain() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let mut query = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError)
        .expect("Failed to create DnsRecord");
    query
        .query_add(
            "this-domain-does-not-exist-12345.invalid",
            DnsRecordType::A,
            DnsCls::IN,
        )
        .expect("query_add failed");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel
        .send_dnsrec(&query, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            // Unlike query_dnsrec, send_dnsrec does NOT translate DNS
            // rcodes to error statuses. It passes ARES_SUCCESS with the
            // parsed response, and the caller inspects the rcode.
            let record = result.expect("send_dnsrec should succeed");
            assert!(record.flags().contains(DnsFlags::QR));
            assert_eq!(record.rcode(), DnsRcode::NXDomain);
            assert_eq!(record.rrs(DnsSection::Answer).count(), 0);
        })
        .expect("send_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_cancel() {
    let mut options = Options::new();
    options.set_timeout(5000).set_tries(3);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_clone = cancelled.clone();

    channel
        .query_dnsrec("google.com", DnsCls::IN, DnsRecordType::A, move |result| {
            if let Err(Error::ECANCELLED) = result {
                cancelled_clone.store(true, Ordering::SeqCst);
            }
        })
        .expect("query_dnsrec failed");

    channel.cancel();

    process_channel(&mut channel, Duration::from_secs(1));
    assert!(
        cancelled.load(Ordering::SeqCst),
        "Query should have been cancelled"
    );
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_returns_query_id() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let qid = channel
        .query_dnsrec("google.com", DnsCls::IN, DnsRecordType::A, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            result.expect("Query failed");
        })
        .expect("query_dnsrec failed");

    let _ = qid;

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn send_dnsrec_returns_query_id() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let mut query = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError)
        .expect("Failed to create DnsRecord");
    query
        .query_add("google.com", DnsRecordType::A, DnsCls::IN)
        .expect("query_add failed");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let qid = channel
        .send_dnsrec(&query, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            result.expect("send_dnsrec query failed");
        })
        .expect("send_dnsrec failed");

    let _ = qid;

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_duplicate_response() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let saved = Arc::new(std::sync::Mutex::new(None::<DnsRecord>));
    let saved_clone = saved.clone();

    channel
        .query_dnsrec("google.com", DnsCls::IN, DnsRecordType::A, move |result| {
            let record = result.expect("Query failed");
            let dup = record.try_clone().expect("try_clone failed");
            *saved_clone.lock().unwrap() = Some(dup);
        })
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));

    // Verify the duplicated record is valid and independently usable
    // after the callback and channel processing are done.
    let guard = saved.lock().unwrap();
    let dup = guard.as_ref().expect("Callback did not save a record");
    assert!(dup.flags().contains(DnsFlags::QR));
    assert_eq!(dup.rcode(), DnsRcode::NoError);
    let rr = dup
        .rrs(DnsSection::Answer)
        .next()
        .expect("at least one answer");
    assert_eq!(rr.rr_type(), DnsRecordType::A);
    assert!(rr.get_addr(DnsRrKey::A_ADDR).is_some());
}

#[test]
#[ignore = "requires network"]
fn query_dnsrec_response_has_additional_section() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    // NS queries often return glue records in the additional section.
    channel
        .query_dnsrec("google.com", DnsCls::IN, DnsRecordType::NS, move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            let record = result.expect("Query failed");
            assert_eq!(record.rcode(), DnsRcode::NoError);

            // Exercise authority and additional section iteration.
            for rr in record.rrs(DnsSection::Authority) {
                let _ = rr.rr_type();
                let _ = rr.name();
            }
            for rr in record.rrs(DnsSection::Additional) {
                match rr.rr_type() {
                    DnsRecordType::A => {
                        let _ = rr.get_addr(DnsRrKey::A_ADDR);
                    }
                    DnsRecordType::AAAA => {
                        let _ = rr.get_addr6(DnsRrKey::AAAA_ADDR);
                    }
                    _ => {}
                }
            }
        })
        .expect("query_dnsrec failed");

    process_channel(&mut channel, Duration::from_secs(3));
    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}
