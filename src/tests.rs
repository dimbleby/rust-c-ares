use super::*;

fn assert_send<T: Send>() {}
fn assert_sync<T: Sync>() {}

#[test]
fn channel_is_send() {
    assert_send::<Channel>();
}

#[test]
fn error_is_send() {
    assert_send::<Error>();
}

#[test]
fn options_is_send() {
    assert_send::<Options>();
}

#[test]
fn get_sock_is_send() {
    assert_send::<GetSock>();
}

#[test]
fn get_sock_iter_is_send() {
    assert_send::<GetSockIter>();
}

#[test]
fn a_result_is_send() {
    assert_send::<AResult>();
}

#[test]
fn a_results_are_send() {
    assert_send::<AResults>();
}

#[test]
fn a_results_iter_is_send() {
    assert_send::<AResultsIter>();
}

#[test]
fn aaaa_result_is_send() {
    assert_send::<AAAAResult>();
}

#[test]
fn aaaa_results_are_send() {
    assert_send::<AAAAResults>();
}

#[test]
fn aaaa_results_iter_is_send() {
    assert_send::<AAAAResultsIter>();
}

#[test]
fn caa_result_is_send() {
    assert_send::<CAAResult>();
}

#[test]
fn caa_results_are_send() {
    assert_send::<CAAResults>();
}

#[test]
fn caa_results_iter_is_send() {
    assert_send::<CAAResultsIter>();
}

#[test]
fn cname_results_are_send() {
    assert_send::<CNameResults>();
}

#[test]
fn host_address_results_iter_is_send() {
    assert_send::<HostAddressResultsIter>();
}

#[test]
fn host_alias_results_iter_is_send() {
    assert_send::<HostAliasResultsIter>();
}

#[test]
fn host_results_are_send() {
    assert_send::<HostResults>();
}

#[test]
fn mx_result_is_send() {
    assert_send::<MXResult>();
}

#[test]
fn mx_results_are_send() {
    assert_send::<MXResults>();
}

#[test]
fn mx_results_iter_is_send() {
    assert_send::<MXResultsIter>();
}

#[test]
fn naptr_result_is_send() {
    assert_send::<NAPTRResult>();
}

#[test]
fn naptr_results_are_send() {
    assert_send::<NAPTRResults>();
}

#[test]
fn naptr_results_iter_is_send() {
    assert_send::<NAPTRResultsIter>();
}

#[test]
fn ns_results_are_send() {
    assert_send::<NSResults>();
}

#[test]
fn ptr_results_are_send() {
    assert_send::<PTRResults>();
}

#[test]
fn srv_result_is_send() {
    assert_send::<SRVResult>();
}

#[test]
fn srv_results_are_send() {
    assert_send::<SRVResults>();
}

#[test]
fn srv_results_iter_is_send() {
    assert_send::<SRVResultsIter>();
}

#[test]
fn txt_result_is_send() {
    assert_send::<TXTResult>();
}

#[test]
fn txt_results_are_send() {
    assert_send::<TXTResults>();
}

#[test]
fn txt_results_iter_is_send() {
    assert_send::<TXTResultsIter>();
}

#[test]
fn uri_result_is_send() {
    assert_send::<URIResult>();
}

#[test]
fn uri_results_are_send() {
    assert_send::<URIResults>();
}

#[test]
fn uri_results_iter_is_send() {
    assert_send::<URIResultsIter>();
}

#[test]
fn channel_is_sync() {
    assert_sync::<Channel>();
}

#[test]
fn error_is_sync() {
    assert_sync::<Error>();
}

#[test]
fn options_is_sync() {
    assert_sync::<Options>();
}

#[test]
fn get_sock_is_sync() {
    assert_sync::<GetSock>();
}

#[test]
fn get_sock_iter_is_sync() {
    assert_sync::<GetSockIter>();
}

#[test]
fn a_result_is_sync() {
    assert_sync::<AResult>();
}

#[test]
fn a_results_are_sync() {
    assert_sync::<AResults>();
}

#[test]
fn a_results_iter_is_sync() {
    assert_sync::<AResultsIter>();
}

#[test]
fn aaaa_result_is_sync() {
    assert_sync::<AAAAResult>();
}

#[test]
fn aaaa_results_are_sync() {
    assert_sync::<AAAAResults>();
}

#[test]
fn aaaa_results_iter_is_sync() {
    assert_sync::<AAAAResultsIter>();
}

#[test]
fn cname_results_are_sync() {
    assert_sync::<CNameResults>();
}

#[test]
fn host_address_results_iter_is_sync() {
    assert_sync::<HostAddressResultsIter>();
}

#[test]
fn host_alias_results_iter_is_sync() {
    assert_sync::<HostAliasResultsIter>();
}

#[test]
fn host_results_are_sync() {
    assert_sync::<HostResults>();
}

#[test]
fn mx_result_is_sync() {
    assert_sync::<MXResult>();
}

#[test]
fn mx_results_are_sync() {
    assert_sync::<MXResults>();
}

#[test]
fn mx_results_iter_is_sync() {
    assert_sync::<MXResultsIter>();
}

#[test]
fn naptr_results_are_sync() {
    assert_sync::<NAPTRResults>();
}

#[test]
fn naptr_result_is_sync() {
    assert_sync::<NAPTRResult>();
}

#[test]
fn naptr_results_iter_is_sync() {
    assert_sync::<NAPTRResultsIter>();
}

#[test]
fn ns_results_are_sync() {
    assert_sync::<NSResults>();
}

#[test]
fn ptr_results_are_sync() {
    assert_sync::<PTRResults>();
}

#[test]
fn srv_result_is_sync() {
    assert_sync::<SRVResult>();
}

#[test]
fn srv_results_are_sync() {
    assert_sync::<SRVResults>();
}

#[test]
fn srv_results_iter_is_sync() {
    assert_sync::<SRVResultsIter>();
}

#[test]
fn txt_result_is_sync() {
    assert_sync::<TXTResult>();
}

#[test]
fn txt_results_are_sync() {
    assert_sync::<TXTResults>();
}

#[test]
fn txt_results_iter_is_sync() {
    assert_sync::<TXTResultsIter>();
}
