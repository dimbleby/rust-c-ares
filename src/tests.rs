use super::*;

fn assert_send<T: Send>() {}
fn assert_sync<T: Sync>() {}

#[test]
pub fn channel_is_send() {
    assert_send::<Channel>();
}

#[test]
pub fn options_is_send() {
    assert_send::<Options>();
}

#[test]
pub fn get_sock_is_send() {
    assert_send::<GetSock>();
}

#[test]
pub fn get_sock_iter_is_send() {
    assert_send::<GetSockIter>();
}

#[test]
pub fn a_result_is_send() {
    assert_send::<AResult>();
}

#[test]
pub fn a_results_are_send() {
    assert_send::<AResults>();
}

#[test]
pub fn a_results_iter_is_send() {
    assert_send::<AResultsIter>();
}

#[test]
pub fn aaaa_result_is_send() {
    assert_send::<AAAAResult>();
}

#[test]
pub fn aaaa_results_are_send() {
    assert_send::<AAAAResults>();
}

#[test]
pub fn aaaa_results_iter_is_send() {
    assert_send::<AAAAResultsIter>();
}

#[test]
pub fn cname_results_are_send() {
    assert_send::<CNameResults>();
}

#[test]
pub fn host_address_results_iter_is_send() {
    assert_send::<HostAddressResultsIter>();
}

#[test]
pub fn host_alias_results_iter_is_send() {
    assert_send::<HostAliasResultsIter>();
}

#[test]
pub fn host_results_are_send() {
    assert_send::<HostResults>();
}

#[test]
pub fn mx_result_is_send() {
    assert_send::<MXResult>();
}

#[test]
pub fn mx_results_are_send() {
    assert_send::<MXResults>();
}

#[test]
pub fn mx_results_iter_is_send() {
    assert_send::<MXResultsIter>();
}

#[test]
pub fn naptr_result_is_send() {
    assert_send::<NAPTRResult>();
}

#[test]
pub fn naptr_results_are_send() {
    assert_send::<NAPTRResults>();
}

#[test]
pub fn naptr_results_iter_is_send() {
    assert_send::<NAPTRResultsIter>();
}

#[test]
pub fn ns_results_are_send() {
    assert_send::<NSResults>();
}

#[test]
pub fn ptr_results_are_send() {
    assert_send::<PTRResults>();
}

#[test]
pub fn srv_result_is_send() {
    assert_send::<SRVResult>();
}

#[test]
pub fn srv_results_are_send() {
    assert_send::<SRVResults>();
}

#[test]
pub fn srv_results_iter_is_send() {
    assert_send::<SRVResultsIter>();
}

#[test]
pub fn txt_results_are_send() {
    assert_send::<TXTResults>();
}

#[test]
pub fn txt_results_iter_is_send() {
    assert_send::<TXTResultsIter>();
}

#[test]
pub fn channel_is_sync() {
    assert_sync::<Channel>();
}

#[test]
pub fn options_is_sync() {
    assert_sync::<Options>();
}

#[test]
pub fn get_sock_is_sync() {
    assert_sync::<GetSock>();
}

#[test]
pub fn get_sock_iter_is_sync() {
    assert_sync::<GetSockIter>();
}

#[test]
pub fn a_result_is_sync() {
    assert_sync::<AResult>();
}

#[test]
pub fn a_results_are_sync() {
    assert_sync::<AResults>();
}

#[test]
pub fn a_results_iter_is_sync() {
    assert_sync::<AResultsIter>();
}

#[test]
pub fn aaaa_result_is_sync() {
    assert_sync::<AAAAResult>();
}

#[test]
pub fn aaaa_results_are_sync() {
    assert_sync::<AAAAResults>();
}

#[test]
pub fn aaaa_results_iter_is_sync() {
    assert_sync::<AAAAResultsIter>();
}

#[test]
pub fn cname_results_are_sync() {
    assert_sync::<CNameResults>();
}

#[test]
pub fn host_address_results_iter_is_sync() {
    assert_sync::<HostAddressResultsIter>();
}

#[test]
pub fn host_alias_results_iter_is_sync() {
    assert_sync::<HostAliasResultsIter>();
}

#[test]
pub fn host_results_are_sync() {
    assert_sync::<HostResults>();
}

#[test]
pub fn mx_result_is_sync() {
    assert_sync::<MXResult>();
}

#[test]
pub fn mx_results_are_sync() {
    assert_sync::<MXResults>();
}

#[test]
pub fn mx_results_iter_is_sync() {
    assert_sync::<MXResultsIter>();
}

#[test]
pub fn naptr_results_are_sync() {
    assert_sync::<NAPTRResults>();
}

#[test]
pub fn naptr_result_is_sync() {
    assert_sync::<NAPTRResult>();
}

#[test]
pub fn naptr_results_iter_is_sync() {
    assert_sync::<NAPTRResultsIter>();
}

#[test]
pub fn ns_results_are_sync() {
    assert_sync::<NSResults>();
}

#[test]
pub fn ptr_results_are_sync() {
    assert_sync::<PTRResults>();
}

#[test]
pub fn srv_result_is_sync() {
    assert_sync::<SRVResult>();
}

#[test]
pub fn srv_results_are_sync() {
    assert_sync::<SRVResults>();
}

#[test]
pub fn srv_results_iter_is_sync() {
    assert_sync::<SRVResultsIter>();
}

#[test]
pub fn txt_results_are_sync() {
    assert_sync::<TXTResults>();
}

#[test]
pub fn txt_results_iter_is_sync() {
    assert_sync::<TXTResultsIter>();
}
