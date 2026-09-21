// SPDX-License-Identifier: AGPL-3.0-or-later

#[path = "../build_identity.rs"]
mod build_identity;

#[test]
fn build_identity_contract_is_linked_into_the_test_suite() {
    assert_eq!(
        build_identity::tree_state("asserted", "0123456789ab", "", Some("clean")).unwrap(),
        "asserted-clean"
    );
}
