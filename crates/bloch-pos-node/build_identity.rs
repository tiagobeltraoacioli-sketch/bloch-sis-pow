// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trust-labelled source identity for the node build.
//!
//! `asserted-clean` is deliberately distinct from `clean`: the former means
//! an outer, auditable build recipe materialized a clean commit and explicitly
//! asserted that fact; the latter means this build script inspected Git itself.

pub(crate) fn tree_state(
    commit_source: &str,
    commit: &str,
    dirty: &str,
    tree_assertion: Option<&str>,
) -> Result<&'static str, String> {
    if let Some(assertion) = tree_assertion {
        if assertion != "clean" {
            return Err(format!(
                "BLOCH_BUILD_TREE_ASSERTION must be exactly 'clean', got {assertion:?}"
            ));
        }
        if commit_source != "asserted" {
            return Err(
                "BLOCH_BUILD_TREE_ASSERTION=clean requires a nonempty BLOCH_BUILD_COMMIT"
                    .to_owned(),
            );
        }
        if !matches!(commit.len(), 12 | 40)
            || !commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(
                "BLOCH_BUILD_TREE_ASSERTION=clean requires BLOCH_BUILD_COMMIT to be 12 or 40 lowercase hexadecimal characters"
                    .to_owned(),
            );
        }
    }

    Ok(match dirty {
        "+dirty" => "modified",
        "+nogit" => "unknown",
        _ if commit_source == "asserted" && tree_assertion == Some("clean") => "asserted-clean",
        _ if commit_source == "asserted" => "unverified",
        _ => "clean",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_assertion_is_explicit_and_labelled() {
        assert_eq!(
            tree_state("asserted", "0123456789ab", "", Some("clean")).unwrap(),
            "asserted-clean"
        );
        assert_eq!(
            tree_state("asserted", "anything", "", None).unwrap(),
            "unverified"
        );
    }

    #[test]
    fn assertion_without_asserted_commit_fails_closed() {
        assert!(tree_state("git", "0123456789ab", "", Some("clean")).is_err());
        assert!(tree_state("none", "unknown", "+nogit", Some("clean")).is_err());
    }

    #[test]
    fn assertion_requires_a_valid_commit_id() {
        for commit in [
            "",
            "abc",
            "0123456789aG",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "0123456789abcdef0123456789abcdef012345678",
        ] {
            assert!(
                tree_state("asserted", commit, "", Some("clean")).is_err(),
                "accepted invalid asserted commit {commit:?}"
            );
        }
        assert!(tree_state(
            "asserted",
            "0123456789abcdef0123456789abcdef01234567",
            "",
            Some("clean")
        )
        .is_ok());
    }

    #[test]
    fn unknown_assertion_value_fails_closed() {
        assert!(tree_state("asserted", "0123456789ab", "", Some("dirty")).is_err());
        assert!(tree_state("asserted", "0123456789ab", "", Some("")).is_err());
    }

    #[test]
    fn git_evidence_keeps_its_existing_states() {
        assert_eq!(
            tree_state("git", "0123456789ab", "", None).unwrap(),
            "clean"
        );
        assert_eq!(
            tree_state("git", "0123456789ab", "+dirty", None).unwrap(),
            "modified"
        );
        assert_eq!(
            tree_state("none", "unknown", "+nogit", None).unwrap(),
            "unknown"
        );
    }
}
