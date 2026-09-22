// SPDX-License-Identifier: AGPL-3.0-or-later

#[path = "../build_environment.rs"]
mod build_environment;

#[test]
fn implicit_native_search_and_loader_channels_are_bound() {
    let fields = build_environment::FIXED_BUILD_ENV;
    for required in [
        "COMPILER_PATH",
        "CPATH",
        "CPLUS_INCLUDE_PATH",
        "C_INCLUDE_PATH",
        "GCC_EXEC_PREFIX",
        "LIBRARY_PATH",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_ROOT_PATH",
        "DYLD_IMAGE_SUFFIX",
        "DYLD_VERSIONED_FRAMEWORK_PATH",
        "DYLD_VERSIONED_LIBRARY_PATH",
        "OBJC_INCLUDE_PATH",
        "ZERO_AR_DATE",
    ] {
        assert!(fields.contains(&required), "missing build input {required}");
    }

    let mut unique = fields.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), fields.len(), "build inputs must be unique");
}
