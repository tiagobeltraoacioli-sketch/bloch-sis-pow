// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact non-source environment inputs to the build identity.

use std::path::{Path, PathBuf};

/// Build knobs whose values can change generated machine code without changing
/// the source tree. Values are hashed, never published verbatim. Prefixes cover
/// Cargo's target/profile-specific forms and the C toolchain used by PQClean.
pub(crate) const FIXED_BUILD_ENV: &[&str] = &[
    "AR",
    "ARFLAGS",
    "BINDGEN_EXTRA_CLANG_ARGS",
    "CARGO",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_INCREMENTAL",
    "CC",
    "CC_FORCE_DISABLE",
    "CC_KNOWN_WRAPPER_CUSTOM",
    "CC_SHELL_ESCAPED_FLAGS",
    "CFLAGS",
    "COMPILER_PATH",
    "CPATH",
    "CPLUS_INCLUDE_PATH",
    "CPPFLAGS",
    "CRATE_CC_NO_DEFAULTS",
    "CXXSTDLIB",
    "C_INCLUDE_PATH",
    "DEBUG",
    "DEP_WASM32_UNKNOWN_UNKNOWN_OPENBSD_LIBC_INCLUDE",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_IMAGE_SUFFIX",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_ROOT_PATH",
    "DYLD_VERSIONED_FRAMEWORK_PATH",
    "DYLD_VERSIONED_LIBRARY_PATH",
    "GCC_EXEC_PREFIX",
    "HOST_AR",
    "HOST_ARFLAGS",
    "HOST_CC",
    "HOST_CFLAGS",
    "HOST_CPPFLAGS",
    "HOST_CXX",
    "HOST_CXXFLAGS",
    "HOST_CXXSTDLIB",
    "HOST_RANLIB",
    "HOST_RANLIBFLAGS",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LIBRARY_PATH",
    "MACOSX_DEPLOYMENT_TARGET",
    "OBJC_INCLUDE_PATH",
    "OPT_LEVEL",
    "RANLIB",
    "RANLIBFLAGS",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTC_LINKER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "RUSTFLAGS",
    "SDKROOT",
    "SOURCE_DATE_EPOCH",
    "TARGET_AR",
    "TARGET_ARFLAGS",
    "TARGET_CC",
    "TARGET_CFLAGS",
    "TARGET_CPPFLAGS",
    "TARGET_CXX",
    "TARGET_CXXFLAGS",
    "TARGET_CXXSTDLIB",
    "TARGET_RANLIB",
    "TARGET_RANLIBFLAGS",
    "WASI_SDK_DIR",
    "ZERO_AR_DATE",
];

/// Cargo prepends its profile output directories to the platform's dynamic
/// loader search path before it starts a build script. The absolute target
/// directory is workspace scratch space, not a build input: two clean target
/// directories contain the same artifacts at different paths. Keep the
/// relative location and ordering while removing only that Cargo-owned
/// absolute prefix. External loader entries remain byte-for-byte significant.
pub(crate) fn canonical_environment_value(
    key: &str,
    value: &str,
    out_dir: Option<&Path>,
) -> String {
    if !matches!(key, "LD_LIBRARY_PATH" | "DYLD_FALLBACK_LIBRARY_PATH") {
        return value.to_owned();
    }
    let Some(out_dir) = out_dir else {
        return value.to_owned();
    };
    let Some(package_build_dir) = out_dir.parent() else {
        return value.to_owned();
    };
    let Some(build_dir) = package_build_dir.parent() else {
        return value.to_owned();
    };
    if build_dir.file_name() != Some(std::ffi::OsStr::new("build")) {
        return value.to_owned();
    }
    let Some(profile_root) = build_dir.parent() else {
        return value.to_owned();
    };

    let entries = std::env::split_paths(value).map(|entry| {
        let Ok(relative) = entry.strip_prefix(profile_root) else {
            return entry;
        };
        let mut canonical = PathBuf::from("__bloch_cargo_profile_output__");
        if !relative.as_os_str().is_empty() {
            canonical.push(relative);
        }
        canonical
    });
    std::env::join_paths(entries)
        .ok()
        .and_then(|joined| joined.into_string().ok())
        .unwrap_or_else(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(paths: &[PathBuf]) -> String {
        std::env::join_paths(paths)
            .expect("join fixture paths")
            .into_string()
            .expect("fixture paths are Unicode")
    }

    #[test]
    fn cargo_loader_paths_are_independent_of_the_target_directory() {
        let t1 = Path::new("/scratch/t1/release/build/node-hash/out");
        let t2 = Path::new("/scratch/t2/release/build/node-hash/out");
        let first = joined(&[
            PathBuf::from("/scratch/t1/release"),
            PathBuf::from("/scratch/t1/release/deps"),
            PathBuf::from("/external/toolchain/lib"),
        ]);
        let second = joined(&[
            PathBuf::from("/scratch/t2/release"),
            PathBuf::from("/scratch/t2/release/deps"),
            PathBuf::from("/external/toolchain/lib"),
        ]);
        for key in ["LD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"] {
            assert_eq!(
                canonical_environment_value(key, &first, Some(t1)),
                canonical_environment_value(key, &second, Some(t2)),
            );
        }
    }

    #[test]
    fn external_loader_paths_and_their_order_remain_significant() {
        let out = Path::new("/scratch/t1/release/build/node-hash/out");
        let cargo = PathBuf::from("/scratch/t1/release/deps");
        let a = PathBuf::from("/external/a");
        let b = PathBuf::from("/external/b");
        let external_change = joined(&[cargo.clone(), a.clone()]);
        let other_external = joined(&[cargo.clone(), b.clone()]);
        let first_order = joined(&[cargo.clone(), a.clone(), b.clone()]);
        let second_order = joined(&[cargo, b, a]);

        assert_ne!(
            canonical_environment_value("DYLD_FALLBACK_LIBRARY_PATH", &external_change, Some(out),),
            canonical_environment_value("DYLD_FALLBACK_LIBRARY_PATH", &other_external, Some(out),),
        );
        assert_ne!(
            canonical_environment_value("LD_LIBRARY_PATH", &first_order, Some(out)),
            canonical_environment_value("LD_LIBRARY_PATH", &second_order, Some(out)),
        );
    }

    #[test]
    fn unrelated_environment_values_are_not_rewritten() {
        let out = Path::new("/scratch/t1/release/build/node-hash/out");
        let value = "/scratch/t1/release/deps";
        assert_eq!(
            canonical_environment_value("LIBRARY_PATH", value, Some(out)),
            value,
        );
        assert_eq!(
            canonical_environment_value("LD_LIBRARY_PATH", value, None),
            value,
        );
    }
}
