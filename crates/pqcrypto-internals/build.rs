extern crate cc;
extern crate dunce;

use std::env;
use std::path::Path;

fn main() {
    let includepath = dunce::canonicalize(Path::new("include")).unwrap();
    println!("cargo:includepath={}", includepath.to_str().unwrap());

    let cfiledir = Path::new("cfiles");
    let common_files = vec![
        cfiledir.join("fips202.c"),
        cfiledir.join("aes.c"),
        cfiledir.join("sha2.c"),
        cfiledir.join("nistseedexpander.c"),
        cfiledir.join("sp800-185.c"),
    ];

    println!("cargo:rerun-if-changed=cfiles/");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");

    let mut build = cc::Build::new();

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "wasi" {
        let wasi_sdk_path =
            &std::env::var("WASI_SDK_DIR").expect("missing environment variable: WASI_SDK_DIR");
        build.flag(format!("--sysroot={wasi_sdk_path}").as_str());
    }

    build.include(&includepath);

    // The freestanding openbsd-libc headers are ONLY for wasm32-unknown-unknown
    // (which has no libc). On wasm32-wasip1/wasi the wasi-sysroot (added via
    // --sysroot above) already provides libc; mixing in the openbsd headers there
    // causes duplicate-typedef errors (sys/types.h __suseconds_t). Native builds
    // never take either branch. Skipping this on wasi lets the mobile wallet WASM
    // build target wasi cleanly.
    if target_os != "wasi" {
        if let Some(libc) = std::env::var_os("DEP_WASM32_UNKNOWN_UNKNOWN_OPENBSD_LIBC_INCLUDE") {
            build.include(libc);
            println!("cargo::rustc-link-lib=wasm32-unknown-unknown-openbsd-libc");
        }
    }

    build.files(common_files).compile("pqclean_common");
    println!("cargo:rustc-link-lib=pqclean_common");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let mut builder = cc::Build::new();

    if target_os == "wasi" {
        let wasi_sdk_path =
            &std::env::var("WASI_SDK_DIR").expect("missing environment variable: WASI_SDK_DIR");
        builder.flag(format!("--sysroot={wasi_sdk_path}").as_str());
    }

    if target_arch == "x86" || target_arch == "x86_64" {
        if target_env == "msvc" {
            builder.flag("/arch:AVX2");
        } else {
            builder.flag("-mavx2");
        }
        builder
            .file(
                cfiledir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
        println!("cargo:rustc-link-lib=keccak4x")
    } else if target_arch == "aarch64" && target_env != "msvc" {
        // The two-way Keccak has two permutations, chosen at COMPILE time in
        // `fips202x2.c` and `feat.S` by the same condition
        // (`(__APPLE__ && __ARM_FEATURE_CRYPTO) || __ARM_FEATURE_SHA3`): the
        // `f1600x2` assembly, which uses the ARMv8.2 SHA3 instructions
        // (`eor3`, `rax1`, `xar`), or portable NEON intrinsics. Nothing
        // checks the CPU at run time, and the ML-DSA / ML-KEM AArch64
        // backends call this code unconditionally.
        //
        // Upstream passed `-march=armv8.2-a+sha3` for every aarch64 target,
        // which selects the assembly everywhere. On a CPU without FEAT_SHA3
        // (Cortex-A53/A72/A76, Neoverse N1: most aarch64 Linux servers and
        // boards) the first ML-DSA or ML-KEM call then dies with SIGILL
        // (security review CRY-13).
        //
        // Every Apple Silicon CPU has FEAT_SHA3, so Apple targets keep the
        // assembly. Every other aarch64 target is built for the ARMv8-A
        // baseline, with the feature macro undefined in case the toolchain
        // default or CFLAGS define it: the NEON permutation is compiled,
        // `feat.S` assembles to nothing, and no SHA3 instruction exists in
        // the object. Keccak's output is identical on both paths; only
        // speed differs on CPUs that do have the extension. (A builder who
        // passes a CPU-specific `-mcpu=` in CFLAGS has chosen the target
        // CPU; the compiler may then use its instructions, as in any C.)
        let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
        if target_vendor == "apple" {
            builder.flag("-march=armv8.2-a+sha3");
        } else {
            builder.flag("-march=armv8-a").flag("-U__ARM_FEATURE_SHA3");
        }
        builder
            .file(cfiledir.join("keccak2x").join("fips202x2.c"))
            .file(cfiledir.join("keccak2x").join("feat.S"))
            .compile("keccak2x");
        println!("cargo:rustc-link-lib=keccak2x")
    }
}
