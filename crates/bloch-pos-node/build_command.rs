// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

/// Split the restricted command form accepted for configured build tools.
/// Quotes and backslash escaping are recognized, but no expansion, pipelines
/// or shell substitution is attempted. An ambiguous command remains bound by
/// its environment value and simply contributes no guessed executable hash.
pub(crate) fn configured_command_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut chars = command.trim().chars().peekable();
    while let Some(ch) = chars.next() {
        if escaped {
            word.push(ch);
            escaped = false;
        } else if ch == '\\' {
            match chars.peek() {
                Some(next)
                    if next.is_whitespace() || *next == '\\' || *next == '\'' || *next == '"' =>
                {
                    escaped = true;
                }
                Some(_) => word.push(ch),
                None => return None,
            }
        } else if let Some(open) = quote {
            if ch == open {
                quote = None;
            } else {
                word.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(ch);
        }
    }
    if escaped || quote.is_some() {
        return None;
    }
    if !word.is_empty() {
        words.push(word);
    }
    (!words.is_empty()).then_some(words)
}

/// Wrappers with a documented `wrapper compiler ...` direct form. We only
/// follow the next word when it is immediately present and not an option;
/// wrapper-specific option parsing would risk fingerprinting the wrong file.
pub(crate) fn delegated_compiler(words: &[String]) -> Option<&str> {
    let wrapper = Path::new(words.first()?)
        .file_name()?
        .to_str()?
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
    if !["ccache", "distcc", "icecc", "sccache"].contains(&wrapper.as_str()) {
        return None;
    }
    let delegate = words.get(1)?;
    (!delegate.starts_with('-')).then_some(delegate.as_str())
}

/// Extract the last explicit `-C linker=...` selection, which is the one rustc
/// applies. Cargo's encoded form uses unit separators and does not need shell
/// parsing; plain RUSTFLAGS uses the same restricted tokenizer as tool values.
pub(crate) fn rustflags_linker(flags: &str, encoded: bool) -> Option<String> {
    let words = if encoded {
        flags
            .split('\u{1f}')
            .filter(|word| !word.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        configured_command_words(flags)?
    };
    let mut linker = None;
    let mut index = 0usize;
    while index < words.len() {
        let word = &words[index];
        if let Some(value) = word.strip_prefix("-Clinker=") {
            if !value.is_empty() {
                linker = Some(value.to_owned());
            }
        } else if word == "-C" {
            if let Some(value) = words
                .get(index.saturating_add(1))
                .and_then(|next| next.strip_prefix("linker="))
                .filter(|value| !value.is_empty())
            {
                linker = Some(value.to_owned());
                index = index.saturating_add(1);
            }
        }
        index = index.saturating_add(1);
    }
    linker
}

fn environment_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// Extract a command and any effective PATH override from a direct or
/// `env`-wrapped command line. Unknown options and a bare command after PATH
/// was cleared fail closed instead of fingerprinting a same-named executable
/// from the build script's different environment.
pub(crate) fn command_from_env(output: &str) -> Option<(Vec<String>, Option<String>)> {
    let words = configured_command_words(output)?;
    let first = words.first()?;
    let is_env = Path::new(first)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("env") || name.eq_ignore_ascii_case("env.exe")
        });
    if !is_env {
        return Some((words, None));
    }

    let mut index = 1usize;
    let mut path_cleared = false;
    let mut path_override = None;
    while index < words.len() {
        match words[index].as_str() {
            "-u" | "--unset" => {
                let name = words.get(index.checked_add(1)?)?;
                if name.eq_ignore_ascii_case("PATH") {
                    path_cleared = true;
                    path_override = None;
                }
                index = index.checked_add(2)?;
            }
            "-i" | "--ignore-environment" => {
                path_cleared = true;
                path_override = None;
                index = index.saturating_add(1);
            }
            word if word.starts_with("--unset=") => {
                if word["--unset=".len()..].eq_ignore_ascii_case("PATH") {
                    path_cleared = true;
                    path_override = None;
                }
                index = index.saturating_add(1);
            }
            word if word.starts_with('-') => return None,
            word if environment_assignment(word) => {
                let (name, value) = word.split_once('=')?;
                if name.eq_ignore_ascii_case("PATH") {
                    path_cleared = false;
                    path_override = Some(value.to_owned());
                }
                index = index.saturating_add(1);
            }
            command => {
                let has_path = Path::new(command).components().count() > 1;
                if !has_path && path_cleared && path_override.is_none() {
                    return None;
                }
                return Some((words[index..].to_vec(), path_override));
            }
        }
    }
    None
}

/// Extract the executable and effective PATH from stable rustc
/// `--print link-args` output. The remaining linker arguments are intentionally
/// ignored after the shared command parser has identified their boundary.
pub(crate) fn linker_from_printed_args(output: &str) -> Option<(String, Option<String>)> {
    let words = configured_command_words(output)?;
    let first = words.first()?;
    let is_env = Path::new(first)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("env") || name.eq_ignore_ascii_case("env.exe")
        });
    if is_env {
        let (command, search_path) = command_from_env(output)?;
        return Some((command.first()?.clone(), search_path));
    }

    // Linux rustc prints the link command as POSIX leading assignments
    // (`LC_ALL=... PATH=... VSLANG=... "cc" ...`) without an `env` command.
    // These words describe the environment rustc actually gave the linker;
    // they are not accepted by `command_from_env` for configured tool values,
    // where Cargo would treat a leading assignment as an executable name.
    let mut index = 0usize;
    let mut search_path = None;
    while let Some(word) = words.get(index).filter(|word| environment_assignment(word)) {
        let (name, value) = word.split_once('=')?;
        if name.eq_ignore_ascii_case("PATH") {
            search_path = Some(value.to_owned());
        }
        index = index.saturating_add(1);
    }
    Some((words.get(index)?.clone(), search_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_words_preserve_quoted_paths_and_reject_ambiguous_quotes() {
        assert_eq!(
            configured_command_words("'/opt/cache wrapper' clang -O2"),
            Some(vec![
                "/opt/cache wrapper".into(),
                "clang".into(),
                "-O2".into()
            ])
        );
        assert_eq!(
            configured_command_words(r"C:\toolchain\cc.exe -O2"),
            Some(vec![r"C:\toolchain\cc.exe".into(), "-O2".into()])
        );
        assert_eq!(configured_command_words("sccache 'clang"), None);
        assert_eq!(configured_command_words("ccache clang\\"), None);
        assert_eq!(configured_command_words("   "), None);
    }

    #[test]
    fn only_unambiguous_known_wrapper_delegation_is_followed() {
        for wrapper in ["ccache", "distcc", "icecc", "sccache", "sccache.exe"] {
            let words = vec![wrapper.into(), "clang".into(), "-O2".into()];
            assert_eq!(delegated_compiler(&words), Some("clang"));
        }
        assert_eq!(
            delegated_compiler(&["/usr/bin/clang".into(), "-O2".into()]),
            None
        );
        assert_eq!(
            delegated_compiler(&["sccache".into(), "--start-server".into()]),
            None
        );
        assert_eq!(delegated_compiler(&["sccache".into()]), None);
    }

    #[test]
    fn rustflags_linker_uses_the_effective_last_selection() {
        assert_eq!(
            rustflags_linker("-C linker='/opt/tool chain/ld' -Copt-level=2", false),
            Some("/opt/tool chain/ld".into())
        );
        assert_eq!(
            rustflags_linker("-Clinker=old\u{1f}-C\u{1f}linker=new", true),
            Some("new".into())
        );
        assert_eq!(rustflags_linker("-C linker=", false), None);
        assert_eq!(rustflags_linker("-C target-cpu=native", false), None);
        assert_eq!(rustflags_linker("-C linker='unterminated", false), None);
    }

    #[test]
    fn printed_link_args_identify_direct_and_env_wrapped_linkers() {
        assert_eq!(
            linker_from_printed_args(r#""/usr/bin/clang" "one.o" -o out"#),
            Some(("/usr/bin/clang".into(), None))
        );
        assert_eq!(
            linker_from_printed_args(
                r#"env -u SDKROOT LC_ALL="C" PATH="/tool bin:/usr/bin" "cc" one.o"#,
            ),
            Some(("cc".into(), Some("/tool bin:/usr/bin".into())))
        );
        assert_eq!(linker_from_printed_args("env -u PATH cc one.o"), None);
        assert_eq!(linker_from_printed_args("env -i cc one.o"), None);
        assert_eq!(
            linker_from_printed_args("env -i PATH=/reviewed/bin cc one.o"),
            Some(("cc".into(), Some("/reviewed/bin".into())))
        );
        assert_eq!(
            linker_from_printed_args("env -u PATH /usr/bin/cc one.o"),
            Some(("/usr/bin/cc".into(), None))
        );
        assert_eq!(linker_from_printed_args("env --unknown cc one.o"), None);
        assert_eq!(linker_from_printed_args("env -u SDKROOT"), None);
        assert_eq!(linker_from_printed_args(""), None);
        assert_eq!(
            linker_from_printed_args(
                r#"LC_ALL="C" PATH="/rust/bin:/usr/bin:/bin" VSLANG="1033" "cc" "symbols.o" -o "probe""#,
            ),
            Some(("cc".into(), Some("/rust/bin:/usr/bin:/bin".into())))
        );
    }

    #[test]
    fn env_wrapped_build_tools_preserve_arguments_and_effective_path() {
        assert_eq!(
            command_from_env("env PATH=/reviewed/bin sccache clang -O2"),
            Some((
                vec!["sccache".into(), "clang".into(), "-O2".into()],
                Some("/reviewed/bin".into()),
            ))
        );
        assert_eq!(
            command_from_env("ccache clang -O2"),
            Some((vec!["ccache".into(), "clang".into(), "-O2".into()], None))
        );
        assert_eq!(command_from_env("env --unknown cc"), None);
        assert_eq!(command_from_env("env -u PATH cc"), None);
    }
}
