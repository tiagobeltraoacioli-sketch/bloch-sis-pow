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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_words_preserve_quoted_paths_and_reject_ambiguous_quotes() {
        assert_eq!(
            configured_command_words("'/opt/cache wrapper' clang -O2"),
            Some(vec!["/opt/cache wrapper".into(), "clang".into(), "-O2".into()])
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
        assert_eq!(delegated_compiler(&["sccache".into(), "--start-server".into()]), None);
        assert_eq!(delegated_compiler(&["sccache".into()]), None);
    }
}
