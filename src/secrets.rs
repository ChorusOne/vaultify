//! .secrets file parser
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::error::{Error, Result};

pub type SecretSpecs = BTreeMap<String, SecretSpec>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretTarget {
    Env {
        name: String,
    },
    File {
        path: PathBuf,
        mode: u32,
        create: bool,
    },
}

/// Spec of a secret parsed from a .secrets file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSpec {
    /// Where to write the resolved secret.
    pub target: SecretTarget,
    /// The mount point of the secret in vault.
    pub mount: String,
    /// The path of the secret under the mount point in vault.
    pub path: String,
    /// The actual secret key in vault.
    pub secret: String,
}

/// A resolved secret value fetched from vault.
#[derive(Clone)]
pub struct Secret {
    pub target: SecretTarget,
    pub secret: String,
}

impl Secret {
    #[inline]
    fn secret_obfuscated(&self) -> String {
        self.secret.chars().map(|_| '*').collect::<String>()
    }
}

/// Custom Debug implementation to prevent secrets from being leaked in logs
impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            r#"Secret {{ target: {:?}, secret: "{}" }}"#,
            self.target,
            self.secret_obfuscated()
        )
    }
}

impl SecretSpec {
    /// Stable key to identify this secret in logs and maps.
    pub fn name(&self) -> String {
        match &self.target {
            SecretTarget::Env { name } => name.clone(),
            SecretTarget::File { path, .. } => format!("file:{}", path.display()),
        }
    }
}

/// Loads the .secrets file and parses it
#[allow(unused)]
pub fn load<P: AsRef<Path>>(path: P) -> Result<SecretSpecs> {
    let contents = std::fs::read_to_string(path.as_ref())
        .map_err(|err| Error::IO(format!("unable to read file {:?}: {}", path.as_ref(), err)))?;
    parse(&contents)
}

/// Loads the .secrets file and parses it
pub async fn load_async<P: AsRef<Path>>(path: P) -> Result<SecretSpecs> {
    let contents = tokio::fs::read_to_string(path.as_ref())
        .await
        .map_err(|err| Error::IO(format!("unable to read file {:?}: {}", path.as_ref(), err)))?;
    parse(&contents)
}

fn parse(contents: &str) -> Result<SecretSpecs> {
    let mut specs = SecretSpecs::new();

    for (lc, raw_line) in contents.lines().enumerate() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split('|');
        let left = parts
            .next()
            .map(str::trim)
            .ok_or_else(|| Error::parse("missing source", lc, line))?;
        let right = parts
            .next()
            .map(str::trim)
            .ok_or_else(|| Error::parse("missing output target after `|`", lc, line))?;
        if parts.next().is_some() {
            return Err(Error::parse("line must contain exactly one `|`", lc, line));
        }

        let (mount, path, secret) = parse_source(left, lc, line)?;
        let target = parse_target(right, lc, line)?;
        let spec = SecretSpec {
            target,
            mount,
            path,
            secret,
        };
        let key = spec.name();
        if specs.insert(key, spec).is_some() {
            return Err(Error::parse("duplicate output target", lc, line));
        }
    }

    Ok(specs)
}

fn strip_comment(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        return "";
    }

    for (idx, c) in line.char_indices() {
        if c == '#' {
            let prefix = &line[..idx];
            if prefix.chars().last().is_some_and(char::is_whitespace) {
                return prefix.trim_end();
            }
        }
    }

    line
}

fn parse_source(source: &str, lc: usize, line: &str) -> Result<(String, String, String)> {
    if source.contains('=') {
        return Err(Error::parse(
            "legacy `NAME=...` syntax is not supported; use `... | env NAME`",
            lc,
            line,
        ));
    }

    let (path_ref, secret) = source
        .split_once('#')
        .ok_or_else(|| Error::parse("source must be in format `mount/path#secret`", lc, line))?;
    let (mount, path) = path_ref
        .split_once('/')
        .ok_or_else(|| Error::parse("source must include mount and path", lc, line))?;

    if mount.is_empty() {
        return Err(Error::parse("mount cannot be empty", lc, line));
    }
    if path.is_empty() {
        return Err(Error::parse("path cannot be empty", lc, line));
    }
    if secret.is_empty() {
        return Err(Error::parse("secret cannot be empty", lc, line));
    }

    Ok((mount.to_string(), path.to_string(), secret.to_string()))
}

fn parse_target(target: &str, lc: usize, line: &str) -> Result<SecretTarget> {
    let mut tokens = target.split_whitespace();
    let kind = tokens
        .next()
        .ok_or_else(|| Error::parse("missing output kind", lc, line))?;

    match kind {
        "env" => {
            let name = tokens
                .next()
                .ok_or_else(|| Error::parse("env target must include variable name", lc, line))?;
            if !is_valid_env_var_name(name) {
                return Err(Error::parse("invalid env var name", lc, line));
            }
            if let Some(extra) = tokens.next() {
                if extra.contains('=') {
                    return Err(Error::parse("env options are not supported", lc, line));
                }
                return Err(Error::parse("unexpected token in env target", lc, line));
            }

            Ok(SecretTarget::Env {
                name: name.to_string(),
            })
        }
        "file" => {
            let path = tokens
                .next()
                .ok_or_else(|| Error::parse("file target must include path", lc, line))?;
            if path.is_empty() {
                return Err(Error::parse("file path cannot be empty", lc, line));
            }

            let mut mode = 0o600;
            let mut create = false;
            let mut seen_mode = false;
            let mut seen_create = false;

            for token in tokens {
                let (key, value) = token
                    .split_once('=')
                    .ok_or_else(|| Error::parse("target options must be key=value", lc, line))?;
                match key {
                    "mode" => {
                        if seen_mode {
                            return Err(Error::parse("duplicate option `mode`", lc, line));
                        }
                        mode = parse_octal_mode(value, lc, line)?;
                        seen_mode = true;
                    }
                    "create" => {
                        if seen_create {
                            return Err(Error::parse("duplicate option `create`", lc, line));
                        }
                        create = parse_bool(value, lc, line)?;
                        seen_create = true;
                    }
                    _ => {
                        return Err(Error::parse(
                            &format!("unknown file option `{}`", key),
                            lc,
                            line,
                        ))
                    }
                }
            }

            Ok(SecretTarget::File {
                path: PathBuf::from(path),
                mode,
                create,
            })
        }
        _ => Err(Error::parse(
            "unknown output kind; expected `env` or `file`",
            lc,
            line,
        )),
    }
}

fn parse_octal_mode(mode: &str, lc: usize, line: &str) -> Result<u32> {
    if mode.len() != 4 || !mode.starts_with('0') || !mode.chars().all(|c| ('0'..='7').contains(&c))
    {
        return Err(Error::parse(
            "invalid mode; expected octal format like 0600",
            lc,
            line,
        ));
    }

    u32::from_str_radix(mode, 8)
        .map_err(|_| Error::parse("invalid mode; expected octal format like 0600", lc, line))
}

fn parse_bool(value: &str, lc: usize, line: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(Error::parse(
            "invalid boolean value; expected true or false",
            lc,
            line,
        )),
    }
}

fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }

    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_env_target() {
        const SECRET: &str =
            r#"secret/production/third-party#api-key | env PRODUCTION_THIRD_PARTY_API_KEY"#;

        let secrets = parse(SECRET).unwrap();
        assert_eq!(secrets.len(), 1);

        let entry = secrets.get("PRODUCTION_THIRD_PARTY_API_KEY").unwrap();
        assert_eq!(entry.mount, "secret");
        assert_eq!(entry.path, "production/third-party");
        assert_eq!(entry.secret, "api-key");
        assert!(matches!(
            entry.target,
            SecretTarget::Env { ref name } if name == "PRODUCTION_THIRD_PARTY_API_KEY"
        ));
    }

    #[test]
    fn pass_file_target_defaults() {
        const SECRET: &str = r#"secret/prod/tls#private_key | file /dev/shm/my-key"#;

        let secrets = parse(SECRET).unwrap();
        assert_eq!(secrets.len(), 1);
        let entry = secrets.get("file:/dev/shm/my-key").unwrap();
        assert!(matches!(
            entry.target,
            SecretTarget::File {
                ref path,
                mode: 0o600,
                create: false
            } if path == &PathBuf::from("/dev/shm/my-key")
        ));
    }

    #[test]
    fn pass_file_target_options() {
        const SECRET: &str =
            r#"secret/prod/tls#private_key | file /dev/shm/my-key create=true mode=0640"#;

        let secrets = parse(SECRET).unwrap();
        let entry = secrets.get("file:/dev/shm/my-key").unwrap();
        assert!(matches!(
            entry.target,
            SecretTarget::File {
                mode: 0o640,
                create: true,
                ..
            }
        ));
    }

    #[test]
    fn pass_comments_and_whitespace() {
        let secrets = parse(
            r#"
            # this is a comment
              foo/bar#baz | env BAR_BAZ   # inline comment
	secret/prod/tls#private_key | file /dev/shm/my-key	# trailing tab comment
            "#,
        )
        .unwrap();
        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains_key("BAR_BAZ"));
        assert!(secrets.contains_key("file:/dev/shm/my-key"));
    }

    #[test]
    fn fail_legacy_format() {
        assert!(parse("BAR_BAZ=foo/bar#baz").is_err());
    }

    #[test]
    fn fail_unknown_file_option() {
        assert!(parse("foo/bar#baz | file /tmp/a mod=0600").is_err());
    }

    #[test]
    fn fail_invalid_mode() {
        assert!(parse("foo/bar#baz | file /tmp/a mode=600").is_err());
    }

    #[test]
    fn fail_invalid_bool() {
        assert!(parse("foo/bar#baz | file /tmp/a create=yes").is_err());
    }

    #[test]
    fn fail_unknown_target_with_comment() {
        assert!(parse("secret/prod/service#token | something # comment").is_err());
    }

    #[test]
    fn fail_unknown_target_with_pipe_in_comment() {
        assert!(
            parse("secret/prod/service#token | something # comment | with weird chars").is_err()
        );
    }

    #[test]
    fn pass_load_file() {
        let secrets = load("tests/pass.secrets").unwrap();
        assert_eq!(secrets.len(), 4);
    }

    #[tokio::test]
    async fn pass_load_file_async() {
        let secrets = load_async("tests/pass.secrets").await.unwrap();
        assert_eq!(secrets.len(), 4);
    }
}
