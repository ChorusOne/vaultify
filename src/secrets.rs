//! .secrets file parser
use std::path::Path;

use lazy_static::lazy_static;
use regex::Regex;

use crate::error::{Error, Result};

lazy_static! {
    static ref REGEX_V1: Regex = {
        Regex::new(r#"^((?<name>[a-zA-Z0-9_]*)=)?((?<mount>[a-zA-Z0-9_\-\@]*)\/)(?<path>[a-zA-Z0-9_\-\/\@]*)#(?<secret>.*)"#)
            .expect("invalid regex")
    };
}

/// Spec of a secret parsed from a .secrets file.
#[derive(Debug)]
pub struct SecretSpec {
    /// The name of the environment variable (optional).
    pub(self) name: Option<String>,
    /// The mount point of the secret in vault.
    pub mount: String,
    /// The path of the secret under the mount point in vault.
    pub path: String,
    /// The actual secret key in vault.
    pub secret: String,
}

/// A secret.
pub struct Secret {
    /// The name of the environment variable.
    pub name: String,
    /// The actual secret value
    pub secret: String,
}

impl Secret {
    #[inline]
    fn secret_obfuscated(&self) -> String {
        self.secret.chars().map(|_c| '*').collect::<String>()
    }
}

/// Custom Debug implementation to prevent secrets from being leaked in logs
impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            r#"Secret {{ name: "{}", secret: "{}" }}"#,
            self.name,
            self.secret_obfuscated()
        )
    }
}

impl SecretSpec {
    /// Returns the configured name or a generated name based on path and secret.
    pub fn name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            self.path
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
                + "_"
                + &self
                    .secret
                    .chars()
                    .map(|c| {
                        if c.is_alphanumeric() {
                            c.to_ascii_uppercase()
                        } else {
                            '_'
                        }
                    })
                    .collect::<String>()
        })
    }
}

/// Loads the .secrets file and parses it
#[allow(unused)]
pub fn load<P: AsRef<Path>>(path: P) -> Result<Vec<SecretSpec>> {
    let contents = std::fs::read_to_string(path.as_ref())
        .map_err(|err| Error::IO(format!("unable to read file {:?}: {}", path.as_ref(), err)))?;
    parse(&contents)
}

/// Loads the .secrets file and parses it
pub async fn load_async<P: AsRef<Path>>(path: P) -> Result<Vec<SecretSpec>> {
    let contents = tokio::fs::read_to_string(path.as_ref())
        .await
        .map_err(|err| Error::IO(format!("unable to read file {:?}: {}", path.as_ref(), err)))?;
    parse(&contents)
}

fn parse(contents: &str) -> Result<Vec<SecretSpec>> {
    let mut secrets = Vec::new();

    for (lc, line) in contents.lines().enumerate() {
        // skip empty lines
        if line.is_empty() || !line.chars().any(|c| !c.is_whitespace()) {
            continue;
        }

        // parse regex
        if let Some(capture) = REGEX_V1.captures(line) {
            let name = capture.name("name").map(|c| c.as_str().to_string());
            if let Some(name) = &name {
                if let Some(c) = name.chars().next() {
                    // https://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap08.html
                    if c.is_numeric() {
                        return Err(Error::parse(
                            "env vars must not start with a number",
                            lc,
                            line,
                        ));
                    }
                } else {
                    return Err(Error::parse("name cannot be empty", lc, line));
                }
            }
            let mount = capture
                .name("mount")
                .ok_or_else(|| Error::parse("missing mount", lc, line))?
                .as_str()
                .to_string();
            if mount.is_empty() {
                return Err(Error::parse("mount cannot be empty", lc, line));
            }
            let path = capture
                .name("path")
                .ok_or_else(|| Error::parse("missing path", lc, line))?
                .as_str()
                .to_string();
            if path.is_empty() {
                return Err(Error::parse("path cannot be empty", lc, line));
            }
            let secret = capture
                .name("secret")
                .ok_or_else(|| Error::parse("missing secret", lc, line))?
                .as_str()
                .to_string();
            if secret.is_empty() {
                return Err(Error::parse("secret cannot be empty", lc, line));
            }
            secrets.push(SecretSpec {
                name,
                mount,
                path,
                secret,
            })
        } else {
            return Err(Error::parse("unable to parse line", lc, line));
        }
    }

    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_regex_compile() {
        assert!(!REGEX_V1.to_string().is_empty())
    }

    #[test]
    fn pass_v1_simple() {
        const SECRET: &str = r#"secret/production/third-party#api-key"#;

        let secrets = parse(SECRET).unwrap();
        assert_eq!(secrets.len(), 1);

        let entry = secrets.first().unwrap();
        assert_eq!(entry.mount, "secret");
        assert_eq!(entry.path, "production/third-party");
        assert_eq!(entry.secret, "api-key");
        assert_eq!(entry.name(), "PRODUCTION_THIRD_PARTY_API_KEY")
    }

    #[test]
    fn pass_v1_1() {
        const SECRET: &str = r#"production/another-third-party#bla
production/another-third-party/another/path#bla
hackathon=production/another-third-party#bla3
hackathon=production/another-third-party#bla"#;

        let secrets = parse(SECRET).unwrap();
        assert_eq!(secrets.len(), 4);
    }

    #[test]
    fn pass_v1_2() {
        const SECRET: &str = r#"mnt/foo#bar
foo/bar#baz
FOO=mnt/bar#baz
BAR=foo/baz#quix
single_underscore=foo/single#underscore
double__underscore=foo/double#underscore
_leading_underscore=foo/double#underscore"#;

        let secrets = parse(SECRET).unwrap();
        assert_eq!(secrets.len(), 7);
    }

    #[test]
    fn pass_v1_variables() {
        const SECRET: &str = r#"BAR_BAZ=foo/bar#baz"#;
        let secrets = parse(SECRET).unwrap();
        assert_eq!(secrets.len(), 1);

        let entry = secrets.first().unwrap();
        assert_eq!(entry.name.as_deref().unwrap(), "BAR_BAZ");
        assert_eq!(entry.mount, "foo");
        assert_eq!(entry.path, "bar");
        assert_eq!(entry.secret, "baz");
        assert_eq!(entry.name(), "BAR_BAZ")
    }

    #[test]
    fn pass_v1_special_chars() {
        const SECRET: &str = r#"mnt/foob@ar#baz"#;

        let secrets = parse(SECRET).unwrap();
        assert_eq!(secrets.len(), 1);

        let entry = secrets.first().unwrap();
        assert!(entry.name.is_none());
        assert_eq!(entry.mount, "mnt");
        assert_eq!(entry.path, "foob@ar");
        assert_eq!(entry.secret, "baz");
        assert_eq!(entry.name(), "FOOB_AR_BAZ")
    }

    #[test]
    fn fail_v1_ambigious() {
        const SECRET: &str = r#"foo#bar/baz#quix
FOO=foo=bar/baz#quix"#;

        assert!(parse(SECRET).is_err());
    }

    #[test]
    fn fail_v1_wrong_envvar_name() {
        const SECRET: &str = r#"5_shouldnt_lead_with_numbers=testing#secret"#;

        assert!(parse(SECRET).is_err());
    }

    #[test]
    fn pass_v1_empty() {
        let secrets = parse("").unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn pass_v1_empty_line() {
        let secrets = parse(
            r#"foo/bar#baz

 
FOO=mnt/bar#baz"#,
        )
        .unwrap();
        assert_eq!(secrets.len(), 2);
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
