//! .secrets file parser
use std::path::Path;

use lazy_static::lazy_static;
use regex::Regex;

use crate::error::{Error, Result};

lazy_static! {
    static ref REGEX_V1: Regex = {
        Regex::new(r#"^(?<name>([a-zA-Z0-9_]*)=)?(?<path>[a-zA-Z0-9_\-\/]*)#(?<secret>.*)"#)
            .expect("invalid regex")
    };
}

fn load<P: AsRef<Path>>(path: P) -> Result<()> {
    // load file
    Ok(())
}

fn parse(contents: &str) -> Result<Vec<Secret>> {
    let mut secrets = Vec::new();

    // TODO: do not allow empty strings

    for (lc, line) in contents.lines().enumerate() {
        if let Some(capture) = REGEX_V1.captures(line) {
            let name = capture.name("name").map(|c| c.as_str().to_string());
            if let Some(name) = &name {
                if let Some(c) = name.chars().next() {
                    // https://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap08.html
                    if c.is_numeric() {
                        return Err(Error::Parse(format!(
                            "env vars must not start with a number (line {}: {})",
                            lc, line
                        )));
                    }
                } else {
                    return Err(Error::Parse(format!(
                        "path cannot be empty (line {}: {})",
                        lc, line
                    )));
                }
            }
            let path = capture
                .name("path")
                .ok_or_else(|| Error::Parse(format!("missing path (line {}: {})", lc, line)))?
                .as_str()
                .to_string();
            if path.is_empty() {
                return Err(Error::Parse(format!(
                    "path cannot be empty (line {}: {})",
                    lc, line
                )));
            }
            let secret = capture
                .name("secret")
                .ok_or_else(|| Error::Parse(format!("missing secret (line {}: {})", lc, line)))?
                .as_str()
                .to_string();
            if secret.is_empty() {
                return Err(Error::Parse(format!(
                    "secret cannot be empty (line {}: {})",
                    lc, line
                )));
            }
            secrets.push(Secret { name, path, secret })
        } else {
            return Err(Error::Parse(format!(
                "unable to parse line {}: {}",
                lc, line
            )));
        }
    }

    Ok(secrets)
}

pub struct Secret {
    pub name: Option<String>,
    pub path: String,
    pub secret: String,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        const SECRET: &str = r#"foo#bar
foo/bar#baz
FOO=bar#baz
BAR=foo/baz#quix
single_underscore=foo/single#underscore
double__underscore=foo/double#underscore
_leading_underscore=foo/double#underscore"#;

        let secrets = parse(SECRET).unwrap();
        assert_eq!(secrets.len(), 7);
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
}
