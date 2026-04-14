use std::ffi::{CString, OsStr};

use crate::error::{Error, Result};

/// Environment variable passed to the spawned command.
pub struct EnvSecret {
    pub name: String,
    pub secret: String,
}

/// Additional spawn options for the child process
pub struct SpawnOptions {
    /// Clear the environment of the spawned process.
    ///
    /// # Remarks:
    ///
    /// If this is set to false, all environment variables of the current process are inherited by
    /// the child process as well.
    pub clear_env: bool,
}

/// Replaces the current process image with the specified process.
///
/// # Safety
///
/// This function is only safe if no other threads are running.
#[cfg(target_os = "linux")]
pub unsafe fn spawn<S: AsRef<OsStr>>(
    cmd: S,
    args: &[String],
    secrets: &[EnvSecret],
    opts: SpawnOptions,
) -> Result<()> {
    // convert cmd
    let c_cmd = CString::new(cmd.as_ref().to_str().ok_or_else(|| {
        Error::Conversion(format!(
            "{:?} cannot be convert to a c-string",
            cmd.as_ref()
        ))
    })?)?;

    // convert args
    let mut c_args = Vec::with_capacity(args.len() + 1);
    c_args.push(c_cmd.clone());
    for arg in args.iter() {
        c_args.push(CString::new(arg.as_str())?);
    }

    // generate env
    let mut c_env = if !opts.clear_env {
        // copy over current env to c_env
        let mut r = Vec::with_capacity(secrets.len());
        for (key, value) in std::env::vars_os() {
            if let Some(key) = key.to_str() {
                if let Some(value) = value.to_str() {
                    r.push(CString::new(format!("{}={}", key, value))?);
                } else {
                    log::warn!(
                        "invalid unicode in environment variable {}={:?}",
                        key,
                        value
                    );
                }
            } else {
                log::warn!(
                    "invalid unicode in environment variable {:?}={:?}",
                    key,
                    value
                );
            }
        }
        r
    } else {
        // create empty env
        Vec::with_capacity(secrets.len())
    };

    // add secrets to env
    for secret in secrets.iter() {
        let key_prefix = format!("{}=", secret.name);
        let c_var = CString::new(format!("{}={}", &secret.name, &secret.secret))?;
        let prev_len = c_env.len();
        c_env.retain(|e| !e.as_bytes().starts_with(key_prefix.as_bytes()));
        if c_env.len() != prev_len {
            log::warn!(
                "env variable `{}` already exists and will be overwritten",
                secret.name
            );
        }
        c_env.push(c_var);
        debug_assert_eq!(
            c_env
                .iter()
                .filter(|e| e.as_bytes().starts_with(key_prefix.as_bytes()))
                .count(),
            1,
            "secret env merge must leave exactly one value per key"
        );
    }

    nix::unistd::execvpe(&c_cmd, &c_args, &c_env)
        .map_err(|err| Error::Execution(err.to_string()))?;

    Ok(())
}
