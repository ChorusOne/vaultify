use std::ffi::{CString, OsStr};

use crate::{
    error::{Error, Result},
    secrets::Secret,
};

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
    secrets: &[Secret],
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
    let mut c_args = Vec::with_capacity(args.len());
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
        let c_var = CString::new(format!("{}={}", &secret.name, &secret.secret))?;
        if c_env.iter().any(|e| *e == c_var) {
            log::warn!(
                "env variable `{}` already exists and will be overwritten",
                secret.name
            );
        }
        c_env.push(c_var);
    }

    nix::unistd::execvpe(&c_cmd, &c_args, &c_env)
        .map_err(|err| Error::Execution(err.to_string()))?;

    Ok(())
}
