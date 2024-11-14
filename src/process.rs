use std::ffi::OsStr;

use crate::{error::Result, secrets::Secret};

/// Additional spawn options for the child process
pub struct SpawnOptions {
    /// Clear the environment of the spawned process.
    ///
    /// # Remarks:
    ///
    /// If this is set to false, all environment variables of the current process are inherited by
    /// the child process as well.
    pub clear_env: bool,
    /// Detach the child process from this process.
    /// When set to `true` the child process will continue running while the `vaultify` process
    /// finishes.
    pub detach: bool,
}

#[cfg(target_os = "linux")]
pub fn spawn<S: AsRef<OsStr>>(
    cmd: S,
    args: &[String],
    secrets: &[Secret],
    opts: SpawnOptions,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // setup command
    let mut command = Command::new(cmd);
    for arg in args.iter() {
        command.arg(arg);
    }

    // set envs
    if opts.clear_env {
        command.env_clear();
    }

    for secret in secrets.iter() {
        if !opts.clear_env && std::env::var(&secret.name).is_ok() {
            log::warn!(
                "env variable `{}` already exists and will be overwritten",
                secret.name
            );
        }
        command.env(&secret.name, &secret.secret);
    }

    if opts.detach {
        // setpgid to make the new process independent of this process
        command.process_group(0);
    }

    let mut child = command.spawn()?;

    if !opts.detach {
        child.wait().unwrap();
    }

    Ok(())
}
