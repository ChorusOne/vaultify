use std::collections::HashMap;
use std::ffi::OsStr;

use crate::secrets::Secret;

pub struct SpawnOptions {
    pub clear_env: bool,
    pub detach: bool,
}

#[cfg(target_os = "linux")]
pub fn spawn<S: AsRef<OsStr>>(cmd: S, args: &[String], secrets: &[Secret], opts: SpawnOptions) {
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
            println!(
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

    let mut child = command.spawn().unwrap();

    if !opts.detach {
        child.wait().unwrap();
    }
}
