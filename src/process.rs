use std::collections::HashMap;
use std::ffi::OsStr;

pub struct SpawnOptions {
    pub clear_env: bool,
    pub detach: bool,
}

#[cfg(target_os = "linux")]
pub fn spawn<S: AsRef<OsStr>>(cmd: S, args: &[String], opts: SpawnOptions) {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let mut envs = HashMap::new();
    envs.insert("TEST_VAL", "1234");

    // setup command
    let mut command = Command::new(cmd);
    for arg in args.iter() {
        command.arg(arg);
    }

    // set envs
    if opts.clear_env {
        command.env_clear();
    }
    command.envs(envs);

    if opts.detach {
        // setpgid to make the new process independent of this process
        // see: https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.process_group
        command.process_group(0);
    }

    let mut child = command.spawn().unwrap();

    if !opts.detach {
        child.wait().unwrap();
    }
}
