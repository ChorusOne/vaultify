#[cfg(target_os = "linux")]
pub fn spawn(clear_env: bool, detach: bool) {
    use std::collections::HashMap;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // TODO: parse command from input and tokenize it

    let mut envs = HashMap::new();
    envs.insert("TEST_VAL", "1234");

    // setup command
    let mut command = Command::new("env");
    //command.arg("\"$TEST_VAL\"");

    // set envs
    if clear_env {
        command.env_clear();
    }
    command.envs(envs);

    if detach {
        // setpgid to make the new process independent of this process
        // see: https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.process_group
        command.process_group(0);
    }

    let mut child = command.spawn().unwrap();

    if !detach {
        child.wait().unwrap();
    }
}
