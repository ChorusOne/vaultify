#[cfg(target_os = "linux")]
fn spawn_process(detach: bool) {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // TODO: parse command from input and tokenize it
    let mut command = Command::new("sleep");
    command.arg("10");

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

fn main() {
    spawn_process(false)
}
