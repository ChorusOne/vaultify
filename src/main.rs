mod error;
mod process;
mod secrets;

fn main() {
    process::spawn(true, false)
}
