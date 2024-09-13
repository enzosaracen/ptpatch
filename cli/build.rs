use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let root = env::var("CARGO_MANIFEST_DIR").unwrap();
    let nolibc = PathBuf::from(&root).join("../nolibc/nolibc.h");
    let out = env::var("OUT_DIR").unwrap();
    let dest = PathBuf::from(out).join("nolibc.rs");
    let mut f = File::create(&dest).unwrap();
    write!(f,
        "pub const NOLIBC_PATH: &str = \"{}\";",
        nolibc.to_str().unwrap()
    ).unwrap();
}
