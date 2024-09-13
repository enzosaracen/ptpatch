use clap::Parser;
use std::error::Error;
use std::fs::OpenOptions;
use std::fs;
use std::io::Write;
use std::process::Command;
use colored::*;

include!(concat!(env!("OUT_DIR"), "/nolibc.rs"));

#[derive(Parser)]
struct Opt {
    #[arg(required = true, num_args = 1.., value_name = "FILE")]
    paths: Vec<String>,
}

enum Breakpoint {
    Expr(String),
    Presys(String),
    Postsys(String),
}

struct Patch {
    breakpoint: Breakpoint,
    body: String,
}

struct ParsedFile {
    globals: String,
    patches: Vec<Patch>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Opt::parse();
    let mut hookcnt = 0;
    let mut hook_str = String::new();
    let mut init_str = String::new();

    let mut hook_sys = false;

    for path in opts.paths {
        let parsed = parse_file(&fs::read_to_string(&path)?)?;
        hook_str.push_str(&parsed.globals);
        for patch in parsed.patches {
            hook_str.push_str(&format!(
                "void hook{}(pid_t pid, void *arg)\n{{\n\t#define regs (*(struct user_regs_struct *)arg)\n\tcur_pid = pid;\n{}\n\t#undef regs\n}}\n",
                hookcnt, patch.body));
            match patch.breakpoint {
                Breakpoint::Expr(s) => {
                    init_str.push_str(&format!("\tbkpt_add(pid, (void*){}, hook{});\n", s, hookcnt));
                },
                Breakpoint::Presys(s) => {
                    hook_sys = true;
                    init_str.push_str(&format!("\tpresys_hooks[{}] = hook{};\n", s, hookcnt));
                },
                Breakpoint::Postsys(s) => {
                    hook_sys = true;
                    init_str.push_str(&format!("\tpostsys_hooks[{}] = hook{};\n", s, hookcnt));
                },
            }
            hookcnt += 1;
        }
    }
    
    if hook_sys {
        hook_str.insert_str(0, "#define HOOK_SYSCALLS\n");
    }

    let p1 = include_str!("../../../stub/stub-p1.c");
    let p2 = include_str!("../../../stub/stub-p2.c");
    let p3 = include_str!("../../../stub/stub-p3.c");

    let mut genfile = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("stub.gen.c")?;
    genfile.write_all(format!("{}{}{}{}{}", p1, hook_str, p2, init_str, p3).as_bytes())?;
    genfile.flush()?;

    println!("stub written to stub.gen.c");
    let nolibc = std::path::Path::new(NOLIBC_PATH).canonicalize()?;

    println!("gcc -nostdlib -include {} -static -Os stub.gen.c -o stub.out -fdiagnostics-color=always", nolibc.display());
    let output = Command::new("gcc")
        .arg("-nostdlib")
        .arg("-include")
        .arg(nolibc)
        .arg("-static")
        .arg("-Os")
        .arg("stub.gen.c")
        .arg("-o")
        .arg("stub.out")
        .arg("-fdiagnostics-color=always")
        .output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err("failed to compile stub.gen.c".into());
    }
    let output = Command::new("strip")
        .arg("stub.out")
        .output()?;
    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    println!("{}", "stub successfully generated".bright_green());
    Ok(())
}

fn parse_file(content: &str) -> Result<ParsedFile, Box<dyn Error>> {
    let mut lines = content.lines();
    let mut globals = String::new();
    let mut patches = Vec::new();

    while let Some(line) = lines.next() {
        if line.trim() == "%%" {
            break;
        }
        globals.push_str(line);
        globals.push('\n');
    }

    let mut current_patch: Option<Patch> = None;
    for line in lines {
        let txt = line.trim();

        if txt.starts_with("<@") {
            if let Some(patch) = current_patch.take() {
                patches.push(patch);
            }
            let breakpoint = parse_breakpoint(txt)?;
            current_patch = Some(Patch {
                breakpoint,
                body: String::new(),
            });
        } else if txt == "@>" {
            if let Some(patch) = current_patch.take() {
                patches.push(patch);
            }
        } else if let Some(ref mut patch) = current_patch {
            patch.body.push_str(line);
            patch.body.push('\n');
        }
    }

    Ok(ParsedFile { globals, patches })
}

fn parse_breakpoint(line: &str) -> Result<Breakpoint, Box<dyn Error>> {
    let line = line.trim_start_matches("<@").trim();
    if line.starts_with("pre-syscall") || line.starts_with("post-syscall") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 1 {
            let arg = match parts[1].parse::<i32>() {
                Ok(_) => parts[1].to_string(),
                Err(_) => format!("__NR_{}", parts[1]),
            };
            if line.starts_with("pre") {
                return Ok(Breakpoint::Presys(arg));
            }
            return Ok(Breakpoint::Postsys(arg));
        }
    }

    Ok(Breakpoint::Expr(line.to_string()))
}
