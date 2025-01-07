use clap::Parser;
use std::error::Error;
use std::fs::OpenOptions;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use colored::*;

include!(concat!(env!("OUT_DIR"), "/paths.rs"));

#[derive(Parser)]
struct Opt {
    #[arg(required = true, num_args = 1.., value_name = "PATCH FILE")]
    paths: Vec<String>,
    #[arg(short = 'e', long = "embed", value_name = "EXECUTABLE")]
    embed: Option<String>,
}

enum Breakpoint {
    Expr(String),
    Presys(Vec<String>),
    Postsys(Vec<String>),
    Fork(),
    Status(),
}

struct Patch {
    breakpoint: Breakpoint,
    body: String,
}

struct ParsedFile {
    globals: String,
    patches: Vec<Patch>,
}

fn run_command(base: &str, args: &[&str], err: &str) -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::new(base);
    cmd.args(args);

    println!("{:?}", cmd);
    let output = cmd.output()?;

    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return Err(err.into());
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    let mut hookcnt = 0;
    let mut hook_str = String::new();
    let mut init_str = String::new();
    let mut seen_fork = false;
    let mut seen_status = false;
    let mut hook_sys = false;

    for path in opt.paths {
        let content = fs::read_to_string(&path)?;
        let parsed = parse_file(&content)?;
        hook_str.push_str(&parsed.globals);
        for patch in parsed.patches {
            if let Breakpoint::Fork() = patch.breakpoint {
                if !seen_fork {
                    hook_str.push_str(&format!(
                        "void fork_handle(int pid, int child, int *ret, void *arg1, void *arg2)\n{{\n\t#define regs (*(struct user_regs_struct*)arg1)\n\t#define child_regs (*(struct user_regs_struct*)arg2)\n\t#define should_trace (*ret)\n\n{}\n\t#undef child_regs\n\t#undef regs\n\t#undef should_trace\n}}\n
",
                        patch.body));
                    seen_fork = true;
                }
                continue;
            }
            if let Breakpoint::Status() = patch.breakpoint {
                if !seen_status {
                    hook_str.push_str(&format!(
                        "void status_handle(int pid, int status, int *ret, void *arg, int is_regs)\n{{\n\t#define regs (*(struct user_regs_struct*)arg)\n\t#define should_exit (*ret)\n\n{}\n\t#undef should_exit\n\t#undef regs\n}}\n",
                        patch.body));
                    seen_status = true;
                }
                continue;
            }
            hook_str.push_str(&format!(
                "void hook{}(pid_t pid, void *arg)\n{{\n\t#define regs (*(struct user_regs_struct *)\
                arg)\n\n{}\n\t#undef regs\n}}\n",
                hookcnt, patch.body));
            match patch.breakpoint {
                Breakpoint::Expr(s) => {
                    init_str.push_str(&format!("\tbkpt_add(pid, (void*){}, hook{});\n", s, hookcnt));
                },
                Breakpoint::Presys(names) => {
                    hook_sys = true;
                    for name in names {
                        let arg = match name.parse::<i32>() {
                            Ok(_) => name,
                            Err(_) => format!("__NR_{}", name),
                        };
                        init_str.push_str(&format!("\tpresys_hooks[{}] = hook{};\n", arg, hookcnt));
                    }
                },
                Breakpoint::Postsys(names) => {
                    hook_sys = true;
                    for name in names {
                        let arg = match name.parse::<i32>() {
                            Ok(_) => name,
                            Err(_) => format!("__NR_{}", name),
                        };
                        init_str.push_str(&format!("\tpostsys_hooks[{}] = hook{};\n", arg, hookcnt));
                    }
                },
                _ => {},
            }
            hookcnt += 1;
        }
    }

    let mut defines = String::new();
    if seen_fork {
        defines += "#define HOOK_FORKS\n";
    }
    if seen_status {
        defines += "#define STATUS_HANDLER\n";
    }
    if hook_sys {
        defines += "#define HOOK_SYSCALLS\n";
    }
    let mut is_embed = false;
    if let Some(embed) = &opt.embed {
        is_embed = true;
        Path::new(embed).canonicalize()?;
        defines += "#define EMBED_EXECUTABLE\n";
        run_command(
            "cp",
            &[embed, "embed.gen.tmp"],
            &format!("failed to copy {} to embed.gen.tmp", embed),
        )?;
        run_command(
            "ld",
            &["-r", "-b", "binary", "-o", "embed.gen.o", "embed.gen.tmp"],
            "linker failed to generate embed.gen.o",
        )?;
    }

    let p1 = include_str!("../../../stub/stub-p1.c");
    let p2 = include_str!("../../../stub/stub-p2.c");
    let p3 = include_str!("../../../stub/stub-p3.c");

    let mut genfile = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("stub.gen.c")?;
    genfile.write_all(format!("{}{}{}{}{}{}", defines, p1, hook_str, p2, init_str, p3).as_bytes())?;
    genfile.flush()?;
    println!("stub written to stub.gen.c");

    run_command(
        "gcc",
        &[
            "-nostdlib", "-nostartfiles", "-include", NOLIBC_PATH, "-static",
            "-Os", "-fcf-protection=none", "-fdiagnostics-color=always", "-Wl,--gc-sections",
            "-Wl,--strip-all", "-Wl,--build-id=none", &format!("-Wl,-T{}", LDSCRIPT_PATH),
            "stub.gen.c", if is_embed { "embed.gen.o" } else { "-Os" }, "-o", "stub.out",
        ],
        "failed to compile stub.gen.c",
    )?;
    // see stub/Makefile for reasoning on why this isn't enabled
    /*run_command(
        "objcopy",
        &["--strip-section-headers", "stub.out"],
        "failed to strip section headers from stub.out",
    )?;*/
    if is_embed {
        run_command(
            "rm",
            &["-f", "embed.gen.tmp", "embed.gen.o"],
            "failed to remove embed.gen.tmp and embed.gen.o",
        )?;
    }
    println!("{}", "stub successfully generated".bright_green());

    Ok(())
}

fn parse_file(content: &str) -> Result<ParsedFile, Box<dyn Error>> {
    let mut lines = content.lines();
    let mut globals = String::new();
    let mut patches = Vec::new();
    let mut in_globals = true;
    let mut line_start = 1;

    while let Some(line) = lines.next() {
        line_start += 1;
        if line.trim() == "%%" {
            in_globals = false;
            break;
        }
        globals.push_str(line);
        globals.push('\n');
    }

    if in_globals {
        return Err("missing '%%' separator between globals and hooks".into());
    }

    let mut current_patch: Option<Patch> = None;
    for (line_num, line) in lines.enumerate() {
        let txt = line.trim();

        if txt.starts_with("<@") {
            if current_patch.is_some() {
                return Err(format!("found '<@' while previous hook not closed with '@>' at line {}", line_start+line_num).into());
            }
            let breakpoint = parse_breakpoint(txt)?;
            current_patch = Some(Patch {
                breakpoint,
                body: String::new(),
            });
        } else if txt == "@>" {
            if let Some(patch) = current_patch.take() {
                patches.push(patch);
            } else {
                return Err(format!("found '@>' without matching '<@' at line {}", line_start+line_num).into());
            }
        } else if let Some(ref mut patch) = current_patch {
            patch.body.push_str(line);
            patch.body.push('\n');
        } else {
            if !txt.is_empty() && !txt.trim().starts_with("//") {
                return Err(format!("unexpected content outside of a hook at line {}: {}", line_start+line_num, txt).into());
            }
        }
    }

    if current_patch.is_some() {
        return Err("unclosed hook: missing '@>' at the end of file".into());
    }

    Ok(ParsedFile { globals, patches })
}

fn parse_breakpoint(line: &str) -> Result<Breakpoint, Box<dyn Error>> {
    let line = line.trim_start_matches("<@").trim();
    if line.starts_with("pre-syscall") {
        let rest = line.strip_prefix("pre-syscall").ok_or("invalid pre-syscall format")?.trim();
        if rest.is_empty() {
            return Err("pre-syscall must be followed by a list of syscall names or numbers".into());
        }
        let names = rest.split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        return Ok(Breakpoint::Presys(names));
    }
    if line.starts_with("post-syscall") {
        let rest = line.strip_prefix("post-syscall").ok_or("invalid post-syscall format")?.trim();
        if rest.is_empty() {
            return Err("post-syscall must be followed by a list of syscall names or numbers".into());
        }
        let names = rest.split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        return Ok(Breakpoint::Postsys(names));
    }
    if line.starts_with("fork") {
        return Ok(Breakpoint::Fork());
    }
    if line.starts_with("status") {
        return Ok(Breakpoint::Status());
    }
    if line.is_empty() {
        return Err("breakpoint expression cannot be empty".into());
    }
    Ok(Breakpoint::Expr(line.to_string()))
}
