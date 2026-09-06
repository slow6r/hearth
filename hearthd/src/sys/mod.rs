//! Thin, auditable wrappers around the few host tools hearthd is allowed to call.
//!
//! Design rule: every wrapper is split into "run the command" and "parse the output".
//! The parsers are pure functions with unit tests, so the interesting logic is testable
//! on any machine — including a Windows dev box with no nftables in sight.
//!
//! hearthd shells out to exactly four programs: `systemctl`, `nft`, `ss`, `journalctl`
//! (plus `rsync`/`ssh` in the backup module). None of them may take attacker-controlled
//! arguments; everything comes from the validated configuration.

pub mod journal;
pub mod nft;
pub mod ss;
pub mod systemd;

use std::ffi::OsStr;
use std::time::Duration;

use crate::error::{Error, Result};

/// Captured result of a subprocess.
#[derive(Debug, Clone)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// Subprocess runner. `dry_run` short-circuits mutating commands so the daemon can be
/// exercised on a developer machine without a systemd or nftables in sight.
#[derive(Debug, Clone)]
pub struct Sys {
    dry_run: bool,
    timeout: Duration,
}

impl Default for Sys {
    fn default() -> Self {
        Self {
            dry_run: false,
            timeout: Duration::from_secs(30),
        }
    }
}

impl Sys {
    pub fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            ..Self::default()
        }
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Run a command and capture its output. Non-zero exit is *not* an error here.
    pub async fn capture<S: AsRef<OsStr>>(&self, program: &str, args: &[S]) -> Result<Output> {
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args.iter().map(AsRef::as_ref));
        cmd.stdin(std::process::Stdio::null());
        cmd.kill_on_drop(true);

        let fut = cmd.output();
        let out = match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(Error::Command {
                    cmd: describe(program, args),
                    status: "spawn-failed".into(),
                    stderr: e.to_string(),
                })
            }
            Err(_) => {
                return Err(Error::Command {
                    cmd: describe(program, args),
                    status: "timeout".into(),
                    stderr: format!("no result after {:?}", self.timeout),
                })
            }
        };
        Ok(Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// Run a command and fail on a non-zero exit status.
    pub async fn run<S: AsRef<OsStr>>(&self, program: &str, args: &[S]) -> Result<Output> {
        let out = self.capture(program, args).await?;
        if out.ok() {
            Ok(out)
        } else {
            Err(Error::Command {
                cmd: describe(program, args),
                status: out.code.to_string(),
                stderr: out.stderr.trim().to_string(),
            })
        }
    }

    /// Run a mutating command; in dry-run mode only log what would have happened.
    pub async fn run_mutating<S: AsRef<OsStr>>(&self, program: &str, args: &[S]) -> Result<Output> {
        if self.dry_run {
            let cmd = describe(program, args);
            tracing::info!(command = %cmd, "dry-run: not executing");
            return Ok(Output {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        self.run(program, args).await
    }
}

fn describe<S: AsRef<OsStr>>(program: &str, args: &[S]) -> String {
    let mut out = program.to_string();
    for a in args {
        out.push(' ');
        out.push_str(&a.as_ref().to_string_lossy());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_skips_mutating_commands() {
        let sys = Sys::new(true);
        let out = sys
            .run_mutating("definitely-not-a-real-program", &["--boom"])
            .await
            .expect("dry-run succeeds without executing");
        assert!(out.ok());
    }

    #[tokio::test]
    async fn missing_program_is_a_command_error() {
        let sys = Sys::new(false);
        let err = sys
            .capture("definitely-not-a-real-program", &["--boom"])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Command { .. }), "got {err:?}");
    }
}
