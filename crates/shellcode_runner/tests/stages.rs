//! Runs the flattened stages from `outputs/` through `shellcode_runner` with
//! `test_program_rust.exe` as the stage3 image. `just test` builds the
//! artifacts first.
//!
//! Tests named `*_runs_image_*` need the Windows loader. Wine cannot start a
//! thread once the loader has moved the main module's `DllBase`, so `just test`
//! skips them on other hosts.

use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use tempfile::TempDir;

const STAGE1_ERROR_FILE_OPEN_FAILED: i32 = 0x10000001;
const STAGE2_ERROR_FILE_OPEN_FAILED: i32 = 0x20000001;

/// Directory of `GameScript`-style state for one run. Stages resolve their
/// inputs from `%LOCALAPPDATA%\..\LocalState`, so `LOCALAPPDATA` points at a
/// sibling of `LocalState`.
struct Sandbox {
    root: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("failed to create sandbox directory");
        std::fs::create_dir(root.path().join("Local")).expect("failed to create Local");
        std::fs::create_dir(root.path().join("LocalState")).expect("failed to create LocalState");

        Self { root }
    }

    fn local_state(&self) -> PathBuf {
        self.root.path().join("LocalState")
    }

    /// Copies `outputs/<artifact>` to `LocalState/<name>` and returns the new path.
    fn install(&self, artifact: &str, name: &str) -> PathBuf {
        let destination = self.local_state().join(name);
        std::fs::copy(artifact_path(artifact), &destination)
            .unwrap_or_else(|e| panic!("failed to install {artifact}: {e}"));

        destination
    }

    fn write_args_file(&self, contents: &str) {
        std::fs::write(self.local_state().join("args.txt"), contents)
            .expect("failed to write args.txt");
    }

    fn run(&self, shellcode: &Path, image: Option<(&Path, Option<&str>)>) -> RunOutcome {
        const TIMEOUT: Duration = Duration::from_secs(60);

        let mut command = Command::new(env!("CARGO_BIN_EXE_shellcode_runner"));
        command
            .arg(shellcode)
            .env("LOCALAPPDATA", self.root.path().join("Local"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some((image_path, image_args)) = image {
            command.arg(image_path);
            command.args(image_args);
        }

        let mut child = command.spawn().expect("failed to spawn shellcode_runner");

        // A stage that faults inside its panic handler spins forever.
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait().expect("failed to poll shellcode_runner") {
                break status;
            }

            if Instant::now() >= deadline {
                child.kill().expect("failed to kill shellcode_runner");
                let output = child
                    .wait_with_output()
                    .expect("failed to collect shellcode_runner output");
                panic!(
                    "shellcode_runner timed out after {TIMEOUT:?}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            std::thread::sleep(Duration::from_millis(50));
        };

        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            pipe.read_to_string(&mut stderr)
                .expect("failed to read shellcode_runner stderr");
        }

        RunOutcome {
            status,
            stderr,
            report: Stage3Report::read(&self.local_state().join("stage3_complete.txt")),
        }
    }
}

struct RunOutcome {
    status: ExitStatus,
    stderr: String,
    report: Option<Stage3Report>,
}

impl RunOutcome {
    fn expect_report(self) -> Stage3Report {
        assert!(
            self.status.success(),
            "shellcode_runner exited with {}\nstderr:\n{}",
            self.status,
            self.stderr
        );

        self.report
            .expect("stage3 did not write stage3_complete.txt")
    }

    /// Asserts the stage returned `code` without starting stage3.
    fn assert_exit_code(self, code: i32) {
        assert_eq!(
            self.status.code(),
            Some(code),
            "expected exit code {code:#X}\nstderr:\n{}",
            self.stderr
        );
        assert!(self.report.is_none(), "stage3 ran unexpectedly");
    }
}

/// Contents of the file `test_program_rust` writes once it runs.
struct Stage3Report {
    args: Vec<String>,
}

impl Stage3Report {
    fn read(path: &Path) -> Option<Self> {
        let contents = std::fs::read_to_string(path).ok()?;

        // Each line after the banner is "<pointer> <argument>".
        let args = contents
            .lines()
            .skip(1)
            .map(|line| {
                let (_pointer, arg) = line.split_once(' ').expect("malformed argument line");
                arg.to_owned()
            })
            .collect();

        Some(Self { args })
    }

    fn assert_image_then(&self, expected_args: &[&str]) {
        let Some((image, args)) = self.args.split_first() else {
            panic!("stage3 received no arguments");
        };

        assert!(
            image.to_ascii_lowercase().ends_with("run.exe"),
            "argv[0] is {image:?}, expected the image path"
        );
        assert_eq!(args, expected_args);
    }
}

fn artifact_path(name: &str) -> PathBuf {
    // Integration tests run with the package root as the working directory.
    let path = Path::new("../../outputs").join(name);
    assert!(
        path.exists(),
        "missing {}; build the artifacts with `just test`",
        path.display()
    );

    path
}

#[test]
fn stage2_runs_image_with_explicit_args() {
    let sandbox = Sandbox::new();
    let image = sandbox.install("test_program_rust.exe", "run.exe");

    let outcome = sandbox.run(
        &artifact_path("stage2.bin"),
        Some((&image, Some(r#"alpha "two words" beta"#))),
    );

    outcome
        .expect_report()
        .assert_image_then(&["alpha", "two words", "beta"]);
}

#[test]
fn stage2_runs_image_with_no_image_args() {
    let sandbox = Sandbox::new();
    let image = sandbox.install("test_program_rust.exe", "run.exe");

    let outcome = sandbox.run(&artifact_path("stage2.bin"), Some((&image, None)));

    outcome.expect_report().assert_image_then(&[]);
}

#[test]
fn stage2_runs_image_from_local_state() {
    let sandbox = Sandbox::new();
    sandbox.install("test_program_rust.exe", "run.exe");
    sandbox.write_args_file("alpha beta");

    let outcome = sandbox.run(&artifact_path("stage2.bin"), None);

    outcome
        .expect_report()
        .assert_image_then(&["alpha", "beta"]);
}

#[test]
fn stage1_runs_image_from_local_state() {
    let sandbox = Sandbox::new();
    sandbox.install("stage2.bin", "stage2.bin");
    sandbox.install("test_program_rust.exe", "run.exe");

    let outcome = sandbox.run(&artifact_path("stage1.bin"), None);

    outcome.expect_report().assert_image_then(&[]);
}

#[test]
fn stage2_embedded_runs_image_without_files() {
    let sandbox = Sandbox::new();

    let outcome = sandbox.run(&artifact_path("stage2_embedded.bin"), None);

    outcome.expect_report().assert_image_then(&[]);
}

#[test]
fn stage2_returns_open_error_for_missing_image() {
    let sandbox = Sandbox::new();
    let missing_image = sandbox.local_state().join("run.exe");

    let outcome = sandbox.run(&artifact_path("stage2.bin"), Some((&missing_image, None)));

    outcome.assert_exit_code(STAGE2_ERROR_FILE_OPEN_FAILED);
}

#[test]
fn stage1_returns_stage2_error_for_missing_image() {
    let sandbox = Sandbox::new();
    sandbox.install("stage2.bin", "stage2.bin");

    let outcome = sandbox.run(&artifact_path("stage1.bin"), None);

    outcome.assert_exit_code(STAGE2_ERROR_FILE_OPEN_FAILED);
}

#[test]
fn stage1_returns_open_error_for_missing_stage2() {
    let sandbox = Sandbox::new();

    let outcome = sandbox.run(&artifact_path("stage1.bin"), None);

    outcome.assert_exit_code(STAGE1_ERROR_FILE_OPEN_FAILED);
}
