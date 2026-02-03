/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! A module for running Chip YAML tests using chip-tool-rs as the server.

use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{self, Context};

use log::{debug, info, warn};

/// Default tests to run
const DEFAULT_TESTS: &[&str] = &["Test_TC_OO_2_1"];

/// The default Git reference to use for the Chip repository
pub const CHIP_DEFAULT_GITREF: &str = "v1.4.2-branch";
/// The directory where the Chip repository will be cloned
const CHIP_DIR: &str = ".build/yamltest/connectedhomeip";

/// The default Git reference to use for the chip-tool-rs repository
pub const CHIP_TOOL_RS_DEFAULT_GITREF: &str = "main";
/// The directory where the chip-tool-rs repository will be cloned
const CHIP_TOOL_RS_DIR: &str = ".build/yamltest/chip-tool-rs";

/// The tooling that is checked for presence in the command line
const REQUIRED_TOOLING: &[&str] = &["bash", "git", "cargo", "python3", "pip3"];

/// The Debian/Ubuntu-specific packages that need to be installed
const REQUIRED_PACKAGES: &[&str] = &[
    "git",
    "python3",
    "python3-pip",
    "python3-venv",
    "python3-dev",
];

/// A utility for running Chip YAML tests using chip-tool-rs.
pub struct YamlTests {
    /// The `rs-matter` workspace directory
    workspace_dir: PathBuf,
    print_cmd_output: bool,
}

impl YamlTests {
    /// Create a new `YamlTests` instance.
    ///
    /// # Arguments
    /// - `workspace_dir`: The path to the `rs-matter` workspace directory.
    /// - `print_cmd_output`: Whether to print command output to the console.
    pub fn new(workspace_dir: PathBuf, print_cmd_output: bool) -> Self {
        YamlTests {
            workspace_dir,
            print_cmd_output,
        }
    }

    /// Print the required system tools for YAML tests.
    pub fn print_tooling(&self) -> anyhow::Result<()> {
        let tooling = REQUIRED_TOOLING.to_vec().join(" ");

        warn!("Printing required system tools for Chip YAML tests");
        info!("{tooling}");

        println!("{tooling}");

        Ok(())
    }

    /// Print the required Debian/Ubuntu system packages for YAML tests.
    pub fn print_packages(&self) -> anyhow::Result<()> {
        let packages = REQUIRED_PACKAGES.to_vec().join(" ");

        warn!("Printing required Debian/Ubuntu system packages for Chip YAML tests");
        info!("{packages}");

        println!("{packages}");

        Ok(())
    }

    /// Setup the environment so that YAML tests can be run.
    ///
    /// In details:
    /// - Check system dependencies
    /// - Clone the Chip repo if it doesn't exist
    /// - Clone the chip-tool-rs repo if it doesn't exist
    /// - Setup Python environment
    /// - Build chip-tool-rs
    pub fn setup(
        &self,
        chip_gitref: Option<&str>,
        chip_tool_rs_gitref: Option<&str>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        warn!("Setting up YAML test environment...");

        // Check system dependencies
        self.check_tooling()?;

        // Setup connectedhomeip
        self.setup_connectedhomeip(chip_gitref, force_rebuild)?;

        // Setup chip-tool-rs
        self.setup_chip_tool_rs(chip_tool_rs_gitref, force_rebuild)?;

        info!("YAML test environment setup completed successfully.");

        Ok(())
    }

    /// Build the chip-tool-rs executable.
    pub fn build(&self, force_rebuild: bool) -> anyhow::Result<()> {
        self.build_chip_tool_rs(force_rebuild)
    }

    /// Run YAML tests
    pub fn run<'a>(
        &self,
        tests: impl IntoIterator<Item = &'a String> + Clone,
        test_timeout_secs: u32,
    ) -> anyhow::Result<()> {
        self.run_tests(tests, test_timeout_secs)
    }

    fn setup_connectedhomeip(
        &self,
        chip_gitref: Option<&str>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        warn!("Setting up connectedhomeip...");

        let chip_dir = self.chip_dir();
        let chip_gitref = chip_gitref.unwrap_or(CHIP_DEFAULT_GITREF);

        // Clone or update Chip repository
        if !chip_dir.exists() {
            info!("Cloning connectedhomeip repository...");

            // Ensure parent directories exist
            if let Some(parent) = chip_dir.parent() {
                fs::create_dir_all(parent)
                    .context("Failed to create parent directories for connectedhomeip")?;
            }

            let mut cmd = Command::new("git");

            cmd.arg("clone")
                .arg("https://github.com/project-chip/connectedhomeip.git")
                .arg(&chip_dir);

            if !self.print_cmd_output {
                cmd.arg("--quiet");
            }

            self.run_command(&mut cmd)?;

            File::create(chip_dir.join(chip_gitref))?;
        } else {
            info!("connectedhomeip repository already exists");

            if force_rebuild || !chip_dir.join(chip_gitref).exists() {
                info!("Force rebuild requested or different gitref, updating...");
            }
        }

        // Checkout the specified reference
        info!("Checking out connectedhomeip GIT reference: {chip_gitref}...");

        let mut cmd = Command::new("git");

        cmd.current_dir(&chip_dir).arg("switch").arg(chip_gitref);

        if !self.print_cmd_output {
            cmd.arg("--quiet");
        }

        self.run_command(&mut cmd)?;

        // Detect host platform for selective submodule initialization
        let platform = self.host_platform()?;
        info!("Detected platform: {platform}");

        // Initialize submodules selectively for host platform only
        info!("Initializing submodules for platform: {platform}...");

        let mut cmd = Command::new("python3");

        cmd.current_dir(&chip_dir)
            .arg("scripts/checkout_submodules.py")
            .arg("--shallow")
            .arg("--platform")
            .arg(platform);

        self.run_command_with(&mut cmd, !self.print_cmd_output)?;

        // Setup Python environment
        self.setup_py_env(&chip_dir)?;

        info!("connectedhomeip setup completed.");

        Ok(())
    }

    fn setup_chip_tool_rs(
        &self,
        chip_tool_rs_gitref: Option<&str>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        warn!("Setting up chip-tool-rs...");

        let chip_tool_rs_dir = self.chip_tool_rs_dir();
        let chip_tool_rs_gitref = chip_tool_rs_gitref.unwrap_or(CHIP_TOOL_RS_DEFAULT_GITREF);

        // Clone or update chip-tool-rs repository
        if !chip_tool_rs_dir.exists() {
            info!("Cloning chip-tool-rs repository...");

            // Ensure parent directories exist
            if let Some(parent) = chip_tool_rs_dir.parent() {
                fs::create_dir_all(parent)
                    .context("Failed to create parent directories for chip-tool-rs")?;
            }

            let mut cmd = Command::new("git");

            cmd.arg("clone")
                .arg("https://github.com/estincelle/chip-tool-rs.git")
                .arg(&chip_tool_rs_dir);

            if !self.print_cmd_output {
                cmd.arg("--quiet");
            }

            self.run_command(&mut cmd)?;

            File::create(chip_tool_rs_dir.join(chip_tool_rs_gitref))?;
        } else {
            info!("chip-tool-rs repository already exists");

            if force_rebuild || !chip_tool_rs_dir.join(chip_tool_rs_gitref).exists() {
                info!("Force rebuild requested or different gitref, updating...");
            }
        }

        // Checkout the specified reference
        info!("Checking out chip-tool-rs GIT reference: {chip_tool_rs_gitref}...");

        let mut cmd = Command::new("git");

        cmd.current_dir(&chip_tool_rs_dir)
            .arg("checkout")
            .arg(chip_tool_rs_gitref);

        if !self.print_cmd_output {
            cmd.arg("--quiet");
        }

        self.run_command(&mut cmd)?;

        // Build chip-tool-rs
        self.build_chip_tool_rs(force_rebuild)?;

        info!("chip-tool-rs setup completed.");

        Ok(())
    }

    fn build_chip_tool_rs(&self, force_rebuild: bool) -> anyhow::Result<()> {
        warn!("Building chip-tool-rs...");

        let chip_tool_rs_dir = self.chip_tool_rs_dir();

        if force_rebuild {
            info!("Force rebuild requested, cleaning previous build artifacts...");

            let mut cmd = Command::new("cargo");

            cmd.arg("clean").current_dir(&chip_tool_rs_dir);

            if !self.print_cmd_output {
                cmd.arg("--quiet");
            }

            self.run_command(&mut cmd)?;
        }

        let mut cmd = Command::new("cargo");

        cmd.arg("build")
            .arg("--release")
            .current_dir(&chip_tool_rs_dir);

        if !self.print_cmd_output {
            cmd.arg("--quiet");
        }

        self.run_command(&mut cmd)?;

        info!("chip-tool-rs built successfully");

        Ok(())
    }

    fn run_tests<'a>(
        &self,
        tests: impl IntoIterator<Item = &'a String> + Clone,
        test_timeout_secs: u32,
    ) -> anyhow::Result<()> {
        warn!("Running YAML tests...");

        let chip_dir = self.chip_dir();
        let chip_tool_rs_dir = self.chip_tool_rs_dir();

        // Verify environment is set up
        if !chip_dir.exists() {
            anyhow::bail!("connectedhomeip not found. Run `cargo xtask yamltest-setup` first.");
        }

        let chip_tool_rs_exe = chip_tool_rs_dir.join("target/release/chip-tool-rs");
        if !chip_tool_rs_exe.exists() {
            anyhow::bail!(
                "chip-tool-rs executable not found. Run `cargo xtask yamltest-setup` first."
            );
        }

        // Determine which tests to run
        let tests = if tests.clone().into_iter().next().is_some() {
            tests.into_iter().map(|s| s.as_str()).collect::<Vec<_>>()
        } else {
            info!("Using default tests");

            DEFAULT_TESTS.to_vec()
        };

        if tests.is_empty() {
            info!("No tests specified and no default tests enabled.");
            return Ok(());
        }

        debug!("About to run tests: {tests:?}");

        // Run each test
        for test_name in tests {
            self.run_test(test_name, test_timeout_secs)?;
        }

        info!("All YAML tests completed successfully.");

        Ok(())
    }

    fn run_test(&self, test_name: &str, timeout_secs: u32) -> anyhow::Result<()> {
        info!("=> Running YAML test `{test_name}` with timeout {timeout_secs}s...");

        let chip_dir = self.chip_dir();
        let chip_tool_rs_dir = self.chip_tool_rs_dir();

        let chiptool_py_path = chip_dir.join("scripts/tests/chipyaml/chiptool.py");
        let chip_tool_rs_exe = chip_tool_rs_dir.join("target/release/chip-tool-rs");

        // Build the test command
        // connectedhomeip/scripts/tests/chipyaml/chiptool.py tests Test_TC_OO_2_1 --server_path <path/to/server/exe>
        let test_command = format!(
            "{} tests {} --server_path {}",
            chiptool_py_path.display(),
            test_name,
            chip_tool_rs_exe.display(),
        );

        // Run in the connectedhomeip build environment
        let script_path = chip_dir.join("scripts/run_in_build_env.sh");

        let mut cmd = Command::new(&script_path);
        cmd.current_dir(&chip_dir)
            .env("CHIP_HOME", &chip_dir)
            .arg(&test_command);

        match self.run_command(&mut cmd) {
            Ok(()) => info!("YAML test `{test_name}` completed successfully"),
            Err(err) => {
                info!("Command failed: {}", test_command);
                return Err(err);
            }
        };

        Ok(())
    }

    fn setup_py_env(&self, chip_dir: &Path) -> anyhow::Result<()> {
        info!("Setting up Python environment...");

        let venv_dir = chip_dir.join("venv");

        // Create virtual environment if it doesn't exist
        if !venv_dir.exists() {
            self.run_command(
                Command::new("python3")
                    .arg("-m")
                    .arg("venv")
                    .arg("venv")
                    .current_dir(chip_dir),
            )?;
        }

        // Install requirements
        let requirements_path = chip_dir.join("scripts/tests/requirements.txt");
        if requirements_path.exists() {
            let pip_path = venv_dir.join("bin/pip");

            self.run_command(
                Command::new(&pip_path)
                    .current_dir(chip_dir)
                    .arg("install")
                    .arg("--upgrade")
                    .arg("pip")
                    .arg("wheel"),
            )?;

            self.run_command(
                Command::new(&pip_path)
                    .env("PW_PROJECT_ROOT", chip_dir)
                    .current_dir(chip_dir)
                    .arg("install")
                    .arg("-r")
                    .arg("scripts/tests/requirements.txt"),
            )?;
        }

        let bootstrap_script = chip_dir.join("scripts/bootstrap.sh");
        let run_bootstrap = format!(
            r#"
            source "{}"
            "#,
            bootstrap_script.display(),
        );

        self.run_command_with(
            Command::new("bash")
                .current_dir(chip_dir)
                .arg("-c")
                .arg(&run_bootstrap),
            !self.print_cmd_output,
        )?;

        Ok(())
    }

    fn check_tooling(&self) -> anyhow::Result<()> {
        for tool in REQUIRED_TOOLING {
            if which::which(tool).is_err() {
                anyhow::bail!("Required tool '{tool}' not found in $PATH");
            }
        }

        info!("System tools check passed");

        Ok(())
    }

    fn run_command(&self, cmd: &mut Command) -> anyhow::Result<()> {
        self.run_command_with(cmd, false)
    }

    fn run_command_with(&self, cmd: &mut Command, suppress_err: bool) -> anyhow::Result<()> {
        debug!("Running: {cmd:?}");

        let cmd = cmd.stdin(Stdio::null());

        if !self.print_cmd_output {
            cmd.stdout(Stdio::null());
        }

        if suppress_err {
            cmd.stderr(Stdio::null());
        }

        let status = cmd
            .status()
            .with_context(|| format!("Failed to execute command: {cmd:?}"))?;

        if !status.success() {
            anyhow::bail!("Command failed with status: {status}");
        }

        Ok(())
    }

    fn chip_dir(&self) -> PathBuf {
        self.workspace_dir.join(CHIP_DIR)
    }

    fn chip_tool_rs_dir(&self) -> PathBuf {
        self.workspace_dir.join(CHIP_TOOL_RS_DIR)
    }

    fn host_platform(&self) -> anyhow::Result<&str> {
        let os = env::consts::OS;
        let chip_platform = match os {
            "linux" => "linux",
            "macos" => "darwin",
            _ => anyhow::bail!("Unsupported host OS: {os}"),
        };

        Ok(chip_platform)
    }
}
