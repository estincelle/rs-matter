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

//! A module for running the PAA Trust Store integration test.
//!
//! Fetches real PAA certificates from the public connectedhomeip repository
//! and verifies that `ArrayAttestationTrustStore::from_directory` can load and look up certs by SKID.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{self, Context};
use log::{debug, info, warn};

use rs_matter::credentials::test_paa::{TEST_PAA_FFF1_SKID, TEST_PAA_NOVID_SKID};
use rs_matter::credentials::trust_store::{ArrayAttestationTrustStore, AttestationTrustStore};

/// GitHub repository URL for connectedhomeip
const CHIP_REPO_URL: &str = "https://github.com/project-chip/connectedhomeip.git";

/// Default git reference (branch/tag) to fetch PAA certs from
pub const CHIP_DEFAULT_GITREF: &str = "master";

/// Subdirectory within connectedhomeip containing PAA root certificates
const PAA_CERTS_SUBDIR: &str = "credentials/development/paa-root-certs";

/// Cache directory (relative to workspace root)
const CACHE_DIR: &str = ".build/truststoretest";

/// A utility for running the PAA Trust Store integration test.
pub struct TrustStoreTests {
    /// The `rs-matter` workspace directory
    workspace_dir: PathBuf,
    print_cmd_output: bool,
}

impl TrustStoreTests {
    /// Create a new `TrustStoreTests` instance.
    pub fn new(workspace_dir: PathBuf, print_cmd_output: bool) -> Self {
        Self {
            workspace_dir,
            print_cmd_output,
        }
    }

    /// Run the trust store integration test.
    ///
    /// Fetches PAA certs (unless `skip_fetch` or `paa_path` is set),
    /// loads them via `ArrayAttestationTrustStore`, and verifies lookup by SKID.
    pub fn run(
        &self,
        gitref: &str,
        paa_path: Option<&Path>,
        skip_fetch: bool,
    ) -> anyhow::Result<()> {
        let paa_dir = if let Some(path) = paa_path {
            info!("Using user-provided PAA cert directory: {}", path.display());
            path.to_path_buf()
        } else {
            if !skip_fetch {
                self.fetch_paa_certs(gitref)?;
            }
            self.paa_certs_dir()
        };

        if !paa_dir.exists() {
            anyhow::bail!(
                "PAA certs directory does not exist: {}. Run without --skip-fetch first.",
                paa_dir.display()
            );
        }

        self.run_trust_store_test(&paa_dir)
    }

    /// Fetch PAA certificates from the connectedhomeip repository using sparse checkout.
    fn fetch_paa_certs(&self, gitref: &str) -> anyhow::Result<()> {
        warn!("Fetching PAA certificates from connectedhomeip ({gitref})...");

        let cache_dir = self.cache_dir();
        let repo_dir = cache_dir.join("connectedhomeip");

        if repo_dir.exists() {
            info!("Removing previous cache...");
            fs::remove_dir_all(&repo_dir).context("Failed to remove previous PAA cert cache")?;
        }

        fs::create_dir_all(&cache_dir).context("Failed to create cache directory")?;

        // Sparse clone: download only metadata, then fetch just the PAA certs directory
        info!("Sparse-cloning connectedhomeip (PAA certs only)...");

        let mut cmd = Command::new("git");
        cmd.arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("--filter=blob:none")
            .arg("--sparse")
            .arg("--branch")
            .arg(gitref)
            .arg(CHIP_REPO_URL)
            .arg(&repo_dir);

        if !self.print_cmd_output {
            cmd.arg("--quiet");
        }

        self.run_command(&mut cmd)?;

        // Set sparse-checkout to only the PAA certs path
        let mut cmd = Command::new("git");
        cmd.current_dir(&repo_dir)
            .arg("sparse-checkout")
            .arg("set")
            .arg(PAA_CERTS_SUBDIR);

        self.run_command(&mut cmd)?;

        let paa_dir = repo_dir.join(PAA_CERTS_SUBDIR);
        if !paa_dir.exists() {
            anyhow::bail!(
                "PAA certs directory not found after sparse checkout: {}",
                paa_dir.display()
            );
        }

        // Count .der files
        let der_count = fs::read_dir(&paa_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "der")
                    .unwrap_or(false)
            })
            .count();

        info!("Fetched {der_count} .der files to {}", paa_dir.display());

        Ok(())
    }

    /// Load PAA certs and verify trust store operations.
    fn run_trust_store_test(&self, paa_dir: &Path) -> anyhow::Result<()> {
        warn!("Running PAA Trust Store test...");

        info!("Loading PAA certificates from: {}", paa_dir.display());

        let store = ArrayAttestationTrustStore::<256>::from_directory(paa_dir)
            .map_err(|e| anyhow::anyhow!("Failed to load PAA certificates: {:?}", e))?;

        if store.paa_count() == 0 {
            anyhow::bail!("No PAA certificates loaded from {}", paa_dir.display());
        }

        info!("Loaded {} PAA certificates", store.paa_count());

        // Test 1: Look up the test PAA FFF1 by SKID
        info!("Looking up Test PAA FFF1 by SKID...");
        match store.get_paa(&TEST_PAA_FFF1_SKID) {
            Ok(cert) => {
                info!("  Found Test PAA FFF1 ({} bytes)", cert.len());
            }
            Err(e) => {
                anyhow::bail!("Test PAA FFF1 not found in store: {:?}", e);
            }
        }

        // Test 2: Look up the test PAA NoVID by SKID
        info!("Looking up Test PAA NoVID by SKID...");
        match store.get_paa(&TEST_PAA_NOVID_SKID) {
            Ok(cert) => {
                info!("  Found Test PAA NoVID ({} bytes)", cert.len());
            }
            Err(e) => {
                anyhow::bail!("Test PAA NoVID not found in store: {:?}", e);
            }
        }

        // Test 3: Unknown SKID should return NotFound
        info!("Looking up unknown SKID (should not find)...");
        let unknown_skid = [0xFF; 20];
        match store.get_paa(&unknown_skid) {
            Ok(_) => {
                anyhow::bail!("Unexpectedly found a cert for an all-0xFF SKID");
            }
            Err(_) => {
                info!("  Unknown SKID correctly returned NotFound");
            }
        }

        // Test 4: from_certs ingestion — build a store from embedded DER bytes
        // and verify it produces the same lookup results as from_directory
        info!("Testing from_certs ingestion with embedded test PAAs...");

        let fff1_der = store.get_paa(&TEST_PAA_FFF1_SKID).unwrap();
        let novid_der = store.get_paa(&TEST_PAA_NOVID_SKID).unwrap();

        let certs_store = ArrayAttestationTrustStore::<2>::from_certs(&[fff1_der, novid_der])
            .map_err(|e| anyhow::anyhow!("from_certs failed: {:?}", e))?;

        if certs_store.paa_count() != 2 {
            anyhow::bail!(
                "from_certs store: expected 2 PAAs, got {}",
                certs_store.paa_count()
            );
        }

        // Verify lookup matches: same SKID returns same cert bytes
        let fff1_from_certs = certs_store
            .get_paa(&TEST_PAA_FFF1_SKID)
            .map_err(|e| anyhow::anyhow!("from_certs store: FFF1 lookup failed: {:?}", e))?;
        if fff1_from_certs != fff1_der {
            anyhow::bail!("from_certs store returned different bytes for FFF1");
        }
        info!("  from_certs FFF1 lookup matches from_directory");

        let novid_from_certs = certs_store
            .get_paa(&TEST_PAA_NOVID_SKID)
            .map_err(|e| anyhow::anyhow!("from_certs store: NoVID lookup failed: {:?}", e))?;
        if novid_from_certs != novid_der {
            anyhow::bail!("from_certs store returned different bytes for NoVID");
        }
        info!("  from_certs NoVID lookup matches from_directory");

        // Unknown SKID should also fail on from_certs store
        if certs_store.get_paa(&unknown_skid).is_ok() {
            anyhow::bail!("from_certs store: unexpectedly found unknown SKID");
        }
        info!("  from_certs unknown SKID correctly rejected");

        warn!("PAA Trust Store test PASSED");
        info!(
            "Summary: loaded {} PAAs via from_directory, verified from_certs produces identical results",
            store.paa_count()
        );

        Ok(())
    }

    fn paa_certs_dir(&self) -> PathBuf {
        self.cache_dir()
            .join("connectedhomeip")
            .join(PAA_CERTS_SUBDIR)
    }

    fn cache_dir(&self) -> PathBuf {
        self.workspace_dir.join(CACHE_DIR)
    }

    fn run_command(&self, cmd: &mut Command) -> anyhow::Result<()> {
        debug!("Running: {cmd:?}");

        let cmd = cmd.stdin(Stdio::null());

        if !self.print_cmd_output {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }

        let status = cmd
            .status()
            .with_context(|| format!("Failed to execute command: {cmd:?}"))?;

        if !status.success() {
            anyhow::bail!("Command failed with status: {status}");
        }

        Ok(())
    }
}
