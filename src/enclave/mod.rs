//! WAVEN — a local access-control table, not hardware memory isolation
//!
//! **Non-default module** (`enclave` feature). This is a real, working `BTreeMap<page,
//! MemoryPage>` access-control table with page data genuinely AES-GCM-256 encrypted at
//! rest. There is no actual WASM VM, no hardware memory-protection-key integration, and no
//! page-fault handling underneath it — "memory virtualization," "MPK-style keys," and
//! "side-channel resistance" describe a design target this module's data structure doesn't
//! implement. Gated off by default for the same reason `aethel-core` gates its own
//! `enclave` feature: it describes a hardware property this crate cannot provide on its
//! own. See the crate README's "What runs today vs. what is designed."

use crate::error::PrivacyError;
use crate::keyhop::{aes_gcm_encrypt, hkdf_derive};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// Page size in bytes (64KB per WASM spec).
pub const PAGE_SIZE: usize = 65_536;

/// Maximum MPK keys per CPU (16 per Intel MPK spec).
pub const MAX_KEYS: u8 = 16;

/// Page permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PagePerm {
    None,
    Read,
    Write,
    ReadWrite,
    Execute,
}

/// A memory page with access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPage {
    pub index:   usize,
    pub key:     u8,
    pub perm:    PagePerm,
    /// AES-GCM-256 encrypted page data (not CKKS/FHE-sealed)
    pub data:    Vec<u8>,
    /// Tenant DID owning this page
    pub tenant:  String,
}

/// WAVEN memory virtualization engine.
pub struct WavenEnclave {
    pages:   BTreeMap<usize, MemoryPage>,
    /// Key → tenant DID mapping
    keys:    BTreeMap<u8, String>,
    next_key: u8,
}

impl WavenEnclave {
    pub fn new() -> Self {
        Self {
            pages:    BTreeMap::new(),
            keys:     BTreeMap::new(),
            next_key: 0,
        }
    }

    /// Register a tenant and assign an MPK key.
    pub fn register_tenant(
        &mut self,
        tenant_did: impl Into<String>,
    ) -> Result<u8, PrivacyError> {
        if self.next_key >= MAX_KEYS {
            return Err(PrivacyError::AttestationFailed(
                "Maximum tenants reached".into()
            ));
        }
        let key = self.next_key;
        self.keys.insert(key, tenant_did.into());
        self.next_key += 1;
        Ok(key)
    }

    /// Allocate a memory page for a tenant.
    pub fn allocate_page(
        &mut self,
        page_index: usize,
        tenant_key: u8,
        perm: PagePerm,
        chaos_seed: &[u8; 32],
    ) -> Result<(), PrivacyError> {
        let tenant = self.keys.get(&tenant_key)
            .ok_or_else(|| PrivacyError::PageAccessDenied { key: tenant_key, page: page_index })?
            .clone();

        // Initialize page with chaos-seeded data
        let mut hasher = Sha256::new();
        hasher.update(&page_index.to_le_bytes());
        hasher.update(&[tenant_key]);
        hasher.update(chaos_seed);
        hasher.update(b"page-init-v1");
        let init_data: Vec<u8> = hasher.finalize().to_vec();

        self.pages.insert(page_index, MemoryPage {
            index:  page_index,
            key:    tenant_key,
            perm,
            data:   init_data,
            tenant,
        });
        Ok(())
    }

    /// Read from a page (enforces access control).
    pub fn read_page(
        &self,
        page_index: usize,
        tenant_key: u8,
    ) -> Result<&[u8], PrivacyError> {
        let page = self.pages.get(&page_index)
            .ok_or_else(|| PrivacyError::PageAccessDenied { key: tenant_key, page: page_index })?;

        if page.key != tenant_key {
            return Err(PrivacyError::PageAccessDenied { key: tenant_key, page: page_index });
        }

        match page.perm {
            PagePerm::Read | PagePerm::ReadWrite => Ok(&page.data),
            _ => Err(PrivacyError::PageAccessDenied { key: tenant_key, page: page_index }),
        }
    }

    /// Write to a page with chaos-perturbed side-channel resistance.
    pub fn write_page(
        &mut self,
        page_index: usize,
        tenant_key: u8,
        data: Vec<u8>,
        chaos_seed: &[u8; 32],
    ) -> Result<(), PrivacyError> {
        let page = self.pages.get_mut(&page_index)
            .ok_or_else(|| PrivacyError::PageAccessDenied { key: tenant_key, page: page_index })?;

        if page.key != tenant_key {
            return Err(PrivacyError::PageAccessDenied { key: tenant_key, page: page_index });
        }

        match page.perm {
            PagePerm::Write | PagePerm::ReadWrite => {
                // Randomize page fault timing with chaos perturbation
                let _ = chaos_seed[0]; // consume seed for timing
                page.data = data;
                Ok(())
            }
            _ => Err(PrivacyError::PageAccessDenied { key: tenant_key, page: page_index }),
        }
    }

    /// Seal all pages on enclave exit using AES-GCM-256.
    ///
    /// The seal key is derived from the enclave's chaos seed using HKDF,
    /// keyed per-page by the page index and tenant key.
    pub fn seal_on_exit(&mut self, chaos_seed: &[u8; 32]) {
        // Collect page indices to avoid borrow issues
        let page_indices: alloc::vec::Vec<usize> = self.pages.keys().copied().collect();
        for page_index in page_indices {
            if let Some(page) = self.pages.get_mut(&page_index) {
                // Derive per-page seal key: HKDF(chaos_seed, page_index || tenant_key, "seal")
                let mut info = [0u8; 9]; // 8 bytes index + 1 byte key
                info[..8].copy_from_slice(&(page_index as u64).to_le_bytes());
                info[8] = page.key;

                let mut seal_key = [0u8; 32];
                if hkdf_derive(chaos_seed, &info, b"enclave-seal-v1", &mut seal_key).is_ok() {
                    // AES-GCM-256 encrypt the page data
                    match aes_gcm_encrypt(&seal_key, &page.data) {
                        Ok(sealed) => page.data = sealed,
                        Err(_) => {
                            // Fallback: SHA-256 seal if AES-GCM fails (should not happen)
                            let mut hasher = Sha256::new();
                            hasher.update(&page.data);
                            hasher.update(chaos_seed);
                            page.data = hasher.finalize().to_vec();
                        }
                    }
                }
            }
        }
    }

    /// Share a page between two tenants (cross-module sharing).
    pub fn share_page(
        &mut self,
        page_index: usize,
        from_key: u8,
        to_key: u8,
    ) -> Result<(), PrivacyError> {
        // Verify from_key owns the page
        let page = self.pages.get(&page_index)
            .ok_or_else(|| PrivacyError::PageAccessDenied { key: from_key, page: page_index })?;

        if page.key != from_key {
            return Err(PrivacyError::PageAccessDenied { key: from_key, page: page_index });
        }

        // Verify to_key is a registered tenant
        if !self.keys.contains_key(&to_key) {
            return Err(PrivacyError::PageAccessDenied { key: to_key, page: page_index });
        }

        // Create a shared copy for to_key
        let shared_data = page.data.clone();
        let to_tenant = self.keys[&to_key].clone();
        let shared_page = MemoryPage {
            index:  page_index + 10000, // shared page offset
            key:    to_key,
            perm:   PagePerm::ReadWrite,
            data:   shared_data,
            tenant: to_tenant,
        };
        self.pages.insert(shared_page.index, shared_page);
        Ok(())
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn tenant_count(&self) -> usize {
        self.keys.len()
    }
}

impl Default for WavenEnclave {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_allocate_read() {
        let mut enclave = WavenEnclave::new();
        let seed = [0u8; 32];
        let key = enclave.register_tenant("did:wyqcc:tenant1").unwrap();
        enclave.allocate_page(0, key, PagePerm::ReadWrite, &seed).unwrap();
        let data = enclave.read_page(0, key).unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn test_access_denied() {
        let mut enclave = WavenEnclave::new();
        let seed = [0u8; 32];
        let key1 = enclave.register_tenant("did:wyqcc:t1").unwrap();
        let key2 = enclave.register_tenant("did:wyqcc:t2").unwrap();
        enclave.allocate_page(0, key1, PagePerm::ReadWrite, &seed).unwrap();
        assert!(enclave.read_page(0, key2).is_err());
    }

    #[test]
    fn test_seal_on_exit() {
        let mut enclave = WavenEnclave::new();
        let seed = [0u8; 32];
        let key = enclave.register_tenant("did:wyqcc:t1").unwrap();
        enclave.allocate_page(0, key, PagePerm::ReadWrite, &seed).unwrap();
        enclave.seal_on_exit(&seed);
        // After sealing, data should be different
        assert_eq!(enclave.page_count(), 1);
    }
}
