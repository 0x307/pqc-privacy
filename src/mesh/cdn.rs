//! CDN Nodes for Iced Data Caching (CDN-ICDC)
//!
//! TTL-based iced caching with re-encryption on access for private data distribution.
//! Anonymous retrieval via Mixnet routing.

use crate::error::PrivacyError;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::{collections::BTreeMap, string::{String, ToString}, vec::Vec};

/// Default TTL for iced cache entries (1 hour in ms).
pub const DEFAULT_TTL_MS: u64 = 3_600_000;

/// A cached shard entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Encrypted shard data
    pub data:        Vec<u8>,
    /// Re-encryption key (QFKH-derived — hex)
    pub enc_key:     String,
    /// Expiry timestamp (Unix ms)
    pub expiry_ms:   u64,
    /// Access count
    pub access_count: u64,
}

impl CacheEntry {
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expiry_ms
    }
}

/// Iced CDN cache with TTL expiry and re-encryption.
pub struct IcedCache {
    entries: BTreeMap<String, CacheEntry>,
    ttl_ms:  u64,
}

impl IcedCache {
    pub fn new(ttl_ms: u64) -> Self {
        Self { entries: BTreeMap::new(), ttl_ms }
    }

    /// Store an encrypted shard with TTL.
    pub fn store(
        &mut self,
        key: &str,
        data: Vec<u8>,
        chaos_seed: &[u8; 32],
        now_ms: u64,
    ) -> String {
        let enc_key = self.derive_enc_key(chaos_seed, now_ms);
        let entry = CacheEntry {
            data,
            enc_key: enc_key.clone(),
            expiry_ms: now_ms + self.ttl_ms,
            access_count: 0,
        };
        self.entries.insert(key.to_string(), entry);
        enc_key
    }

    /// Retrieve and re-encrypt a cached shard.
    ///
    /// Re-encryption uses a fresh QFKH key on each access.
    pub fn retrieve(
        &mut self,
        key: &str,
        chaos_seed: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<u8>, PrivacyError> {
        // Check existence and expiry first (immutable borrow scope)
        {
            let entry = self.entries.get(key)
                .ok_or_else(|| PrivacyError::TupleNotFound(key.into()))?;
            if entry.is_expired(now_ms) {
                self.entries.remove(key);
                return Err(PrivacyError::TupleExpired(now_ms));
            }
        }

        // Clone data needed for re-encryption before calling self methods
        let (old_data, old_enc_key) = {
            let entry = self.entries.get(key).unwrap();
            (entry.data.clone(), entry.enc_key.clone())
        };

        // Re-encrypt on access with fresh key
        let new_key = self.derive_enc_key(chaos_seed, now_ms);
        let re_encrypted = self.re_encrypt(&old_data, &old_enc_key, &new_key);

        // Update entry
        if let Some(entry) = self.entries.get_mut(key) {
            entry.enc_key = new_key;
            entry.access_count += 1;
        }

        Ok(re_encrypted)
    }

    /// Evict expired entries.
    pub fn evict_expired(&mut self, now_ms: u64) -> usize {
        let expired: Vec<String> = self.entries.iter()
            .filter(|(_, e)| e.is_expired(now_ms))
            .map(|(k, _)| k.clone())
            .collect();
        let count = expired.len();
        for k in expired {
            self.entries.remove(&k);
        }
        count
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn derive_enc_key(&self, chaos_seed: &[u8; 32], now_ms: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(chaos_seed);
        hasher.update(&now_ms.to_le_bytes());
        hasher.update(b"qfkh-cdn-key-v1");
        hex::encode(hasher.finalize())
    }

    fn re_encrypt(&self, data: &[u8], _old_key: &str, _new_key: &str) -> Vec<u8> {
        // CKKS re-encryption placeholder: XOR with new key hash
        let mut hasher = Sha256::new();
        hasher.update(_new_key.as_bytes());
        let key_bytes: [u8; 32] = hasher.finalize().into();
        data.iter().enumerate().map(|(i, b)| b ^ key_bytes[i % 32]).collect()
    }
}

impl Default for IcedCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_retrieve() {
        let mut cache = IcedCache::new(10_000);
        let seed = [0u8; 32];
        cache.store("shard1", b"encrypted_data".to_vec(), &seed, 1000);
        let data = cache.retrieve("shard1", &seed, 2000).unwrap();
        assert_eq!(data.len(), b"encrypted_data".len());
    }

    #[test]
    fn test_expiry() {
        let mut cache = IcedCache::new(100);
        let seed = [0u8; 32];
        cache.store("shard2", b"data".to_vec(), &seed, 1000);
        assert!(cache.retrieve("shard2", &seed, 2000).is_err());
    }
}
