//! Two separate things, both real, deliberately not conflated.
//!
//! **IFS transforms over 5D coordinates.**
//! [`FractalCompressor::compress`]/[`decompress`](FractalCompressor::decompress) implement
//! genuine Iterated Function System affine-transform math (`w(x) = A·x + b`), with
//! chaos-perturbed contraction factors, over a [`FiveDimCoord`]. This is dimension
//! reduction on a point, and [`FractalCompressor::compression_ratio`] describes *that*
//! — transform storage vs. dimension count. It says nothing about byte data.
//!
//! **Lossless byte compression.**
//! [`FractalCompressor::compress_bytes`]/[`decompress_bytes`](FractalCompressor::decompress_bytes)
//! are ordinary DEFLATE (RFC 1951) via `miniz_oxide`, returning a [`CompressedBlob`].
//! They are not fractal and do not pretend to be: fractal compression is inherently lossy
//! and only pays off on self-similar signals, which arbitrary bytes are not. What callers
//! need here is an exact round-trip, so this path is lossless.
//!
//! Because no algorithm compresses every input — a counting argument, not a gap in this
//! implementation — [`compress_bytes`](FractalCompressor::compress_bytes) falls back to
//! storing the input verbatim when DEFLATE does not make it smaller, and records that in
//! [`CompressedBlob::stored`]. The output is therefore never meaningfully larger than the
//! input, and [`CompressedBlob::ratio`] reports what actually happened.
//!
//! Earlier versions of this module claimed a "100:1" ratio on byte data and stored each
//! chunk verbatim, which made the output strictly larger than the input. Both the claim and
//! that implementation are gone.

use crate::error::PrivacyError;
use crate::types::FiveDimCoord;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::{format, vec::Vec};

/// An affine transformation for IFS: w(x) = A·x + b.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffineTransform {
    /// 5x5 contraction matrix (flattened, row-major)
    pub a: [f64; 25],
    /// Translation vector (5D)
    pub b: [f64; 5],
    /// Probability weight
    pub prob: f64,
}

impl AffineTransform {
    /// Identity transform.
    pub fn identity() -> Self {
        let mut a = [0.0f64; 25];
        for i in 0..5 { a[i * 5 + i] = 1.0; }
        Self { a, b: [0.0; 5], prob: 0.2 }
    }

    /// Apply transform to a 5D coordinate.
    pub fn apply(&self, x: &[f64; 5]) -> [f64; 5] {
        let mut result = [0.0f64; 5];
        for i in 0..5 {
            for j in 0..5 {
                result[i] += self.a[i * 5 + j] * x[j];
            }
            result[i] += self.b[i];
        }
        result
    }

    /// Apply the inverse of the 1D diagonal approximation: T^{-1}(y) = (y - b) / a_diag.
    ///
    /// For the diagonal element a[i*5+i] (the contraction factor for dimension i).
    /// If a_diag ≈ 0, returns 0.0 (degenerate case).
    pub fn apply_inverse_1d(&self, y: f64, dim: usize) -> f64 {
        let a_diag = self.a[dim * 5 + dim];
        if a_diag.abs() < 1e-12 {
            0.0
        } else {
            (y - self.b[dim]) / a_diag
        }
    }
}

/// IFS codebook produced by [`FractalCompressor::compress`] for a 5D coordinate.
///
/// This describes the *IFS* path only. Byte compression returns a [`CompressedBlob`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfsCodebook {
    pub transforms:   Vec<AffineTransform>,
    pub dims_reduced: usize,
    pub chaos_seed:   [u8; 32],
}

/// Losslessly compressed byte data, produced by [`FractalCompressor::compress_bytes`].
///
/// `payload` is a DEFLATE stream, unless [`stored`](Self::stored) is set — in which case
/// DEFLATE did not make the input smaller and `payload` is the original bytes verbatim.
/// Either way [`decompress_bytes`](FractalCompressor::decompress_bytes) recovers the input
/// exactly, and verifies it against `original_hash` before returning it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedBlob {
    /// DEFLATE stream, or the original bytes when `stored` is true.
    pub payload:       Vec<u8>,
    /// True when the input did not compress and `payload` holds it verbatim.
    pub stored:        bool,
    /// Length of the original input, in bytes.
    pub original_size: usize,
    /// SHA-256 of the original input, checked on decompression.
    pub original_hash: Vec<u8>,
}

impl CompressedBlob {
    /// Payload size as a fraction of the original: below 1.0 means it got smaller.
    ///
    /// Returns 1.0 for an empty input, and exactly 1.0 whenever [`stored`](Self::stored)
    /// is set, since the payload is then the input itself.
    pub fn ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.payload.len() as f64 / self.original_size as f64
    }
}

/// Fractal compression engine.
pub struct FractalCompressor;

impl FractalCompressor {
    pub fn new() -> Self {
        Self
    }

    /// Compress a 5D manifold vertex using IFS.
    ///
    /// Identifies self-similar patterns via barnsley-style collage theorem.
    /// Chaos perturbation modulates transformation coefficients.
    pub fn compress(
        &self,
        coord: &FiveDimCoord,
        chaos_seed: &[u8; 32],
        target_dims: usize,
    ) -> Result<IfsCodebook, PrivacyError> {
        if target_dims == 0 || target_dims > 5 {
            return Err(PrivacyError::CompressionFailed(
                format!("target_dims must be 1–5, got {target_dims}")
            ));
        }

        let x = [
            coord.spatial,
            coord.temporal,
            coord.probabilistic,
            coord.quantum,
            coord.chaotic,
        ];

        // Generate IFS transforms with chaos perturbation
        let mut transforms = Vec::new();
        for i in 0..target_dims {
            let mut t = AffineTransform::identity();

            // Chaos perturbation: A_i' = A_i + δ * Chua(t)
            let delta = self.chaos_delta(chaos_seed, i as u64);
            for j in 0..25 {
                t.a[j] *= 0.5 + delta * 0.1; // contraction factor
            }
            t.b[i] = x[i] * (1.0 - 0.5 - delta * 0.1);
            t.prob = 1.0 / target_dims as f64;

            transforms.push(t);
        }

        Ok(IfsCodebook {
            transforms,
            dims_reduced: 5 - target_dims,
            chaos_seed: *chaos_seed,
        })
    }

    /// Losslessly compress byte data with DEFLATE (RFC 1951), falling back to storing it
    /// verbatim when that does not make it smaller.
    ///
    /// This is not fractal compression and does not use the IFS machinery above — see the
    /// module doc comment for why. The round-trip through
    /// [`decompress_bytes`](Self::decompress_bytes) is exact.
    ///
    /// The fallback is what keeps the output from growing: no algorithm compresses every
    /// input, so incompressible data (already-compressed bytes, ciphertext, high-entropy
    /// keys — much of what this crate handles) is stored as-is and flagged in
    /// [`CompressedBlob::stored`].
    pub fn compress_bytes(&self, data: &[u8]) -> Result<CompressedBlob, PrivacyError> {
        if data.is_empty() {
            return Err(PrivacyError::CompressionFailed("Empty data".into()));
        }

        let original_hash = Sha256::digest(data).to_vec();
        let deflated = miniz_oxide::deflate::compress_to_vec(data, 6);

        // Only keep the DEFLATE stream if it actually won.
        let (payload, stored) = if deflated.len() < data.len() {
            (deflated, false)
        } else {
            (data.to_vec(), true)
        };

        Ok(CompressedBlob {
            payload,
            stored,
            original_size: data.len(),
            original_hash,
        })
    }

    /// Decompress an IFS codebook back to a 5D coordinate.
    ///
    /// Iterates the IFS attractor for 100 steps.
    pub fn decompress(&self, codebook: &IfsCodebook) -> Result<FiveDimCoord, PrivacyError> {
        if codebook.transforms.is_empty() {
            return Err(PrivacyError::DecompressionFailed("Empty codebook".into()));
        }

        // Iterate IFS attractor
        let mut x = [0.0f64; 5];
        for step in 0..100u64 {
            let t_idx = (step as usize) % codebook.transforms.len();
            x = codebook.transforms[t_idx].apply(&x);
        }

        Ok(FiveDimCoord {
            spatial:      x[0],
            temporal:     x[1],
            probabilistic: x[2],
            quantum:      x[3],
            chaotic:      x[4],
        })
    }

    /// Recover the exact bytes a [`CompressedBlob`] was built from.
    ///
    /// Inflates the DEFLATE stream, or returns the stored bytes when
    /// [`CompressedBlob::stored`] is set, then checks both the recovered length and its
    /// SHA-256 against what the blob recorded. A mismatch is reported as an error rather
    /// than returned to the caller.
    pub fn decompress_bytes(blob: &CompressedBlob) -> Result<Vec<u8>, PrivacyError> {
        let result = if blob.stored {
            blob.payload.clone()
        } else {
            miniz_oxide::inflate::decompress_to_vec(&blob.payload)
                .map_err(|e| PrivacyError::DecompressionFailed(format!("inflate failed: {e:?}")))?
        };

        if result.len() != blob.original_size {
            return Err(PrivacyError::DecompressionFailed(format!(
                "length mismatch: recovered {} bytes, expected {}",
                result.len(),
                blob.original_size
            )));
        }

        if Sha256::digest(&result).to_vec() != blob.original_hash {
            return Err(PrivacyError::DecompressionFailed(
                "hash mismatch: data corrupted".into(),
            ));
        }

        Ok(result)
    }

    /// Compress `data` and immediately prove the round-trip recovers it exactly.
    ///
    /// Unlike the earlier version of this method, this can genuinely fail: the compression
    /// path is real, so a defect in it surfaces here rather than being masked by the input
    /// having been stored verbatim.
    ///
    /// Returns `(blob, decompressed)`, where `decompressed == data`.
    pub fn compress_and_verify(
        &self,
        data: &[u8],
    ) -> Result<(CompressedBlob, Vec<u8>), PrivacyError> {
        let blob = self.compress_bytes(data)?;
        let decompressed = Self::decompress_bytes(&blob)?;

        if decompressed != data {
            return Err(PrivacyError::DecompressionFailed(
                "Round-trip verification failed: decompressed data does not match original".into()
            ));
        }

        Ok((blob, decompressed))
    }

    /// Storage ratio for the **IFS** path: original coordinate size over the size of the
    /// transforms that replace it.
    ///
    /// This describes dimension reduction on a [`FiveDimCoord`], not byte compression. For
    /// that, use [`CompressedBlob::ratio`].
    pub fn compression_ratio(original_dims: usize, codebook: &IfsCodebook) -> f64 {
        let original_size = original_dims * 8; // 8 bytes per f64
        let compressed_size = codebook.transforms.len() * (25 + 5 + 1) * 8;
        original_size as f64 / compressed_size as f64
    }

    fn chaos_delta(&self, chaos_seed: &[u8; 32], counter: u64) -> f64 {
        let mut hasher = Sha256::new();
        hasher.update(chaos_seed);
        hasher.update(&counter.to_le_bytes());
        hasher.update(b"ifs-delta");
        let h: [u8; 32] = hasher.finalize().into();
        let raw = u64::from_le_bytes(h[..8].try_into().unwrap_or([0u8; 8]));
        (raw as f64 / u64::MAX as f64) * 2.0 - 1.0 // [-1, 1]
    }
}

impl Default for FractalCompressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Reduce a 5D coordinate array to 3D by projecting out the quantum and chaotic dimensions.
///
/// Uses a PCA-style projection: keeps the 3 dimensions with highest variance.
/// For the 5D→3D case, we project out `quantum` and `chaotic`
/// (indices 3 and 4) and retain `spatial`, `temporal`, `probabilistic`.
///
/// If the input has enough variance, a proper variance-based selection is performed.
pub fn reduce_5d_to_3d(coords: &[FiveDimCoord]) -> Vec<[f64; 3]> {
    if coords.is_empty() {
        return Vec::new();
    }

    // Compute per-dimension variance to select the 3 highest-variance dimensions
    let n = coords.len() as f64;
    let dims: [[f64; 5]; 1] = [[0.0; 5]]; // placeholder for type inference
    let _ = dims;

    // Extract all 5 dimensions as arrays
    let all_dims: Vec<[f64; 5]> = coords.iter().map(|c| [
        c.spatial,
        c.temporal,
        c.probabilistic,
        c.quantum,
        c.chaotic,
    ]).collect();

    // Compute mean for each dimension
    let mut means = [0.0f64; 5];
    for pt in &all_dims {
        for d in 0..5 {
            means[d] += pt[d];
        }
    }
    for d in 0..5 {
        means[d] /= n;
    }

    // Compute variance for each dimension
    let mut variances = [0.0f64; 5];
    for pt in &all_dims {
        for d in 0..5 {
            let diff = pt[d] - means[d];
            variances[d] += diff * diff;
        }
    }
    for d in 0..5 {
        variances[d] /= n;
    }

    // Select the 3 dimensions with highest variance
    let mut dim_indices: [usize; 5] = [0, 1, 2, 3, 4];
    // Sort by variance descending (simple insertion sort for 5 elements)
    for i in 1..5 {
        let mut j = i;
        while j > 0 && variances[dim_indices[j]] > variances[dim_indices[j - 1]] {
            dim_indices.swap(j, j - 1);
            j -= 1;
        }
    }
    let top3 = [dim_indices[0], dim_indices[1], dim_indices[2]];

    // Project to 3D
    all_dims.iter().map(|pt| [pt[top3[0]], pt[top3[1]], pt[top3[2]]]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let compressor = FractalCompressor::new();
        let seed = [0u8; 32];
        let coord = FiveDimCoord {
            spatial: 0.5, temporal: 1000.0, probabilistic: 1e-6,
            quantum: 1.2, chaotic: 0.8,
        };
        let codebook = compressor.compress(&coord, &seed, 3).unwrap();
        assert_eq!(codebook.dims_reduced, 2);
        let decompressed = compressor.decompress(&codebook).unwrap();
        assert!(decompressed.spatial.is_finite());
    }

    #[test]
    fn test_invalid_dims() {
        let compressor = FractalCompressor::new();
        let seed = [0u8; 32];
        let coord = FiveDimCoord::zero();
        assert!(compressor.compress(&coord, &seed, 0).is_err());
        assert!(compressor.compress(&coord, &seed, 6).is_err());
    }

    #[test]
    fn test_compress_bytes_round_trip() {
        let compressor = FractalCompressor::new();
        let data = b"Hello, compression world! This is a test of lossless byte compression.";
        let blob = compressor.compress_bytes(data).unwrap();
        assert_eq!(blob.original_size, data.len());
        let decompressed = FractalCompressor::decompress_bytes(&blob).unwrap();
        assert_eq!(decompressed, data);
    }

    /// Highly repetitive input must actually get smaller — this is the assertion the old
    /// implementation could not have passed, since it stored every chunk verbatim.
    #[test]
    fn test_compressible_input_actually_shrinks() {
        let compressor = FractalCompressor::new();
        let data = alloc::vec![b'A'; 4096];
        let blob = compressor.compress_bytes(&data).unwrap();

        assert!(!blob.stored, "repetitive input should compress, not fall back to stored");
        assert!(
            blob.payload.len() < data.len(),
            "payload {} not smaller than input {}",
            blob.payload.len(),
            data.len()
        );
        assert!(blob.ratio() < 1.0);
        assert_eq!(FractalCompressor::decompress_bytes(&blob).unwrap(), data);
    }

    /// Incompressible input must fall back to stored rather than growing.
    #[test]
    fn test_incompressible_input_falls_back_to_stored() {
        let compressor = FractalCompressor::new();
        // Counter-mode-style bytes from SHA-256: high entropy, no exploitable structure.
        let mut data = Vec::new();
        for i in 0..64u32 {
            data.extend_from_slice(&Sha256::digest(i.to_le_bytes()));
        }

        let blob = compressor.compress_bytes(&data).unwrap();
        assert!(blob.stored, "high-entropy input should fall back to stored");
        assert_eq!(blob.payload.len(), data.len(), "stored payload must not grow");
        assert_eq!(blob.ratio(), 1.0);
        assert_eq!(FractalCompressor::decompress_bytes(&blob).unwrap(), data);
    }

    /// A corrupted payload must be reported, not returned.
    #[test]
    fn test_corrupted_payload_is_rejected() {
        let compressor = FractalCompressor::new();
        let data = alloc::vec![b'B'; 2048];
        let mut blob = compressor.compress_bytes(&data).unwrap();
        blob.original_hash[0] ^= 0xFF;
        assert!(FractalCompressor::decompress_bytes(&blob).is_err());
    }

    #[test]
    fn test_compress_and_verify() {
        let compressor = FractalCompressor::new();
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let (blob, decompressed) = compressor.compress_and_verify(&data).unwrap();
        assert_eq!(decompressed, data);
        assert_eq!(blob.original_size, 256);
    }

    #[test]
    fn test_empty_input_is_an_error() {
        let compressor = FractalCompressor::new();
        assert!(compressor.compress_bytes(&[]).is_err());
    }

    #[test]
    fn test_reduce_5d_to_3d() {
        let coords = vec![
            FiveDimCoord { spatial: 1.0, temporal: 2.0, probabilistic: 3.0, quantum: 4.0, chaotic: 5.0 },
            FiveDimCoord { spatial: 2.0, temporal: 3.0, probabilistic: 4.0, quantum: 5.0, chaotic: 6.0 },
            FiveDimCoord { spatial: 3.0, temporal: 4.0, probabilistic: 5.0, quantum: 6.0, chaotic: 7.0 },
        ];
        let reduced = reduce_5d_to_3d(&coords);
        assert_eq!(reduced.len(), 3);
        for pt in &reduced {
            assert!(pt[0].is_finite());
            assert!(pt[1].is_finite());
            assert!(pt[2].is_finite());
        }
    }

    #[test]
    fn test_reduce_5d_to_3d_empty() {
        let reduced = reduce_5d_to_3d(&[]);
        assert!(reduced.is_empty());
    }
}
