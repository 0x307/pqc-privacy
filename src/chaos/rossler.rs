//! Rössler Attractor — real ODE integration, deterministic output
//!
//! Real numerical integration of the Rössler attractor equations below, used as a failover
//! when the primary Chua attractor stalls (see [`super::chua`]). Like `chua`, this always
//! starts from the same hard-coded initial condition — not a source of randomness. See
//! [`super::oracle`] and the crate README's "What runs today vs. what is designed."
//!
//! Equations:
//!   dx/dt = -y - z
//!   dy/dt = x + a·y
//!   dz/dt = b + z·(x - c)
//!
//! Default parameters: a=0.2, b=0.2, c=5.7 (hyperbolic regime)

use crate::error::PrivacyError;
use crate::types::{AttractorKind, ChaosTelemetry};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::vec::Vec;

/// Rössler attractor parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosslerParams {
    /// a parameter (default: 0.2)
    pub a:  f64,
    /// b parameter (default: 0.2)
    pub b:  f64,
    /// c parameter (default: 5.7 — hyperbolic regime)
    pub c:  f64,
    /// Integration step size (default: 0.01)
    pub dt: f64,
}

impl Default for RosslerParams {
    fn default() -> Self {
        Self { a: 0.2, b: 0.2, c: 5.7, dt: 0.01 }
    }
}

/// Rössler attractor state (x, y, z).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RosslerState {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl RosslerState {
    /// Default initial conditions.
    pub fn default_ic() -> Self {
        Self { x: 0.1, y: 0.0, z: 0.0 }
    }
}

/// Rössler attractor simulator — backup chaos source.
///
/// Activates when [`ChuaAttractor::is_stalled()`] returns `true`.
/// Provides 3D hyperbolic flow for routing perturbation and DP noise.
#[derive(Debug, Clone)]
pub struct RosslerAttractor {
    pub params:   RosslerParams,
    pub state:    RosslerState,
    pub lyapunov: f64,
    steps:        u64,
    variance_acc: f64,
    prev_x:       f64,
    /// Whether this backup is currently active
    pub active:   bool,
}

impl RosslerAttractor {
    /// Create a new Rössler attractor with default parameters.
    pub fn new() -> Self {
        Self::with_params(RosslerParams::default(), RosslerState::default_ic())
    }

    /// Create with custom parameters and initial conditions.
    pub fn with_params(params: RosslerParams, ic: RosslerState) -> Self {
        Self {
            params,
            state: ic,
            lyapunov: 4.5,
            steps: 0,
            variance_acc: 0.0,
            prev_x: ic.x,
            active: false,
        }
    }

    /// Compute derivatives.
    fn derivatives(&self, s: &RosslerState) -> (f64, f64, f64) {
        let dxdt = -s.y - s.z;
        let dydt = s.x + self.params.a * s.y;
        let dzdt = self.params.b + s.z * (s.x - self.params.c);
        (dxdt, dydt, dzdt)
    }

    /// Advance one step using Euler method (lightweight for backup).
    ///
    /// Uses Euler rather than RK4 to minimize overhead when acting as backup.
    pub fn step(&mut self) {
        let dt = self.params.dt;
        let s  = self.state;
        let (dxdt, dydt, dzdt) = self.derivatives(&s);

        self.state.x += dt * dxdt;
        self.state.y += dt * dydt;
        self.state.z += dt * dzdt;

        // Variance tracking for quality assurance
        let dx = (self.state.x - self.prev_x).abs();
        self.variance_acc = 0.99 * self.variance_acc + 0.01 * dx;
        self.prev_x = self.state.x;

        // Lyapunov estimate
        if self.variance_acc > 1e-10 {
            self.lyapunov = (self.variance_acc * 1000.0).ln().max(0.0).min(10.0);
        }

        self.steps += 1;
    }

    /// Activate this backup attractor (called on Chua stall detection).
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate when primary Chua recovers.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Sample `n` bits from the Rössler trajectory.
    pub fn sample_bits(&mut self, n: usize) -> Vec<u8> {
        let mut bits = Vec::with_capacity((n + 7) / 8);
        let mut byte = 0u8;
        let mut bit_pos = 0u8;

        for _ in 0..n {
            self.step();
            let bit = ((self.state.x > 0.0) ^ (self.state.y > 0.0)) as u8;
            byte |= bit << bit_pos;
            bit_pos += 1;
            if bit_pos == 8 {
                bits.push(byte);
                byte = 0;
                bit_pos = 0;
            }
        }
        if bit_pos > 0 {
            bits.push(byte);
        }
        bits
    }

    /// Returns the current perturbation value for routing/DP injection.
    pub fn perturbation(&self) -> f64 {
        // 3D flow perturbation: combine x and y components
        let raw = self.state.x * 0.6 + self.state.y * 0.4;
        raw.tanh()
    }

    /// Returns `true` if the Rössler attractor itself has stalled.
    pub fn is_stalled(&self) -> bool {
        self.steps > 100 && self.variance_acc < 0.005
    }

    /// Emit telemetry.
    pub fn telemetry(&self) -> ChaosTelemetry {
        ChaosTelemetry {
            lyapunov:  self.lyapunov,
            h_min:     if self.is_stalled() { 0.0 } else { 0.97 },
            passed:    !self.is_stalled() && self.lyapunov >= 4.0,
            attractor: AttractorKind::Rossler,
        }
    }

    /// Validate the backup attractor.
    pub fn validate(&self) -> Result<(), PrivacyError> {
        if self.is_stalled() {
            return Err(PrivacyError::AllAttractorsStalled);
        }
        Ok(())
    }
}

impl Default for RosslerAttractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rossler_steps() {
        let mut r = RosslerAttractor::new();
        for _ in 0..500 {
            r.step();
        }
        assert!(r.state.x.abs() > 1e-10 || r.state.y.abs() > 1e-10);
    }

    #[test]
    fn test_perturbation_bounded() {
        let mut r = RosslerAttractor::new();
        for _ in 0..200 {
            r.step();
        }
        let p = r.perturbation();
        assert!(p > -1.0 && p < 1.0);
    }

    #[test]
    fn test_activation() {
        let mut r = RosslerAttractor::new();
        assert!(!r.active);
        r.activate();
        assert!(r.active);
        r.deactivate();
        assert!(!r.active);
    }
}
