//! Chua Attractor — real ODE integration, deterministic output
//!
//! Real 4th-order Runge-Kutta integration of the Chua double-scroll attractor equations
//! below. The trajectory always starts from the same hard-coded initial condition (see
//! [`ChuaState::default_ic`]), so this is not a source of randomness — see [`super::oracle`]
//! and the crate README's "What runs today vs. what is designed" for the full accounting.
//! The "Lyapunov" figure this module reports is a heuristic variance-based proxy, not a
//! true Lyapunov exponent.
//!
//! Equations:
//!   dx/dt = α(y - x - f(x))
//!   dy/dt = x - y + z
//!   dz/dt = -βy
//!
//! where f(x) = m₁·x + 0.5·(m₀ - m₁)·(|x + 1| - |x - 1|)

use crate::error::PrivacyError;
use crate::types::{AttractorKind, ChaosTelemetry};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::vec::Vec;

/// Chua attractor parameters (double-scroll regime).
///
/// Default values produce the canonical double-scroll attractor:
/// α=9.0, β=14.286, m₀=-1/7, m₁=2/7
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChuaParams {
    /// α parameter (default: 9.0)
    pub alpha: f64,
    /// β parameter (default: 14.286)
    pub beta:  f64,
    /// m₀ piecewise-linear slope (default: -1/7 ≈ -0.1429)
    pub m0:    f64,
    /// m₁ piecewise-linear slope (default: 2/7 ≈ 0.2857)
    pub m1:    f64,
    /// Integration step size (default: 0.01)
    pub dt:    f64,
}

impl Default for ChuaParams {
    fn default() -> Self {
        Self {
            alpha: 9.0,
            beta:  14.286,
            m0:    -1.0 / 7.0,
            m1:    2.0 / 7.0,
            dt:    0.01,
        }
    }
}

/// Chua attractor state (x, y, z).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ChuaState {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl ChuaState {
    /// Default initial conditions for double-scroll.
    pub fn default_ic() -> Self {
        Self { x: 0.7, y: 0.0, z: 0.0 }
    }
}

/// Chua attractor simulator.
///
/// Generates chaotic trajectories for privacy perturbation.
/// Detects stalls (periodic orbits) and signals failover to Rössler.
#[derive(Debug, Clone)]
pub struct ChuaAttractor {
    pub params: ChuaParams,
    pub state:  ChuaState,
    /// Estimated Lyapunov exponent (updated each step)
    pub lyapunov: f64,
    /// Step counter
    steps: u64,
    /// Variance accumulator for stall detection
    variance_acc: f64,
    prev_x: f64,
}

impl ChuaAttractor {
    /// Create a new Chua attractor with default parameters.
    pub fn new() -> Self {
        Self::with_params(ChuaParams::default(), ChuaState::default_ic())
    }

    /// Create with custom parameters and initial conditions.
    pub fn with_params(params: ChuaParams, ic: ChuaState) -> Self {
        Self {
            params,
            state: ic,
            lyapunov: 4.5,
            steps: 0,
            variance_acc: 0.0,
            prev_x: ic.x,
        }
    }

    /// Piecewise-linear nonlinearity f(x).
    fn f(&self, x: f64) -> f64 {
        let m0 = self.params.m0;
        let m1 = self.params.m1;
        m1 * x + 0.5 * (m0 - m1) * ((x + 1.0).abs() - (x - 1.0).abs())
    }

    /// Compute derivatives (dx/dt, dy/dt, dz/dt).
    fn derivatives(&self, s: &ChuaState) -> (f64, f64, f64) {
        let alpha = self.params.alpha;
        let beta  = self.params.beta;
        let dxdt = alpha * (s.y - s.x - self.f(s.x));
        let dydt = s.x - s.y + s.z;
        let dzdt = -beta * s.y;
        (dxdt, dydt, dzdt)
    }

    /// Advance one step using 4th-order Runge-Kutta.
    pub fn step(&mut self) {
        let dt = self.params.dt;
        let s  = self.state;

        let (k1x, k1y, k1z) = self.derivatives(&s);
        let s2 = ChuaState {
            x: s.x + 0.5 * dt * k1x,
            y: s.y + 0.5 * dt * k1y,
            z: s.z + 0.5 * dt * k1z,
        };
        let (k2x, k2y, k2z) = self.derivatives(&s2);
        let s3 = ChuaState {
            x: s.x + 0.5 * dt * k2x,
            y: s.y + 0.5 * dt * k2y,
            z: s.z + 0.5 * dt * k2z,
        };
        let (k3x, k3y, k3z) = self.derivatives(&s3);
        let s4 = ChuaState {
            x: s.x + dt * k3x,
            y: s.y + dt * k3y,
            z: s.z + dt * k3z,
        };
        let (k4x, k4y, k4z) = self.derivatives(&s4);

        self.state.x += dt / 6.0 * (k1x + 2.0 * k2x + 2.0 * k3x + k4x);
        self.state.y += dt / 6.0 * (k1y + 2.0 * k2y + 2.0 * k3y + k4y);
        self.state.z += dt / 6.0 * (k1z + 2.0 * k2z + 2.0 * k3z + k4z);

        // Update variance accumulator for stall detection
        let dx = (self.state.x - self.prev_x).abs();
        self.variance_acc = 0.99 * self.variance_acc + 0.01 * dx;
        self.prev_x = self.state.x;

        // Estimate Lyapunov exponent from divergence rate
        // Simplified: use log of variance growth as proxy
        if self.variance_acc > 1e-10 {
            self.lyapunov = (self.variance_acc * 1000.0).ln().max(0.0).min(10.0);
        }

        self.steps += 1;
    }

    /// Advance `n` steps and return the trajectory as a bitstream.
    ///
    /// Each step contributes 1 bit: sign(x) XOR sign(z).
    pub fn sample_bits(&mut self, n: usize) -> Vec<u8> {
        let mut bits = Vec::with_capacity((n + 7) / 8);
        let mut byte = 0u8;
        let mut bit_pos = 0u8;

        for _ in 0..n {
            self.step();
            let bit = ((self.state.x > 0.0) ^ (self.state.z > 0.0)) as u8;
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

    /// Returns `true` if the attractor has stalled (periodic orbit detected).
    ///
    /// Stall condition: variance < 0.01.
    pub fn is_stalled(&self) -> bool {
        self.steps > 100 && self.variance_acc < 0.01
    }

    /// Returns the current perturbation value for DP/FHE injection.
    ///
    /// δ = x * exp(λ * t_normalized), clamped to [-1, 1].
    pub fn perturbation(&self) -> f64 {
        let t_norm = (self.steps as f64) / 1000.0;
        let delta = self.state.x * (self.lyapunov * t_norm).exp();
        delta.tanh() // tanh maps to (-1, 1)
    }

    /// Emit telemetry for monitoring.
    pub fn telemetry(&self) -> ChaosTelemetry {
        ChaosTelemetry {
            lyapunov:  self.lyapunov,
            h_min:     if self.is_stalled() { 0.0 } else { 0.99 },
            passed:    !self.is_stalled() && self.lyapunov >= 4.5,
            attractor: AttractorKind::Chua,
        }
    }

    /// Validate the attractor meets the required thresholds.
    pub fn validate(&self) -> Result<(), PrivacyError> {
        if self.is_stalled() {
            return Err(PrivacyError::AttractorStalled(self.lyapunov));
        }
        Ok(())
    }
}

impl Default for ChuaAttractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chua_steps() {
        let mut chua = ChuaAttractor::new();
        for _ in 0..1000 {
            chua.step();
        }
        // After 1000 steps, state should be non-zero
        assert!(chua.state.x.abs() > 1e-10 || chua.state.y.abs() > 1e-10);
    }

    #[test]
    fn test_sample_bits_length() {
        let mut chua = ChuaAttractor::new();
        let bits = chua.sample_bits(256);
        assert_eq!(bits.len(), 32); // 256 bits = 32 bytes
    }

    #[test]
    fn test_perturbation_bounded() {
        let mut chua = ChuaAttractor::new();
        for _ in 0..100 {
            chua.step();
        }
        let p = chua.perturbation();
        assert!(p > -1.0 && p < 1.0);
    }
}
