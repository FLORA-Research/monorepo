//! Valve control and the irrigation state machine.
//!
//! One controller owns every path to the valve — manual, automatic, and
//! the safety caps — so no path can bypass `max_runtime_s` or
//! `min_off_s`. A manual command takes precedence until its deadline,
//! and missing moisture always closes the valve: a node that cannot see
//! its sensor must not water indefinitely.

use crate::config::NodeConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualError {
    InvalidDuration,
    MinimumOffTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrrigationController {
    valve_open: bool,
    opened_at_s: u32,
    last_closed_at_s: u32,
    manual_until_s: Option<u32>,
}

impl IrrigationController {
    pub const fn new(now_s: u32) -> Self {
        Self {
            valve_open: false,
            opened_at_s: now_s,
            last_closed_at_s: now_s,
            manual_until_s: None,
        }
    }

    pub const fn is_open(&self) -> bool {
        self.valve_open
    }

    /// Apply a manual command. Close is always allowed; open is bounded
    /// by the configured runtime cap and the minimum off time.
    pub fn set_manual(
        &mut self,
        open: bool,
        duration_s: u16,
        config: &NodeConfig,
        now_s: u32,
    ) -> Result<(), ManualError> {
        if !open {
            self.manual_until_s = None;
            self.close(now_s);
            return Ok(());
        }
        if duration_s == 0 || duration_s > config.max_runtime_s {
            return Err(ManualError::InvalidDuration);
        }
        if !self.off_time_elapsed(config, now_s) {
            return Err(ManualError::MinimumOffTime);
        }
        self.manual_until_s = Some(now_s.wrapping_add(u32::from(duration_s)));
        self.open(now_s);
        Ok(())
    }

    /// Advance the automatic controller. Missing/un-calibrated moisture
    /// always closes the valve. Returns the valve state after the update.
    pub fn update_auto(
        &mut self,
        moisture_per_mille: Option<u16>,
        config: &NodeConfig,
        now_s: u32,
    ) -> bool {
        if let Some(until) = self.manual_until_s {
            if deadline_reached(now_s, until) || self.max_runtime_reached(config, now_s) {
                self.manual_until_s = None;
                self.close(now_s);
            }
            return self.valve_open;
        }

        if self.valve_open {
            let saturated = moisture_per_mille.is_some_and(|value| value >= config.wet_threshold);
            if moisture_per_mille.is_none() || saturated || self.max_runtime_reached(config, now_s)
            {
                self.close(now_s);
            }
        } else if moisture_per_mille.is_some_and(|value| value < config.dry_threshold)
            && self.off_time_elapsed(config, now_s)
        {
            self.open(now_s);
        }
        self.valve_open
    }

    fn open(&mut self, now_s: u32) {
        if !self.valve_open {
            self.valve_open = true;
            self.opened_at_s = now_s;
        }
    }

    fn close(&mut self, now_s: u32) {
        if self.valve_open {
            self.valve_open = false;
            self.last_closed_at_s = now_s;
        }
    }

    fn max_runtime_reached(&self, config: &NodeConfig, now_s: u32) -> bool {
        self.valve_open && now_s.wrapping_sub(self.opened_at_s) >= u32::from(config.max_runtime_s)
    }

    fn off_time_elapsed(&self, config: &NodeConfig, now_s: u32) -> bool {
        now_s.wrapping_sub(self.last_closed_at_s) >= u32::from(config.min_off_s)
    }
}

fn deadline_reached(now_s: u32, deadline_s: u32) -> bool {
    (now_s.wrapping_sub(deadline_s) as i32) >= 0
}
