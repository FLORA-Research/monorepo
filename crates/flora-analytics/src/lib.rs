//! Reports for Chapter 4: sensor validation, water savings, and fleet health.
//!
//! The statistics are computed in Rust from rows fetched by SQL, rather than in
//! SQL, for two reasons. The MAE procedure pairs each node reading with the
//! nearest independent reference measurement, and expressing "nearest within a
//! tolerance" in a way that can be reasoned about and tested is easier in code
//! than in a windowed join. And the paper needs the formula to be inspectable:
//! a reader can check these functions against the methodology chapter, which is
//! not true of a nested query.
//!
//! Unavailable metrics are `NULL` in the database, never a sentinel, so every
//! function here skips `None` rather than averaging it in.

use chrono::{DateTime, Duration, Utc};
use flora_db::models::NewReading;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnalyticsError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// A node reading paired with the reference measurement it is compared against.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PairedSample {
    pub sensor: f32,
    pub reference: f32,
}

/// Mean absolute error: `mean(|sensor - reference|)`.
///
/// Returns `None` for an empty set rather than zero, because "no paired
/// samples" and "perfect agreement" are very different findings and the paper
/// must not confuse them.
pub fn mean_absolute_error(pairs: &[PairedSample]) -> Option<f64> {
    if pairs.is_empty() {
        return None;
    }
    let total: f64 = pairs
        .iter()
        .map(|pair| f64::from((pair.sensor - pair.reference).abs()))
        .sum();
    Some(total / pairs.len() as f64)
}

/// Root mean squared error, reported alongside MAE because MAE alone hides
/// large individual errors.
pub fn root_mean_squared_error(pairs: &[PairedSample]) -> Option<f64> {
    if pairs.is_empty() {
        return None;
    }
    let total: f64 = pairs
        .iter()
        .map(|pair| {
            let difference = f64::from(pair.sensor - pair.reference);
            difference * difference
        })
        .sum();
    Some((total / pairs.len() as f64).sqrt())
}

/// Largest absolute error, which shows the worst case a mean would smooth over.
pub fn max_absolute_error(pairs: &[PairedSample]) -> Option<f64> {
    pairs
        .iter()
        .map(|pair| f64::from((pair.sensor - pair.reference).abs()))
        .fold(None, |worst: Option<f64>, error| {
            Some(worst.map_or(error, |current| current.max(error)))
        })
}

/// Pair each sensor reading with the nearest reference measurement in time.
///
/// A reading further than `tolerance` from any reference is dropped: pairing it
/// with a distant reference would measure the plot's drying rate rather than
/// the sensor's accuracy, which is the opposite of what validation means.
pub fn pair_with_reference(
    readings: &[(DateTime<Utc>, Option<f32>)],
    references: &[(DateTime<Utc>, Option<f32>)],
    tolerance: Duration,
) -> Vec<PairedSample> {
    let mut pairs = Vec::new();
    for (reading_ts, sensor) in readings {
        let Some(sensor) = sensor else {
            continue;
        };
        let nearest = references
            .iter()
            .filter_map(|(reference_ts, reference)| {
                reference
                    .map(|reference| ((*reference_ts - *reading_ts).num_seconds().abs(), reference))
            })
            .min_by_key(|(delta, _)| *delta);
        let Some((delta, reference)) = nearest else {
            continue;
        };
        if delta <= tolerance.num_seconds().abs() {
            pairs.push(PairedSample {
                sensor: *sensor,
                reference,
            });
        }
    }
    pairs
}

/// Sensor validation over one metric.
#[derive(Debug, Clone, Serialize)]
pub struct MaeReport {
    pub metric: String,
    pub samples: usize,
    pub mae: Option<f64>,
    pub rmse: Option<f64>,
    pub max_error: Option<f64>,
    pub window_days: i64,
    /// Readings skipped because the pairing tolerance was exceeded.
    pub unpaired: usize,
}

/// Build a report from already-paired samples.
pub fn mae_report(
    metric: &str,
    pairs: &[PairedSample],
    unpaired: usize,
    window_days: i64,
) -> MaeReport {
    MaeReport {
        metric: metric.to_owned(),
        samples: pairs.len(),
        mae: mean_absolute_error(pairs),
        rmse: root_mean_squared_error(pairs),
        max_error: max_absolute_error(pairs),
        window_days,
        unpaired,
    }
}

/// One node's water use, in valve-open minutes.
#[derive(Debug, Clone, Serialize)]
pub struct WaterUse {
    pub node_uuid: String,
    pub open_minutes: f64,
    /// Litres, when a flow rate is configured.
    pub litres: Option<f64>,
}

/// Estimate valve-open duration per node from the telemetry.
///
/// The firmware sends `valve_state` with each reading, so the open time is the
/// sum of the gaps between readings where the valve was open. Gaps longer than
/// `max_gap` are capped: a device that was offline did not necessarily have its
/// valve open for the whole outage, and counting that would overstate savings.
pub fn valve_open_minutes(samples: &[(DateTime<Utc>, Option<i16>)], max_gap: Duration) -> f64 {
    let mut minutes = 0.0;
    for window in samples.windows(2) {
        let (start_ts, state) = window[0];
        let (end_ts, _) = window[1];
        if state != Some(1) {
            continue;
        }
        let gap = end_ts - start_ts;
        let capped = gap.min(max_gap);
        minutes += capped.num_seconds() as f64 / 60.0;
    }
    minutes
}

/// Water savings against a baseline schedule.
#[derive(Debug, Clone, Serialize)]
pub struct WaterSavings {
    pub automated_minutes: f64,
    pub baseline_minutes: f64,
    pub saved_minutes: f64,
    /// Percentage saved, or `None` when the baseline is zero.
    pub saved_percent: Option<f64>,
}

pub fn water_savings(automated_minutes: f64, baseline_minutes: f64) -> WaterSavings {
    let saved = baseline_minutes - automated_minutes;
    WaterSavings {
        automated_minutes,
        baseline_minutes,
        saved_minutes: saved,
        // A zero baseline means no comparison exists, not a perfect saving.
        saved_percent: if baseline_minutes > 0.0 {
            Some(saved / baseline_minutes * 100.0)
        } else {
            None
        },
    }
}

/// One gateway's health.
#[derive(Debug, Clone, Serialize)]
pub struct FleetEntry {
    pub gateway_id: String,
    pub label: Option<String>,
    pub status: String,
    pub fw_version: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub minutes_since_seen: Option<i64>,
    pub nodes: i64,
}

impl FleetEntry {
    /// Whether the gateway has reported recently enough to be considered up.
    pub fn online(&self, offline_after_minutes: i64) -> bool {
        self.minutes_since_seen
            .is_some_and(|minutes| minutes <= offline_after_minutes)
    }
}

/// Fleet health across an account.
#[derive(Debug, Clone, Serialize)]
pub struct FleetHealth {
    pub gateways: Vec<FleetEntry>,
    pub online: usize,
    pub offline: usize,
    pub provisioned: usize,
    pub claimed: usize,
    pub retired: usize,
}

pub fn fleet_health(entries: Vec<FleetEntry>, offline_after_minutes: i64) -> FleetHealth {
    let online = entries
        .iter()
        .filter(|e| e.online(offline_after_minutes))
        .count();
    let provisioned = entries.len();
    let claimed = entries.iter().filter(|e| e.status == "claimed").count();
    let retired = entries.iter().filter(|e| e.status == "retired").count();
    FleetHealth {
        offline: provisioned - online,
        online,
        provisioned,
        claimed,
        retired,
        gateways: entries,
    }
}

/// Metrics a report can be built for.
pub const METRICS: [&str; 3] = ["moisture", "temperature", "humidity"];

/// Read one metric from a row for the named column.
pub fn metric_value(reading: &NewReading, metric: &str) -> Option<f32> {
    match metric {
        "moisture" => reading.moisture,
        "temperature" => reading.temperature,
        "humidity" => reading.humidity,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    #[test]
    fn mae_matches_the_hand_computed_value() {
        // |10-12| = 2, |20-19| = 1, |30-34| = 4  ->  mean 7/3
        let pairs = [
            PairedSample {
                sensor: 10.0,
                reference: 12.0,
            },
            PairedSample {
                sensor: 20.0,
                reference: 19.0,
            },
            PairedSample {
                sensor: 30.0,
                reference: 34.0,
            },
        ];
        let mae = mean_absolute_error(&pairs).unwrap();
        assert!((mae - 7.0 / 3.0).abs() < 1e-9, "{mae}");
    }

    #[test]
    fn rmse_and_max_expose_what_mae_hides() {
        // Two sets with identical MAE but very different worst cases.
        let steady = [
            PairedSample {
                sensor: 10.0,
                reference: 11.0,
            },
            PairedSample {
                sensor: 20.0,
                reference: 21.0,
            },
        ];
        let spiky = [
            PairedSample {
                sensor: 10.0,
                reference: 10.0,
            },
            PairedSample {
                sensor: 20.0,
                reference: 22.0,
            },
        ];
        assert_eq!(mean_absolute_error(&steady), mean_absolute_error(&spiky));
        assert!(
            root_mean_squared_error(&spiky).unwrap() > root_mean_squared_error(&steady).unwrap()
        );
        assert!(max_absolute_error(&spiky).unwrap() > max_absolute_error(&steady).unwrap());
    }

    #[test]
    fn an_empty_set_reports_none_not_zero() {
        assert_eq!(mean_absolute_error(&[]), None);
        assert_eq!(root_mean_squared_error(&[]), None);
        assert_eq!(max_absolute_error(&[]), None);
    }

    #[test]
    fn pairing_picks_the_nearest_reference_within_tolerance() {
        let readings = [(at(0), Some(10.0))];
        let references = [(at(5), Some(11.0)), (at(600), Some(99.0))];
        let pairs = pair_with_reference(&readings, &references, Duration::minutes(5));
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].reference, 11.0, "the nearer reference must win");
    }

    #[test]
    fn a_reference_further_than_the_tolerance_is_not_used() {
        let readings = [(at(0), Some(10.0))];
        let references = [(at(3_600), Some(11.0))];
        assert!(
            pair_with_reference(&readings, &references, Duration::minutes(5)).is_empty(),
            "pairing across an hour would measure drying, not sensor accuracy"
        );
    }

    #[test]
    fn pairing_skips_unavailable_values_on_either_side() {
        let readings = [(at(0), None), (at(60), Some(10.0))];
        let references = [(at(0), None)];
        let pairs = pair_with_reference(&readings, &references, Duration::minutes(5));
        assert!(pairs.is_empty(), "a sentinel must never enter a statistic");
    }

    #[test]
    fn valve_minutes_sum_only_while_open() {
        let samples = [
            (at(0), Some(1)),
            (at(60), Some(1)),  // open for 1 minute
            (at(120), Some(0)), // closed at 120, so this gap is not open time
            (at(180), Some(0)),
        ];
        let minutes = valve_open_minutes(&samples, Duration::hours(1));
        assert!((minutes - 2.0).abs() < 1e-9, "{minutes}");
    }

    #[test]
    fn valve_minutes_cap_a_long_outage() {
        // The valve was open when last seen, then the device went silent for an
        // hour. Counting the whole hour would claim watering that never ran.
        let samples = [(at(0), Some(1)), (at(3_600), Some(1))];
        let capped = valve_open_minutes(&samples, Duration::minutes(10));
        assert!((capped - 10.0).abs() < 1e-9, "{capped}");
    }

    #[test]
    fn water_savings_reports_none_without_a_baseline() {
        let savings = water_savings(30.0, 0.0);
        assert_eq!(savings.saved_percent, None);
        assert_eq!(savings.saved_minutes, -30.0);

        let savings = water_savings(30.0, 100.0);
        assert_eq!(savings.saved_percent, Some(70.0));
        assert_eq!(savings.saved_minutes, 70.0);
    }

    #[test]
    fn fleet_health_counts_states_and_liveness() {
        let entry = |status: &str, minutes: Option<i64>| FleetEntry {
            gateway_id: "gw".into(),
            label: None,
            status: status.into(),
            fw_version: None,
            last_seen: None,
            minutes_since_seen: minutes,
            nodes: 2,
        };
        let health = fleet_health(
            vec![
                entry("claimed", Some(1)),
                entry("claimed", Some(120)),
                entry("unclaimed", None),
                entry("retired", Some(1)),
            ],
            15,
        );
        assert_eq!(health.provisioned, 4);
        assert_eq!(health.claimed, 2, "unclaimed and retired are not claimed");
        assert_eq!(health.retired, 1);
        assert_eq!(
            health.online, 2,
            "only recent, non-retired reports count as online"
        );
        assert_eq!(health.offline, 2);
    }

    #[test]
    fn metric_lookup_selects_the_named_column() {
        let reading = NewReading {
            ts: at(0),
            gateway_id: "gw".into(),
            node_uuid: vec![0; 8],
            moisture: Some(31.2),
            temperature: Some(28.4),
            humidity: Some(71.0),
            valve_state: None,
            seq: None,
        };
        assert_eq!(metric_value(&reading, "moisture"), Some(31.2));
        assert_eq!(metric_value(&reading, "temperature"), Some(28.4));
        assert_eq!(metric_value(&reading, "humidity"), Some(71.0));
        assert_eq!(metric_value(&reading, "pressure"), None);
        assert_eq!(METRICS.len(), 3);
    }
}
