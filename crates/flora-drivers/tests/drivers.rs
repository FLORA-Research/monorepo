//! Host-run driver behavior: calibration math, sensor decode, and the
//! valve state machine against the safety rules. These run on the host
//! because the logic is board-independent; the firmware bins bind it to
//! pins.

use flora_drivers::{
    Dht22Error, IrrigationController, ManualError, NodeConfig, sample_per_mille, to_per_mille,
};

// ---- soil moisture ----

#[test]
fn moisture_maps_both_calibration_directions_and_clamps() {
    // Normal polarity: wet reads lower than dry.
    assert_eq!(to_per_mille(2000, 3000, 1000), Some(500));
    // Inverted polarity: wet reads higher.
    assert_eq!(to_per_mille(2000, 1000, 3000), Some(500));
    // Endpoints clamp to the full scale.
    assert_eq!(to_per_mille(500, 3000, 1000), Some(1000));
    assert_eq!(to_per_mille(3500, 3000, 1000), Some(0));
}

#[test]
fn moisture_refuses_uncalibrated_or_invalid_inputs() {
    use flora_protocol::UNAVAILABLE_U16;
    assert_eq!(to_per_mille(2000, UNAVAILABLE_U16, 1000), None);
    assert_eq!(to_per_mille(2000, 1000, 1000), None, "identical refs");
    assert_eq!(to_per_mille(4096, 3000, 1000), None, "raw above ADC range");
    assert_eq!(to_per_mille(2000, 4096, 1000), None, "dry ref invalid");
    assert_eq!(to_per_mille(2000, 3000, 4096), None, "wet ref invalid");
}

#[test]
fn moisture_sample_uses_config_references() {
    let mut config = NodeConfig::default();
    assert_eq!(sample_per_mille(2000, &config), None, "uncalibrated");

    config.soil_dry_adc = 3000;
    config.soil_wet_adc = 1000;
    assert_eq!(sample_per_mille(2000, &config), Some(500));
    assert!(config.soil_calibrated());
}

#[test]
fn moisture_extremes_map_to_the_full_scale() {
    // A saturated probe must read 1000, bone-dry 0 — and the boundary
    // values exactly at the references must not round outside the scale.
    assert_eq!(to_per_mille(3000, 3000, 1000), Some(0));
    assert_eq!(to_per_mille(1000, 3000, 1000), Some(1000));
    assert_eq!(to_per_mille(0, 3000, 1000), Some(1000));
    assert_eq!(to_per_mille(4095, 3000, 1000), Some(0));
}

// ---- dht22 ----

#[test]
fn dht22_decodes_humidity_and_signed_temperature() {
    use flora_drivers::dht22;
    assert_eq!(
        dht22::decode([0x02, 0xBC, 0x01, 0x1C, 0xDB]),
        Ok(dht22::Reading {
            temperature_deci_c: 284,
            humidity_per_mille: 700
        })
    );
    // Negative temperature: sign bit set on the high byte.
    assert_eq!(
        dht22::decode([0x01, 0xF4, 0x80, 0xFA, 0x6F]),
        Ok(dht22::Reading {
            temperature_deci_c: -250,
            humidity_per_mille: 500
        })
    );
}

#[test]
fn dht22_rejects_checksum_and_range_errors() {
    use flora_drivers::dht22;
    assert_eq!(
        dht22::decode([0x02, 0xBC, 0x01, 0x1C, 0]),
        Err(Dht22Error::Checksum)
    );
    // 100.1% RH is a sensor failure, not a reading.
    assert_eq!(
        dht22::decode([0x03, 0xE9, 0x01, 0x1C, 0x09]),
        Err(Dht22Error::OutOfRange)
    );
    // -40.1 °C is below the sensor's own range (checksum 0xD0 = low byte
    // of the wrapped sum 0x1D0).
    assert_eq!(
        dht22::decode([0x02, 0xBC, 0x81, 0x91, 0xD0]),
        Err(Dht22Error::OutOfRange)
    );
}

#[test]
fn dht22_checksum_wraps_at_the_byte_boundary() {
    // Bytes chosen so the plain sum exceeds 255: 3+232+1+144 = 380,
    // whose low byte is 124. The checksum must wrap, not saturate.
    use flora_drivers::dht22;
    let bytes = [0x03, 0xE8, 0x01, 0x90, 0x7C];
    assert_eq!(
        dht22::decode(bytes),
        Ok(dht22::Reading {
            temperature_deci_c: 400,
            humidity_per_mille: 1000,
        })
    );
}

// ---- irrigation controller ----

#[test]
fn hysteresis_opens_below_dry_and_closes_at_wet() {
    let config = NodeConfig {
        min_off_s: 10,
        ..NodeConfig::default()
    };
    let mut controller = IrrigationController::new(0);
    assert!(!controller.update_auto(Some(299), &config, 9));
    assert!(controller.update_auto(Some(299), &config, 10));
    assert!(controller.update_auto(Some(599), &config, 11));
    assert!(!controller.update_auto(Some(600), &config, 12));
    assert!(!controller.update_auto(Some(299), &config, 21));
    assert!(controller.update_auto(Some(299), &config, 22));
}

#[test]
fn missing_moisture_and_runtime_limit_close_the_valve() {
    let config = NodeConfig {
        max_runtime_s: 5,
        min_off_s: 1,
        ..NodeConfig::default()
    };
    let mut controller = IrrigationController::new(0);
    assert!(controller.update_auto(Some(100), &config, 1));
    // A node that cannot see its sensor must not water indefinitely.
    assert!(!controller.update_auto(None, &config, 2));
    assert!(controller.update_auto(Some(100), &config, 3));
    // The runtime cap closes regardless of moisture.
    assert!(!controller.update_auto(Some(100), &config, 8));
    assert!(controller.update_auto(Some(100), &config, 9));
    assert!(!controller.update_auto(Some(100), &config, 14));
}

#[test]
fn manual_open_is_timed_and_obeys_off_time_and_caps() {
    let config = NodeConfig {
        max_runtime_s: 5,
        min_off_s: 3,
        ..NodeConfig::default()
    };
    let mut controller = IrrigationController::new(0);
    assert_eq!(
        controller.set_manual(true, 2, &config, 1),
        Err(ManualError::MinimumOffTime)
    );
    assert_eq!(
        controller.set_manual(true, 6, &config, 3),
        Err(ManualError::InvalidDuration)
    );
    assert_eq!(
        controller.set_manual(true, 0, &config, 3),
        Err(ManualError::InvalidDuration),
        "zero duration is never valid"
    );
    controller.set_manual(true, 4, &config, 3).unwrap();
    assert!(controller.update_auto(None, &config, 6));
    // The manual deadline closes the valve even with moisture unknown.
    assert!(!controller.update_auto(None, &config, 7));
    assert_eq!(
        controller.set_manual(true, 1, &config, 9),
        Err(ManualError::MinimumOffTime)
    );
    controller.set_manual(false, 0, &config, 10).unwrap();
    assert!(!controller.is_open());
}

#[test]
fn manual_close_is_always_allowed_and_clears_the_deadline() {
    // Boot at t=0 and act at t=1000, so the default 600 s minimum off
    // time has elapsed and the manual open itself is legal.
    let config = NodeConfig::default();
    let mut controller = IrrigationController::new(0);
    controller.set_manual(true, 60, &config, 1000).unwrap();
    assert!(controller.is_open());
    // Close ignores duration, runtime, and off time.
    controller.set_manual(false, 999, &config, 1000).unwrap();
    assert!(!controller.is_open());
    // A subsequent auto update does not reopen from a stale deadline.
    // Dry moisture would open the valve, but the 600 s minimum off time
    // has not elapsed since the close at t=1000.
    assert!(!controller.update_auto(Some(299), &config, 1001));
}

// ---- node config ----

#[test]
fn record_round_trips_every_field() {
    let config = NodeConfig {
        address: 5,
        soil_dry_adc: 3200,
        soil_wet_adc: 1200,
        ..NodeConfig::default()
    };
    let mut page = [0xFFu8; 256];
    config.encode_record(42, &mut page);
    assert_eq!(NodeConfig::decode_record(&page), Some((42, config)));
    // The remainder of the page stays erased.
    assert!(page[24..].iter().all(|byte| *byte == 0xFF));
}

#[test]
fn erased_and_corrupt_pages_are_rejected() {
    let erased = [0xFFu8; 256];
    assert_eq!(NodeConfig::decode_record(&erased), None);

    let mut page = [0xFFu8; 256];
    let good = NodeConfig {
        address: 5,
        soil_dry_adc: 3200,
        soil_wet_adc: 1200,
        ..NodeConfig::default()
    };
    good.encode_record(1, &mut page);
    page[6] ^= 0x01;
    assert_eq!(
        NodeConfig::decode_record(&page),
        None,
        "checksum must catch corruption"
    );

    let mut page = [0xFFu8; 256];
    good.encode_record(1, &mut page);
    page[0] = b'X';
    assert_eq!(
        NodeConfig::decode_record(&page),
        None,
        "magic must be checked"
    );

    // A truncated page cannot be interpreted at all.
    let mut page = [0xFFu8; 256];
    good.encode_record(1, &mut page);
    assert_eq!(NodeConfig::decode_record(&page[..23]), None);
}

#[test]
fn validate_rejects_unsafe_or_incomplete_configurations() {
    let commissioned = NodeConfig {
        address: 5,
        soil_dry_adc: 3200,
        soil_wet_adc: 1200,
        ..NodeConfig::default()
    };
    assert!(commissioned.validate());

    let bad = |config: NodeConfig| !config.validate();
    // Uncommissioned or reserved address.
    assert!(bad(NodeConfig {
        address: 0,
        ..commissioned
    }));
    assert!(bad(NodeConfig {
        address: 0xFF,
        ..commissioned
    }));
    // Inverted hysteresis band.
    assert!(bad(NodeConfig {
        dry_threshold: 700,
        wet_threshold: 600,
        ..commissioned
    }));
    // Out-of-range thresholds.
    assert!(bad(NodeConfig {
        wet_threshold: 1001,
        ..commissioned
    }));
    assert!(bad(NodeConfig {
        dry_threshold: 1001,
        ..commissioned
    }));
    // Zero runtime would make the cap meaningless.
    assert!(bad(NodeConfig {
        max_runtime_s: 0,
        ..commissioned
    }));
    // Identical calibration references cannot produce a scale.
    assert!(bad(NodeConfig {
        soil_wet_adc: 3200,
        ..commissioned
    }));
    // The opposite polarity is legitimate for a capacitive probe.
    assert!(
        (NodeConfig {
            soil_dry_adc: 1200,
            soil_wet_adc: 3200,
            ..commissioned
        })
        .validate()
    );
}

#[test]
fn uncalibrated_configuration_is_legal() {
    let uncalibrated = NodeConfig {
        address: 3,
        ..NodeConfig::default()
    };
    assert!(uncalibrated.validate());
    assert!(!uncalibrated.soil_calibrated());
}
