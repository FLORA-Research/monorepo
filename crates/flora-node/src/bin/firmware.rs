//! RP2040 field-node firmware entry point.
//!
//! Hello world for now: boots the Embassy runtime and blinks the onboard
//! LED, which proves the vector table, the linker script, and the time
//! driver all work. Sensing, irrigation, and the RS-485 servant arrive with
//! `flora-device` integration.

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_rp::gpio::{Level, Output};
use embassy_time::Timer;
use {defmt_rtt as _, panic_probe as _};

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // PIN_25 is the Pico's onboard LED.
    let mut led = Output::new(p.PIN_25, Level::Low);

    loop {
        led.set_high();
        Timer::after_millis(500).await;
        led.set_low();
        Timer::after_millis(500).await;
    }
}
