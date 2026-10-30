//! RP2040 Pico W aggregator firmware entry point.
//!
//! Boots the Embassy runtime, brings up the CYW43 radio, and joins the
//! first access point it can from the compiled-in `wifi.toml`
//! dictionary. The heartbeat proves the vector table, the linker script,
//! and the time driver work; RS-485, uplink, and command verification
//! arrive with the full `flora-device` integration.

#![no_std]
#![no_main]

use cyw43::Control;
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::dma::{Channel, InterruptHandler as DmaInterruptHandler};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler as PioInterruptHandler, Pio};
use embassy_time::Timer;
use flora_aggregator::wifi::{Auth, WifiNetwork};
use heapless::Vec as HVec;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => PioInterruptHandler<PIO0>;
    DMA_IRQ_0 => DmaInterruptHandler<DMA_CH0>;
});

/// Map the dictionary's auth spelling onto the CYW43 firmware's choices.
///
/// Open networks join with `new_open()`; every protected kind joins with
/// the passphrase bytes and AES, with TKIP added only for plain `wpa`
/// (the old TKIP-era suite). Mixed `wpa2wpa3` is the crate default, kept
/// here so the mapping stays exhaustive over `Auth`.
fn join_options<'a>(network: &'a WifiNetwork) -> cyw43::JoinOptions<'a> {
    match network.auth {
        Auth::Open => cyw43::JoinOptions::new_open(),
        Auth::Wpa => {
            let mut options = cyw43::JoinOptions::new(network.passphrase());
            options.auth = cyw43::JoinAuth::Wpa;
            options.cipher_tkip = true;
            options
        }
        Auth::Wpa2 => {
            let mut options = cyw43::JoinOptions::new(network.passphrase());
            options.auth = cyw43::JoinAuth::Wpa2;
            options
        }
        Auth::Wpa3 => {
            let mut options = cyw43::JoinOptions::new(network.passphrase());
            options.auth = cyw43::JoinAuth::Wpa3;
            options
        }
        Auth::Wpa2Wpa3 => cyw43::JoinOptions::new(network.passphrase()),
    }
}

/// Associate with every dictionary network in priority order until one
/// joins.
///
/// A router rebooting at the wrong moment must not brick a deployed
/// device, so association is retried rather than fatal: each outer pass
/// walks the whole dictionary, pausing between passes. A station already
/// associated to one AP will rejoin it first, so the loop converges.
async fn join_first_available(
    control: &mut Control<'_>,
    networks: &HVec<WifiNetwork, { flora_aggregator::wifi::MAX_NETWORKS }>,
) {
    loop {
        for index in 0..networks.len() {
            let network = &networks[index];
            let ssid = network.ssid_str();
            defmt::info!("wifi: joining {} (priority {})", ssid, network.priority);
            match control.join(ssid, join_options(network)).await {
                Ok(()) => {
                    defmt::info!("wifi: joined {}", ssid);
                    return;
                }
                Err(error) => {
                    defmt::warn!("wifi: join {} failed: {:?}; trying next", ssid, error);
                }
            }
        }
        defmt::warn!("wifi: no network joined this pass; retrying in 5 s");
        Timer::after_secs(5).await;
    }
}

/// Servicing the radio's low-level stack.
#[embassy_executor::task]
async fn cyw43_task(
    runner: cyw43::Runner<
        'static,
        cyw43::SpiBus<Output<'static>, cyw43_pio::PioSpi<'static, PIO0, 0>>,
    >,
) -> ! {
    runner.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // The radio is powered down until this pin goes high; it is part of the
    // chip's wiring, not a choice. PIN_25 doubles as the CYW43 chip-select
    // and the onboard LED gate, so the LED is driven through the radio
    // from here on, never as a plain GPIO.
    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = cyw43_pio::PioSpi::new(
        &mut pio.common,
        pio.sm0,
        cyw43_pio::DEFAULT_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        Channel::new(p.DMA_CH0, Irqs),
    );

    // Radio firmware, vendored beside the crate (see
    // `cyw43-firmware/README.md`): the chip's own firmware, its regulatory
    // table, and the board's calibration data.
    let fw = cyw43::aligned_bytes!("../../cyw43-firmware/43439A0.bin");
    let clm = cyw43::aligned_bytes!("../../cyw43-firmware/43439A0_clm.bin");
    let nvram = cyw43::aligned_bytes!("../../cyw43-firmware/nvram_rp2040.bin");

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (_net_device, mut control, runner) = cyw43::new(state, pwr, spi, fw, nvram).await;
    spawner.spawn(cyw43_task(runner).unwrap());

    control.init(clm).await;
    // The radio is the dominant power load; power-save idles it between
    // uplinks, which the solar budget assumes.
    control
        .set_power_management(cyw43::PowerManagementMode::PowerSave)
        .await;

    // Join the best available access point from the compiled dictionary.
    // `wifi.toml` at the repository root is the single place to edit.
    let networks = flora_aggregator::wifi_networks();
    defmt::info!("wifi dictionary: {} network(s) compiled in", networks.len());
    join_first_available(&mut control, &networks).await;
    defmt::info!("network up");

    // Heartbeat through WL_GPIO0, so a joined device is distinguishable in
    // the field. Real operation (RS-485 poll, batch uplink) lands with the
    // full firmware port; `net_device` will be handed to embassy-net then.
    loop {
        control.gpio_set(0, true).await;
        Timer::after_millis(500).await;
        control.gpio_set(0, false).await;
        Timer::after_millis(500).await;
    }
}
