//! RP2040 field-node firmware.
//!
//! The loop is a servant: it answers the aggregator's bus transactions
//! (poll for readings, valve, thresholds, calibration, address change)
//! and between them samples its own sensors every minute. Nothing here
//! initiates; the aggregator drives the bus, so the node can be
//! effectively asleep whenever it is not being asked a question.
//!
//! Provisioning is the only interactive path: an uncommissioned node
//! waits on USB with a greeting line until the provisioner assigns an
//! address. After that the process runs unattended.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use defmt::{error, info, warn};
use embassy_executor::Spawner;
use embassy_rp::adc::{Adc, Channel, Config as AdcConfig, InterruptHandler as AdcInterruptHandler};
use embassy_rp::bind_interrupts;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{Flex, Level, Output, Pull};
use embassy_rp::peripherals::USB;
use embassy_rp::uart::{self, Uart};
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_time::{Duration, Instant, Timer};
use embassy_usb::UsbDevice;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcState};
use embassy_usb::driver::EndpointError;
use flora_device::node::{NACK_BUSY, NodeProcessor, Response, nack_for};
use flora_drivers::{FIRMWARE_VERSION, IrrigationController, NodeConfig};
use flora_node::board;
use flora_node::storage::{FLASH_SIZE, NodeStorage};
use flora_protocol::SensorReading;
use flora_protocol::frame::{self, Frame, MAX_FRAME_LEN, UNAVAILABLE_U16};
use heapless::String;
use serde_json_core::from_slice;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    ADC_IRQ_FIFO => AdcInterruptHandler;
    USBCTRL_IRQ => UsbInterruptHandler<USB>;
});

type NodeUsbDriver = Driver<'static, USB>;
/// The commissioning request, straight from the shared handshake model.
#[derive(serde::Deserialize)]
struct NodeProvisionRequest<'a> {
    cmd: &'a str,
    address: u8,
}

#[embassy_executor::task]
async fn usb_task(mut usb: UsbDevice<'static, NodeUsbDriver>) -> ! {
    usb.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // External 100 kΩ gate pull-down and a normally-closed valve keep the
    // valve closed through reset, boot, panic, and loss of Pico power.
    let mut valve_pin = Output::new(p.PIN_15, Level::Low);
    let mut de_pin = Output::new(p.PIN_2, Level::Low);

    let flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
    let mut storage = match NodeStorage::new(flash) {
        Ok(storage) => storage,
        Err(error) => fatal_storage(error),
    };
    let node_uuid = match storage.node_uuid() {
        Ok(uuid) => uuid,
        Err(error) => fatal_storage(error),
    };
    let mut config = storage.config();

    let mut usb_builder = make_usb_builder(p.USB);
    let mut cdc = {
        static CDC_STATE: StaticCell<CdcState> = StaticCell::new();
        CdcAcmClass::new(&mut usb_builder, CDC_STATE.init(CdcState::new()), 64)
    };
    spawner.spawn(usb_task(usb_builder.build()).unwrap());

    if config.address == board::UNCOMMISSIONED_ADDRESS {
        config = commission_over_usb(&mut cdc, &mut storage, config, node_uuid).await;
    }

    info!("Node commissioned at address {}", config.address);
    let mut adc = Adc::new(p.ADC, Irqs, AdcConfig::default());
    let mut soil_channel = Channel::new_pin(p.PIN_26, Pull::None);
    let mut dht_pin = Flex::new(p.PIN_16);
    dht_pin.set_pull(Pull::Up);
    dht_pin.set_as_input();

    let mut uart_config = uart::Config::default();
    uart_config.baudrate = board::RS485_BAUD;
    let mut uart = Uart::new_blocking(p.UART0, p.PIN_0, p.PIN_1, uart_config);

    // DHT22 requires one second after power-up before the first request.
    Timer::after_secs(1).await;
    let mut reading = sample_sensors(&mut adc, &mut soil_channel, &mut dht_pin, &config, 1).await;
    let boot_time = Instant::now();
    let mut next_sample = boot_time + Duration::from_secs(60);
    let mut irrigation = IrrigationController::new(0);
    let mut processor = NodeProcessor::default();
    let mut valve_open = false;
    let mut receive = ReceiveFrame::new();

    loop {
        let now_s = Instant::now().duration_since(boot_time).as_secs() as u32;
        let desired_valve = irrigation.update_auto(reading.moisture_per_mille, &config, now_s);
        set_valve(&mut valve_pin, &mut valve_open, desired_valve);

        if let Ok(byte) = embedded_hal_nb::serial::Read::read(&mut uart) {
            if let Some(frame_len) = receive.push(byte, Instant::now()) {
                if let Ok(frame) = frame::decode(receive.bytes(frame_len)) {
                    let old_config = config;
                    let response = processor.process(
                        frame,
                        &mut config,
                        reading,
                        &mut irrigation,
                        node_uuid,
                        now_s,
                    );
                    if config != old_config {
                        // A config that cannot persist must not appear to
                        // have applied: NACK and cache the corrected reply.
                        if storage.save_config(config).is_err() {
                            config = old_config;
                            let nack =
                                Some(nack_for(frame.addr, frame.cmd, frame.sequence, NACK_BUSY));
                            if let Some(response) = nack {
                                processor.replace_cached_response(response);
                            }
                        }
                    }
                    if let Some(response) = response {
                        set_valve(&mut valve_pin, &mut valve_open, irrigation.is_open());
                        transmit_response(&mut uart, &mut de_pin, response).await;
                    }
                }
                receive.reset();
            }
        }

        if Instant::now() >= next_sample {
            reading = sample_sensors(
                &mut adc,
                &mut soil_channel,
                &mut dht_pin,
                &config,
                reading.sequence.wrapping_add(1),
            )
            .await;
            next_sample = Instant::now() + Duration::from_secs(60);
        }

        Timer::after_micros(100).await;
    }
}

fn make_usb_builder(
    usb: embassy_rp::Peri<'static, USB>,
) -> embassy_usb::Builder<'static, NodeUsbDriver> {
    let driver = Driver::new(usb, Irqs);
    let mut config = embassy_usb::Config::new(0x2E8A, 0x000A);
    config.manufacturer = Some("FLORA");
    config.product = Some("FLORA Node Provisioning");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUFFER: StaticCell<[u8; 64]> = StaticCell::new();
    embassy_usb::Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        &mut [],
        CONTROL_BUFFER.init([0; 64]),
    )
}

/// Greet the provisioner and accept an address until one sticks.
///
/// Looping here rather than booting half-configured is deliberate: a
/// node that thinks it has an address it does not have would inject
/// frames addressed to a real node's slot.
async fn commission_over_usb(
    cdc: &mut CdcAcmClass<'static, NodeUsbDriver>,
    storage: &mut NodeStorage<'_>,
    mut config: NodeConfig,
    node_uuid: [u8; 8],
) -> NodeConfig {
    let uuid = encode_hex(&node_uuid);
    loop {
        cdc.wait_connection().await;
        let mut greeting: String<128> = String::new();
        if write!(
            greeting,
            "{{\"flora_prov\":{},\"hw\":\"{}\",\"fw\":\"{}\",\"uuid\":\"{}\"}}\n",
            flora_protocol::HANDSHAKE_VERSION,
            flora_protocol::NODE_HW,
            FIRMWARE_VERSION,
            uuid
        )
        .is_err()
        {
            continue;
        }
        if write_usb_line(cdc, greeting.as_bytes()).await.is_err() {
            continue;
        }

        let mut line = [0u8; 128];
        let length = match read_usb_line(cdc, &mut line).await {
            Ok(length) => length,
            Err(_) => continue,
        };
        let address = match from_slice::<NodeProvisionRequest>(&line[..length]) {
            Ok((request, _)) if request.cmd == flora_protocol::provision::SetNodeAddress::CMD => {
                request.address
            }
            _ => {
                let _ = write_usb_line(cdc, b"{\"ok\":false}\n").await;
                continue;
            }
        };
        if !(0x02..=0xFE).contains(&address) {
            let _ = write_usb_line(cdc, b"{\"ok\":false}\n").await;
            continue;
        }

        config.address = address;
        if storage.save_config(config).is_err() {
            config.address = board::UNCOMMISSIONED_ADDRESS;
            let _ = write_usb_line(cdc, b"{\"ok\":false}\n").await;
            continue;
        }
        if write_usb_line(cdc, b"{\"ok\":true}\n").await.is_ok() {
            return config;
        }
    }
}

async fn read_usb_line(
    cdc: &mut CdcAcmClass<'static, NodeUsbDriver>,
    line: &mut [u8; 128],
) -> Result<usize, EndpointError> {
    let mut length = 0;
    let mut packet = [0u8; 64];
    loop {
        let read = cdc.read_packet(&mut packet).await?;
        for byte in &packet[..read] {
            if *byte == b'\n' {
                if length > 0 && line[length - 1] == b'\r' {
                    length -= 1;
                }
                return Ok(length);
            }
            if length >= line.len() {
                return Err(EndpointError::BufferOverflow);
            }
            line[length] = *byte;
            length += 1;
        }
    }
}

async fn write_usb_line(
    cdc: &mut CdcAcmClass<'static, NodeUsbDriver>,
    line: &[u8],
) -> Result<(), EndpointError> {
    for packet in line.chunks(64) {
        cdc.write_packet(packet).await?;
    }
    Ok(())
}

/// Hex for the 8-byte UUID: exactly 16 characters, so the buffer is exact.
fn encode_hex(bytes: &[u8]) -> String<16> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::new();
    for byte in bytes {
        let _ = text.push(HEX[(byte >> 4) as usize] as char);
        let _ = text.push(HEX[(byte & 0x0F) as usize] as char);
    }
    text
}

async fn sample_sensors(
    adc: &mut Adc<'_, embassy_rp::adc::Async>,
    soil_channel: &mut Channel<'_>,
    dht_pin: &mut Flex<'_>,
    config: &NodeConfig,
    sequence: u32,
) -> SensorReading {
    let soil_raw = adc.read(soil_channel).await.unwrap_or(UNAVAILABLE_U16);
    let moisture_per_mille =
        flora_drivers::to_per_mille(soil_raw, config.soil_dry_adc, config.soil_wet_adc);
    let dht = read_dht22(dht_pin);
    if dht.is_none() {
        warn!("DHT22 sample failed; reporting temperature and humidity unavailable");
    }
    SensorReading {
        soil_raw,
        moisture_per_mille,
        temperature_deci_c: dht.map(|reading| reading.temperature_deci_c),
        humidity_per_mille: dht.map(|reading| reading.humidity_per_mille),
        sequence,
    }
}

/// Read one DHT22 frame with a bit-banged one-wire transaction.
///
/// Every wait is bounded, so a disconnected sensor costs a bounded slice
/// of the sample period rather than a hang.
fn read_dht22(pin: &mut Flex<'_>) -> Option<flora_drivers::Dht22Reading> {
    pin.set_pull(Pull::Up);
    pin.set_high();
    pin.set_as_output();
    pin.set_low();
    delay_us(1_100);
    pin.set_high();
    delay_us(30);
    pin.set_as_input();

    if !wait_for_level(pin, false, 120)
        || !wait_for_level(pin, true, 120)
        || !wait_for_level(pin, false, 120)
    {
        return None;
    }

    let mut bytes = [0u8; 5];
    for bit in 0..40 {
        if !wait_for_level(pin, true, 100) {
            return None;
        }
        let high_start = Instant::now();
        if !wait_for_level(pin, false, 100) {
            return None;
        }
        let high_us = Instant::now().duration_since(high_start).as_micros();
        if high_us > 50 {
            bytes[bit / 8] |= 1 << (7 - (bit % 8));
        }
    }
    flora_drivers::dht22::decode(bytes).ok()
}

fn delay_us(micros: u64) {
    let deadline = Instant::now() + Duration::from_micros(micros);
    while Instant::now() < deadline {}
}

fn wait_for_level(pin: &Flex<'_>, high: bool, timeout_us: u64) -> bool {
    let deadline = Instant::now() + Duration::from_micros(timeout_us);
    while Instant::now() < deadline {
        if pin.is_high() == high {
            return true;
        }
    }
    false
}

fn set_valve(pin: &mut Output<'_>, current: &mut bool, open: bool) {
    if open == *current {
        return;
    }
    if open {
        pin.set_high();
    } else {
        pin.set_low();
    }
    *current = open;
}

/// Drive DE, transmit, and release the bus.
///
/// The processor builds every reply complete — `DATA` already carries the
/// uuid, firmware constant, and the reading it sampled — so this only
/// frames what it is given.
async fn transmit_response(
    uart: &mut Uart<'_, embassy_rp::uart::Blocking>,
    de_pin: &mut Output<'_>,
    response: Response,
) {
    Timer::after_micros(2_000).await;
    let frame = Frame {
        addr: response.addr,
        cmd: response.cmd,
        sequence: response.sequence,
        payload: &response.payload[..response.payload_len],
    };
    let mut bytes = [0u8; MAX_FRAME_LEN];
    let length = match frame::encode(&frame, &mut bytes) {
        Ok(length) => length,
        Err(_) => return,
    };

    de_pin.set_high();
    Timer::after_micros(2).await;
    if uart.blocking_write(&bytes[..length]).is_err() || uart.blocking_flush().is_err() {
        de_pin.set_low();
        return;
    }
    while uart.busy() {}
    de_pin.set_low();
}

/// Byte-at-a-time frame reassembly with an idle timeout.
///
/// RS-485 gives no framing for free: the SOF byte starts a frame, the
/// length byte sets its size, and a gap longer than one byte-time at
/// 115200 baud means the sender stopped mid-frame.
struct ReceiveFrame {
    bytes: [u8; MAX_FRAME_LEN],
    length: usize,
    expected: usize,
    started_at: Instant,
}

impl ReceiveFrame {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_FRAME_LEN],
            length: 0,
            expected: 0,
            started_at: Instant::now(),
        }
    }

    fn reset(&mut self) {
        self.length = 0;
        self.expected = 0;
    }

    fn push(&mut self, byte: u8, now: Instant) -> Option<usize> {
        if self.length > 0 && now.duration_since(self.started_at).as_micros() > 20_000 {
            self.reset();
        }
        if self.length == 0 {
            if byte == frame::SOF {
                self.bytes[0] = byte;
                self.length = 1;
                self.started_at = now;
            }
            return None;
        }
        if self.length >= self.bytes.len() {
            self.reset();
            return None;
        }
        self.bytes[self.length] = byte;
        self.length += 1;
        if self.length == 6 {
            let payload_length = self.bytes[5] as usize;
            if payload_length > frame::MAX_PAYLOAD_LEN {
                self.reset();
                return None;
            }
            self.expected = frame::FRAME_OVERHEAD + payload_length;
        }
        if self.expected != 0 && self.length == self.expected {
            return Some(self.length);
        }
        if self.expected != 0 && self.length > self.expected {
            self.reset();
        }
        None
    }

    fn bytes(&self, length: usize) -> &[u8] {
        &self.bytes[..length]
    }
}

fn fatal_storage(_error: flora_device::identity::StorageError) -> ! {
    error!("Node storage or flash identity failure");
    panic!();
}
