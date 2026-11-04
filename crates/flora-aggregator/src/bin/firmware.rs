//! RP2040 Pico W aggregator firmware entry point.
//!
//! The aggregator is a node plus radio: it samples and irrigates its own
//! plot exactly like a field node, polls the RS-485 bus for its neighbours'
//! readings, buffers batches when the cloud is unreachable, and verifies
//! signed commands from the app before any valve moves.
//!
//! Boot order matters. The radio is brought up only after the identity is
//! present, because joining an access point costs seconds and a device with
//! no credentials would spend them for nothing. An unprovisioned board sits
//! on USB with a greeting until the provisioner hands over its identity.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use cyw43::Control;
use defmt::{error, info, warn};
use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::{IpAddress, Stack, StackResources};
use embassy_rp::adc::{Adc, Channel, Config as AdcConfig, InterruptHandler as AdcInterruptHandler};
use embassy_rp::bind_interrupts;
use embassy_rp::dma::{Channel as DmaChannel, InterruptHandler as DmaInterruptHandler};
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{Flex, Level, Output, Pull};
use embassy_rp::peripherals::{DMA_CH0, PIO0, USB};
use embassy_rp::pio::{InterruptHandler as PioInterruptHandler, Pio};
use embassy_rp::uart::{self, Uart};
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_time::{Duration, Instant, Timer};
use embassy_usb::UsbDevice;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcState};
use embassy_usb::driver::EndpointError;
use embedded_io_async::Write as _;
use flora_aggregator::board;
use flora_aggregator::commands::{self, CommandWire, MAX_COMMANDS};
use flora_aggregator::storage::{FLASH_SIZE, UplinkStorage};
use flora_aggregator::uplink::{self, UplinkConfig, UplinkState};
use flora_aggregator::wifi::{Auth, WifiNetwork};
use flora_device::coord::{Coordinator, DispatchOutcome, RoutedCommand, apply_local_valve};
use flora_device::coordinator::poll_request;
use flora_device::identity::{Identity, StorageError};
use flora_drivers::{FIRMWARE_VERSION, IrrigationController, NodeConfig};
use flora_protocol::MAX_BATCH_JSON;
use flora_protocol::SensorReading;
use flora_protocol::frame::{self, MAX_FRAME_LEN, UNAVAILABLE_U16};
use heapless::Vec as HVec;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => PioInterruptHandler<PIO0>;
    DMA_IRQ_0 => DmaInterruptHandler<DMA_CH0>;
    ADC_IRQ_FIFO => AdcInterruptHandler;
    USBCTRL_IRQ => UsbInterruptHandler<USB>;
});

type AggUsbDriver = Driver<'static, USB>;

/// How large a response body the command poll can hold.
///
/// The API returns at most sixteen commands, each roughly 350 bytes of JSON,
/// so 6 KiB covers a full queue. A short buffer would silently truncate the
/// array and lose the commands the cloud already marked dispatched.
const RESPONSE_BYTES: usize = 6144;

/// Response buffer for the batch upload, where only the status matters.
const INGEST_RESPONSE_BYTES: usize = 256;

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

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, cyw43::NetDriver<'static>>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn usb_task(mut usb: UsbDevice<'static, AggUsbDriver>) -> ! {
    usb.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // Normally-closed valve with an external gate pull-down: closed through
    // reset, boot, panic, and loss of Pico power.
    let mut valve_pin = Output::new(p.PIN_15, Level::Low);
    let mut de_pin = Output::new(p.PIN_2, Level::Low);

    let flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
    let mut storage = match UplinkStorage::new(flash) {
        Ok(storage) => storage,
        Err(error) => fatal_storage(error),
    };

    let mut usb_builder = make_usb_builder(p.USB);
    let mut cdc = {
        static CDC_STATE: StaticCell<CdcState> = StaticCell::new();
        CdcAcmClass::new(&mut usb_builder, CDC_STATE.init(CdcState::new()), 64)
    };
    spawner.spawn(usb_task(usb_builder.build()).unwrap());

    let board_id = match storage.unique_id() {
        Ok(uuid) => uuid,
        Err(error) => fatal_storage(error),
    };
    if !storage.is_provisioned() {
        commission_over_usb(&mut cdc, &mut storage, board_id).await;
    }
    let config = storage.config();
    info!("aggregator provisioned; joining network");

    let stack = start_network(
        &spawner,
        RadioPins {
            pio: p.PIO0,
            dma: p.DMA_CH0,
            pwr: p.PIN_23,
            cs: p.PIN_25,
            dio: p.PIN_24,
            clk: p.PIN_29,
        },
        &mut storage,
    )
    .await;

    let mut adc = Adc::new(p.ADC, Irqs, AdcConfig::default());
    let mut soil_channel = Channel::new_pin(p.PIN_26, Pull::None);
    let mut dht_pin = Flex::new(p.PIN_16);
    dht_pin.set_pull(Pull::Up);
    dht_pin.set_as_input();

    let mut uart_config = uart::Config::default();
    uart_config.baudrate = board::RS485_BAUD;
    let mut uart = Uart::new_blocking(p.UART0, p.PIN_0, p.PIN_1, uart_config);

    // One socket for the life of the process: `TcpSocket` owns its buffers
    // for good, so creating one per request would leak them.
    static SOCKET_RX: StaticCell<[u8; 1024]> = StaticCell::new();
    static SOCKET_TX: StaticCell<[u8; uplink::MAX_REQUEST_BYTES]> = StaticCell::new();
    let mut socket = TcpSocket::new(
        stack,
        SOCKET_RX.init([0; 1024]),
        SOCKET_TX.init([0; uplink::MAX_REQUEST_BYTES]),
    );
    socket.set_timeout(Some(Duration::from_secs(20)));

    // DHT22 requires one second after power-up before the first request.
    Timer::after_secs(1).await;
    let mut coordinator = Coordinator::new(storage.gateway_id(), board::LOCAL_ADDR);
    let mut irrigation = IrrigationController::new(0);
    let mut reading = sample_sensors(&mut adc, &mut soil_channel, &mut dht_pin, &config, 1).await;
    let boot_time = Instant::now();
    let mut next_sample = boot_time + Duration::from_secs(board::SAMPLE_INTERVAL_S);
    let mut next_uplink = boot_time + Duration::from_secs(board::UPLINK_INTERVAL_S);
    let mut attempts = 0u8;
    let mut receive = ReceiveFrame::new();
    let mut local_valve_open = false;

    loop {
        let now = Instant::now();
        let now_s = now.duration_since(boot_time).as_secs() as u32;

        // Local irrigation runs through the same controller and limits as a
        // node's, so the aggregator's own plot is not a special case.
        let desired = irrigation.update_auto(reading.moisture_per_mille, &config, now_s);
        set_valve(&mut valve_pin, &mut local_valve_open, desired);

        // ---- Poll one node per pass ----
        //
        // One rather than all: a full sweep would block this loop for up to
        // sixteen timeouts, starving both the local sensor and the uplink.
        if let Some(plan) = coordinator.poller().next_poll() {
            let (request, len) = poll_request(plan.addr, plan.sequence);
            transmit(&mut uart, &mut de_pin, &request[..len]).await;
            receive.reset();

            let deadline = Instant::now() + Duration::from_millis(board::POLL_TIMEOUT_MS);
            let mut answered = false;
            while Instant::now() < deadline {
                if let Ok(byte) = embedded_hal_nb::serial::Read::read(&mut uart)
                    && let Some(frame_len) = receive.push(byte, Instant::now())
                    && let Ok(frame) = frame::decode(receive.bytes(frame_len))
                    && frame.addr == plan.addr
                {
                    coordinator.record_reply(&frame);
                    answered = true;
                    receive.reset();
                    break;
                }
                Timer::after_micros(200).await;
            }

            if answered {
                coordinator.poller().note_reply(plan.addr);
            } else {
                coordinator.poller().note_timeout(plan.addr);
            }
        }

        // ---- Sample the local plot ----
        if Instant::now() >= next_sample {
            reading = sample_sensors(
                &mut adc,
                &mut soil_channel,
                &mut dht_pin,
                &config,
                reading.sequence.wrapping_add(1),
            )
            .await;
            next_sample = Instant::now() + Duration::from_secs(board::SAMPLE_INTERVAL_S);
        }

        // ---- Push a batch and collect commands ----
        if Instant::now() >= next_uplink {
            let batch = coordinator.build_batch(now_s, reading, irrigation.is_open());
            if coordinator.buffer().len() == flora_device::coord::BUFFER_SLOTS {
                warn!("offline buffer full; oldest batch dropped");
            }
            coordinator.queue_batch(batch);

            match deliver(&mut socket, stack, &storage, &mut coordinator).await {
                Some(status) => match uplink::next_state(Some(status), attempts) {
                    UplinkState::Ready => attempts = 0,
                    UplinkState::Rejected => {
                        error!("uplink rejected with {}; check credentials", status);
                        attempts = 0;
                    }
                    _ => attempts = attempts.saturating_add(1),
                },
                None => attempts = attempts.saturating_add(1),
            }

            // Commands ride the same schedule: the cloud cannot push, so the
            // device asks whenever it is awake anyway.
            poll_commands(
                &mut socket,
                stack,
                &storage,
                &mut coordinator,
                &config,
                &mut irrigation,
                &mut uart,
                &mut de_pin,
                &mut local_valve_open,
                now_s,
            )
            .await;

            let backoff = uplink::backoff_seconds(attempts);
            next_uplink =
                Instant::now() + Duration::from_secs(board::UPLINK_INTERVAL_S.max(backoff));
        }

        Timer::after_micros(500).await;
    }
}

/// Bring up the radio and the network stack.
struct RadioPins {
    pio: embassy_rp::Peri<'static, PIO0>,
    dma: embassy_rp::Peri<'static, DMA_CH0>,
    pwr: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_23>,
    cs: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_25>,
    dio: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_24>,
    clk: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_29>,
}

async fn start_network(
    spawner: &Spawner,
    pins: RadioPins,
    _storage: &mut UplinkStorage<'_>,
) -> Stack<'static> {
    // The radio is powered down until this pin goes high; it is part of the
    // chip's wiring, not a choice. PIN_25 doubles as the CYW43 chip-select
    // and the onboard LED gate, so the LED is driven through the radio
    // from here on, never as a plain GPIO.
    let pwr = Output::new(pins.pwr, Level::Low);
    let cs = Output::new(pins.cs, Level::High);
    let mut pio = Pio::new(pins.pio, Irqs);
    let spi = cyw43_pio::PioSpi::new(
        &mut pio.common,
        pio.sm0,
        cyw43_pio::DEFAULT_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        pins.dio,
        pins.clk,
        DmaChannel::new(pins.dma, Irqs),
    );

    // Radio firmware, vendored beside the crate (see
    // `cyw43-firmware/README.md`): the chip's own firmware, its regulatory
    // table, and the board's calibration data.
    let fw = cyw43::aligned_bytes!("../../cyw43-firmware/43439A0.bin");
    let clm = cyw43::aligned_bytes!("../../cyw43-firmware/43439A0_clm.bin");
    let nvram = cyw43::aligned_bytes!("../../cyw43-firmware/nvram_rp2040.bin");

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (net_device, mut control, runner) = cyw43::new(state, pwr, spi, fw, nvram).await;
    spawner.spawn(cyw43_task(runner).unwrap());

    control.init(clm).await;
    // The radio is the dominant power load; power-save idles it between
    // uplinks, which the solar budget assumes.
    control
        .set_power_management(cyw43::PowerManagementMode::PowerSave)
        .await;

    // Join the best available access point from the compiled dictionary.
    // `wifi.toml` beside this crate is the single place to edit.
    let networks = flora_aggregator::wifi_networks();
    info!("wifi dictionary: {} network(s) compiled in", networks.len());
    join_first_available(&mut control, &networks).await;
    info!("network up");

    let seed = embassy_rp::clocks::RoscRng.next_u64();
    let (stack, net_runner) = embassy_net::new(
        net_device,
        embassy_net::Config::dhcpv4(Default::default()),
        RESOURCES.init(StackResources::new()),
        seed,
    );
    let stack = *STACK.init(stack);
    spawner.spawn(net_task(net_runner).unwrap());
    stack
}

static RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
static STACK: StaticCell<Stack<'static>> = StaticCell::new();

/// Send one buffered batch to the cloud.
///
/// Returns the HTTP status, or `None` if the request never completed. The
/// batch is popped only after a 2xx: everything before that point must leave
/// it buffered for the next attempt.
async fn deliver(
    socket: &mut TcpSocket<'static>,
    stack: Stack<'static>,
    storage: &UplinkStorage<'_>,
    coordinator: &mut Coordinator,
) -> Option<u16> {
    let config = storage.uplink_config();
    if !config.is_ready() {
        return None;
    }
    if !config.is_encrypted() {
        // The token is a bearer credential, so plaintext hands it to anyone on
        // the path. Tolerated for a bench server, never for a deployment.
        warn!("uplink is not encrypted; the device token crosses the network in clear");
    }

    let mut body = [0u8; MAX_BATCH_JSON];
    let body_len = {
        let batch = coordinator.buffer().peek()?;
        uplink::encode_body(batch, &mut body)?
    };

    let mut response = [0u8; INGEST_RESPONSE_BYTES];
    let (status, _) = http_request(
        socket,
        stack,
        &config,
        uplink::INGEST_METHOD,
        uplink::INGEST_PATH,
        &body[..body_len],
        &mut response,
    )
    .await?;
    if (200..300).contains(&status) {
        // Only now is it safe to drop the batch.
        coordinator.buffer().pop();
    }
    Some(status)
}

/// The poll response is far too large for the stack, and a `StaticCell`
/// initialized inside the poll would panic on the second poll.
static COMMAND_RESPONSE: StaticCell<[u8; RESPONSE_BYTES]> = StaticCell::new();
static PARSED_COMMANDS: StaticCell<[Option<CommandWire<'static>>; MAX_COMMANDS]> =
    StaticCell::new();

/// Ask the cloud for queued commands, apply each, and acknowledge it.
#[allow(clippy::too_many_arguments)]
async fn poll_commands(
    socket: &mut TcpSocket<'static>,
    stack: Stack<'static>,
    storage: &UplinkStorage<'_>,
    coordinator: &mut Coordinator,
    config: &NodeConfig,
    irrigation: &mut IrrigationController,
    uart: &mut Uart<'_, uart::Blocking>,
    de_pin: &mut Output<'_>,
    local_valve_open: &mut bool,
    now_s: u32,
) {
    let uplink_config = storage.uplink_config();
    if !uplink_config.is_ready() {
        return;
    }

    let response = &mut *COMMAND_RESPONSE.init([0; RESPONSE_BYTES]);
    let parsed = &mut *PARSED_COMMANDS.init([None; MAX_COMMANDS]);

    let Some((status, len)) = http_request(
        socket,
        stack,
        &uplink_config,
        "GET",
        uplink::COMMANDS_PATH,
        &[],
        response,
    )
    .await
    else {
        return;
    };
    if status != 200 {
        warn!("command poll returned {}", status);
        return;
    }
    let Some((_, body)) = uplink::split_response(&response[..len]) else {
        warn!("command poll response had no complete head");
        return;
    };
    let Ok(body) = core::str::from_utf8(body) else {
        warn!("command poll returned non-UTF-8");
        return;
    };

    let count = match commands::parse_commands(body, parsed) {
        Ok(count) => count,
        Err(_) => {
            // Nothing has been acked, so the cloud will expire these commands
            // rather than hand them out again. Say so loudly: it means a
            // firmware/API shape mismatch.
            error!("command poll parse failed");
            return;
        }
    };
    if count == 0 {
        return;
    }
    info!("{} command(s) queued", count);

    for command in parsed[..count].iter().flatten() {
        let applied = match handle_command(coordinator, config, irrigation, command, now_s) {
            Handling::Applied => true,
            Handling::Routed(bytes, len) => {
                transmit(uart, de_pin, &bytes[..len]).await;
                true
            }
            Handling::Refused => false,
        };
        // A local valve command has already moved the pin through the
        // controller; keep the cached state in step so the next sample does
        // not drive it back.
        *local_valve_open = irrigation.is_open();
        let ack = ack_command(socket, stack, &uplink_config, command.id, applied).await;
        if ack.is_none() {
            warn!("command {} applied but not acknowledged", command.id);
        }
    }
}

enum Handling {
    Applied,
    Routed([u8; MAX_FRAME_LEN], usize),
    Refused,
}

/// Verify a command's signature and route it.
///
/// The signature is checked before any bus traffic is generated, so an
/// unauthenticated cloud cannot cause a valve to move.
fn handle_command(
    coordinator: &mut Coordinator,
    config: &NodeConfig,
    irrigation: &mut IrrigationController,
    command: &CommandWire<'_>,
    now_s: u32,
) -> Handling {
    let routed = RoutedCommand {
        kind: command.kind,
        addr: command.node_addr,
        payload: command.payload,
    };
    match coordinator.accept_command(
        &command.app_pubkey,
        &command.signature,
        routed,
        command.nonce,
        command.ts,
        now_s,
    ) {
        Ok(DispatchOutcome::Local) => {
            // Only a valve command has a local meaning; thresholds and
            // calibration are bus operations even when addressed here.
            if command.kind == flora_protocol::KIND_SET_VALVE
                && apply_local_valve(&command.payload, config, irrigation, now_s)
            {
                Handling::Applied
            } else {
                Handling::Refused
            }
        }
        Ok(DispatchOutcome::Routed(bytes, len)) => Handling::Routed(bytes, len),
        Ok(DispatchOutcome::UnknownNode) => Handling::Refused,
        Err(_) => {
            warn!("command signature refused");
            Handling::Refused
        }
    }
}

/// Acknowledge one command, reporting whether it was applied or refused.
async fn ack_command(
    socket: &mut TcpSocket<'static>,
    stack: Stack<'static>,
    config: &UplinkConfig<'_>,
    id: &str,
    applied: bool,
) -> Option<u16> {
    let mut path = [0u8; 64];
    let path_len = commands::ack_path(id, &mut path)?;
    let path = core::str::from_utf8(&path[..path_len]).ok()?;
    let body = commands::ack_body(applied);

    let mut response = [0u8; 256];
    let (status, _) = http_request(
        socket,
        stack,
        config,
        "POST",
        path,
        body.as_bytes(),
        &mut response,
    )
    .await?;
    (200..300).contains(&status).then_some(status)
}

/// One HTTP/1.1 request over a fresh TCP connection, returning the status.
///
/// A connection per request costs a handshake but avoids holding a socket
/// open across a sleep, which is what the power budget wants.
async fn http_request(
    socket: &mut TcpSocket<'static>,
    stack: Stack<'static>,
    config: &UplinkConfig<'_>,
    method: &str,
    path: &str,
    body: &[u8],
    response: &mut [u8],
) -> Option<(u16, usize)> {
    let (host, port) = split_host(config.host());
    let address = resolve(stack, host).await?;

    // Reset any connection left open by a failed attempt: a socket is only
    // connectable from the closed state.
    socket.abort();
    if socket.connect((address, port)).await.is_err() {
        return None;
    }

    let mut head = [0u8; uplink::MAX_HEAD_BYTES];
    let head_len = uplink::write_request(method, path, config, body.len(), &mut head).ok()?;
    if socket.write_all(&head[..head_len]).await.is_err() {
        return None;
    }
    if !body.is_empty() && socket.write_all(body).await.is_err() {
        return None;
    }
    socket.flush().await.ok()?;

    // `Connection: close` means the body ends when the socket does; a
    // Content-Length is not needed to frame it.
    let mut len = 0usize;
    loop {
        if len == response.len() {
            break;
        }
        match socket.read(&mut response[len..]).await {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(_) => break,
        }
    }
    let status = uplink::parse_status(&response[..len])?;
    Some((status, len))
}

/// Resolve a hostname to the first IPv4 answer.
///
/// IPv6 is not attempted: the deployment is a single cloud host, and trying
/// both would double the timeout on a network with one path out.
async fn resolve(stack: Stack<'static>, host: &str) -> Option<IpAddress> {
    let socket = embassy_net::dns::DnsSocket::new(stack);
    let answers = socket
        .query(host, embassy_net::dns::DnsQueryType::A)
        .await
        .ok()?;
    answers.first().copied()
}

/// Split `host:port` into its parts, defaulting to the plaintext port.
///
/// The firmware speaks HTTP only until a TLS stack is wired in, so the
/// default is 80 rather than 443: sending a bearer token to 443 without TLS
/// would fail the handshake rather than silently succeed.
fn split_host(host: &str) -> (&str, u16) {
    match host.rsplit_once(':') {
        Some((name, port)) => (name, port.parse().unwrap_or(80)),
        None => (host, 80),
    }
}

/// Byte-at-a-time frame reassembly with an idle timeout.
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

/// Drive DE, transmit, and release the bus.
async fn transmit(uart: &mut Uart<'_, uart::Blocking>, de_pin: &mut Output<'_>, bytes: &[u8]) {
    de_pin.set_high();
    Timer::after_micros(2).await;
    if uart.blocking_write(bytes).is_err() || uart.blocking_flush().is_err() {
        de_pin.set_low();
        return;
    }
    while uart.busy() {}
    de_pin.set_low();
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
/// Every wait is bounded, so a disconnected sensor costs a bounded slice of
/// the sample period rather than a hang.
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

// ---- Provisioning over USB ------------------------------------------------

/// What the provisioner sends. The shape is shared with the host tool
/// through `flora_protocol::provision`, so a field cannot go missing on one
/// side only.
#[derive(serde::Deserialize)]
struct SetIdentityWire<'a> {
    cmd: &'a str,
    gateway_id: &'a str,
    device_id: &'a str,
    device_token: &'a str,
    cloud_url: &'a str,
}

fn make_usb_builder(
    usb: embassy_rp::Peri<'static, USB>,
) -> embassy_usb::Builder<'static, AggUsbDriver> {
    let driver = Driver::new(usb, Irqs);
    let mut config = embassy_usb::Config::new(0x2E8A, 0x000B);
    config.manufacturer = Some("FLORA");
    config.product = Some("FLORA Aggregator Provisioning");
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

/// Greet the provisioner and accept an identity until one sticks.
///
/// Looping here rather than booting unprovisioned is deliberate: an
/// aggregator with no credentials would join WiFi, fail every uplink, and
/// look identical to a network fault.
async fn commission_over_usb(
    cdc: &mut CdcAcmClass<'static, AggUsbDriver>,
    storage: &mut UplinkStorage<'_>,
    board_id: [u8; 8],
) {
    let (uuid, public_key) = device_identity(board_id);
    let uuid = encode_hex_8(&uuid);
    let public_key_hex = encode_hex_32(&public_key);
    let mut failed = 0u32;

    loop {
        cdc.wait_connection().await;
        let mut greeting: heapless::String<192> = heapless::String::new();
        if writeln!(
            greeting,
            "{{\"flora_prov\":{},\"hw\":\"{}\",\"fw\":\"{}\",\"pubkey\":\"{}\",\"uuid\":\"{}\"}}",
            flora_protocol::HANDSHAKE_VERSION,
            flora_protocol::AGGREGATOR_HW,
            FIRMWARE_VERSION,
            public_key_hex,
            uuid
        )
        .is_err()
        {
            continue;
        }
        if write_usb_line(cdc, greeting.as_bytes()).await.is_err() {
            continue;
        }

        let mut line = [0u8; 256];
        let length = match read_usb_line(cdc, &mut line).await {
            Ok(length) => length,
            Err(_) => continue,
        };
        let identity = match serde_json_core::from_slice::<SetIdentityWire>(&line[..length]) {
            Ok((request, _)) if request.cmd == flora_protocol::provision::SetIdentity::CMD => {
                match identity_from_wire(&request) {
                    Ok(identity) => identity,
                    Err(_) => {
                        let _ = write_usb_line(cdc, b"{\"ok\":false,\"error\":\"bad_identity\"}\n")
                            .await;
                        continue;
                    }
                }
            }
            _ => {
                let _ = write_usb_line(cdc, b"{\"ok\":false}\n").await;
                continue;
            }
        };

        if storage.save_identity(identity).is_err() {
            failed += 1;
            let _ = write_usb_line(cdc, b"{\"ok\":false,\"error\":\"storage\"}\n").await;
            if failed >= 3 {
                error!("could not store the identity after three attempts");
                panic!();
            }
            continue;
        }
        if write_usb_line(cdc, b"{\"ok\":true}\n").await.is_ok() {
            info!("identity provisioned");
            return;
        }
    }
}

fn identity_from_wire(request: &SetIdentityWire<'_>) -> Result<Identity, StorageError> {
    let gateway_id = decode_hex_16(request.gateway_id).ok_or(StorageError::TooLong)?;
    Identity::from_parts(
        gateway_id,
        request.device_id,
        request.device_token,
        request.cloud_url,
    )
}

fn decode_hex_16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    commands::unhex_into(text, &mut out)?;
    Some(out)
}

/// The board's stable identity: a UUID and an Ed25519 public key.
///
/// The key is derived from the flash chip's unique id, which every board
/// has and no re-flash changes. That makes the identity stable across
/// firmware updates, at the cost of the secret being derivable by anyone
/// holding the board — acceptable because the device never signs with it;
/// it exists to give the cloud a stable key-shaped device id. A board that
/// must keep a secret needs a secure element, which the Pico does not have.
fn device_identity(board_id: [u8; 8]) -> ([u8; 8], [u8; 32]) {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"flora-aggregator-device");
    hasher.update(board_id);
    let digest = hasher.finalize();
    let mut uuid = [0u8; 8];
    uuid.copy_from_slice(&digest[..8]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    let keypair = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(keypair.pk.as_ref());
    (uuid, public_key)
}

async fn read_usb_line(
    cdc: &mut CdcAcmClass<'static, AggUsbDriver>,
    line: &mut [u8; 256],
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
    cdc: &mut CdcAcmClass<'static, AggUsbDriver>,
    line: &[u8],
) -> Result<(), EndpointError> {
    for packet in line.chunks(64) {
        cdc.write_packet(packet).await?;
    }
    Ok(())
}

fn encode_hex_8(bytes: &[u8; 8]) -> heapless::String<16> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = heapless::String::new();
    for byte in bytes {
        let _ = text.push(HEX[(byte >> 4) as usize] as char);
        let _ = text.push(HEX[(byte & 0x0F) as usize] as char);
    }
    text
}

fn encode_hex_32(bytes: &[u8; 32]) -> heapless::String<64> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = heapless::String::new();
    for byte in bytes {
        let _ = text.push(HEX[(byte >> 4) as usize] as char);
        let _ = text.push(HEX[(byte & 0x0F) as usize] as char);
    }
    text
}

fn fatal_storage(_error: StorageError) -> ! {
    error!("aggregator storage or flash identity failure");
    panic!();
}
