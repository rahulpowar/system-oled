use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose;
use base64::Engine;
use clap::Parser;
#[cfg(target_os = "linux")]
use embedded_graphics::mono_font::ascii::FONT_6X10;
#[cfg(target_os = "linux")]
use embedded_graphics::mono_font::MonoTextStyle;
#[cfg(target_os = "linux")]
use embedded_graphics::pixelcolor::BinaryColor;
#[cfg(target_os = "linux")]
use embedded_graphics::prelude::*;
#[cfg(target_os = "linux")]
use embedded_graphics::text::{Baseline, Text};
use get_if_addrs::{get_if_addrs, IfAddr};
use hyper::body::to_bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, HOST};
use hyper::{Body, Client, Method, Request, StatusCode};
use hyperlocal::{UnixClientExt, UnixConnector};
#[cfg(target_os = "linux")]
use linux_embedded_hal::I2cdev;
use serde::Deserialize;
#[cfg(target_os = "linux")]
use ssd1306::prelude::*;
#[cfg(target_os = "linux")]
use ssd1306::mode::BufferedGraphicsMode;
#[cfg(target_os = "linux")]
use ssd1306::I2CDisplayInterface;
#[cfg(target_os = "linux")]
use ssd1306::Ssd1306;
use sysinfo::{Disks, System};
use tokio::sync::Semaphore;
use tokio::time;
use urlencoding::encode;

const LOCALAPI_HOST: &str = "local-tailscaled.sock";
const DEFAULT_LINUX_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";
const DEFAULT_OLED_I2C_BUS: &str = "/dev/i2c-1";
const DEFAULT_OLED_I2C_ADDR: &str = "0x3c";
const OLED_MAX_COLS: usize = 21;
const OLED_MAX_LINES: usize = 6;

#[derive(Parser, Debug, Clone)]
#[command(about = "Run system checks (Tailscale latency, disk usage, etc.)", version)]
struct Args {
    /// Checks to run (ping, disks, interfaces, system, vcgencmd). If omitted, runs all checks.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    check: Vec<String>,

    /// List available checks and exit
    #[arg(long)]
    list_checks: bool,

    /// Run continuously and refresh output
    #[arg(long)]
    continuous: bool,

    /// Poll interval in seconds for continuous mode
    #[arg(long, default_value_t = 15)]
    interval_secs: u64,

    /// Render output to the Argon ONE V5 OLED (I2C)
    #[arg(long)]
    oled: bool,

    /// I2C bus for OLED (Raspberry Pi)
    #[arg(long, default_value = DEFAULT_OLED_I2C_BUS)]
    oled_i2c_bus: String,

    /// I2C address for OLED (hex or decimal)
    #[arg(long, default_value = DEFAULT_OLED_I2C_ADDR)]
    oled_i2c_addr: String,

    /// Ping type: disco, tsmp, icmp, peerapi
    #[arg(long, default_value = "disco")]
    ping_type: String,

    /// Optional ping payload size (bytes)
    #[arg(long)]
    size: Option<usize>,

    /// Max concurrent pings
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,

    /// Include offline peers
    #[arg(long)]
    include_offline: bool,

    /// Include this node in results
    #[arg(long)]
    include_self: bool,

    /// Use LocalAPI TCP addr (macOS GUI), e.g. 127.0.0.1:41641
    #[arg(long, env = "TS_LOCALAPI_ADDR")]
    addr: Option<String>,

    /// LocalAPI TCP password (macOS GUI)
    #[arg(long, env = "TS_LOCALAPI_PASSWORD")]
    password: Option<String>,

    /// LocalAPI unix socket path (Linux)
    #[arg(long, env = "TS_SOCKET")]
    socket: Option<String>,
}

#[derive(Clone)]
enum Transport {
    Tcp {
        base: String,
        auth: Option<String>,
        client: Client<hyper::client::HttpConnector>,
    },
    Unix {
        socket: PathBuf,
        client: Client<UnixConnector>,
    },
}

#[derive(Clone)]
struct LocalApiClient {
    transport: Transport,
}

impl LocalApiClient {
    fn new(transport: Transport) -> Self {
        Self { transport }
    }

    async fn get_status(&self, timeout: Duration) -> Result<Status> {
        let body = self
            .request(Method::GET, "/localapi/v0/status".to_string(), timeout)
            .await?;
        serde_json::from_slice(&body).context("decode status JSON")
    }

    async fn ping(&self, ip: &str, ping_type: &str, size: Option<usize>, timeout: Duration) -> Result<PingResult> {
        let mut path = format!(
            "/localapi/v0/ping?ip={}&type={}",
            encode(ip),
            encode(ping_type)
        );
        if let Some(size) = size {
            path.push_str(&format!("&size={}", size));
        }
        let body = self.request(Method::POST, path, timeout).await?;
        serde_json::from_slice(&body).context("decode ping JSON")
    }

    async fn request(&self, method: Method, path: String, timeout: Duration) -> Result<Vec<u8>> {
        match &self.transport {
            Transport::Tcp { base, auth, client } => {
                let uri = format!("{base}{path}");
                let mut req = Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .body(Body::empty())
                    .context("build request")?;
                {
                    let headers = req.headers_mut();
                    headers.insert(HOST, hyper::header::HeaderValue::from_static(LOCALAPI_HOST));
                    headers.insert(ACCEPT, hyper::header::HeaderValue::from_static("application/json"));
                    if let Some(password) = auth {
                        let token = general_purpose::STANDARD.encode(format!(":{}", password));
                        let value = format!("Basic {}", token);
                        headers.insert(
                            AUTHORIZATION,
                            hyper::header::HeaderValue::from_str(&value).context("auth header")?,
                        );
                    }
                }
                let resp = time::timeout(timeout, client.request(req))
                    .await
                    .context("request timeout")??;
                collect_ok(resp, &method, &path).await
            }
            Transport::Unix { socket, client } => {
                let uri: hyper::Uri = hyperlocal::Uri::new(socket, path.as_str()).into();
                let mut req = Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .body(Body::empty())
                    .context("build request")?;
                {
                    let headers = req.headers_mut();
                    headers.insert(HOST, hyper::header::HeaderValue::from_static(LOCALAPI_HOST));
                    headers.insert(ACCEPT, hyper::header::HeaderValue::from_static("application/json"));
                }
                let resp = time::timeout(timeout, client.request(req))
                    .await
                    .context("request timeout")??;
                collect_ok(resp, &method, &path).await
            }
        }
    }
}

async fn collect_ok(
    resp: hyper::Response<Body>,
    method: &Method,
    path: &str,
) -> Result<Vec<u8>> {
    let status = resp.status();
    let body = to_bytes(resp.into_body()).await.context("read response")?;
    if status != StatusCode::OK {
        let text = String::from_utf8_lossy(&body);
        return Err(anyhow!(
            "LocalAPI {} {} failed: {} {}",
            method,
            path,
            status,
            text.trim()
        ));
    }
    Ok(body.to_vec())
}

#[derive(Deserialize, Debug)]
struct Status {
    #[serde(rename = "Peer", default)]
    peers: HashMap<String, PeerStatus>,
    #[serde(rename = "Self")]
    me: Option<PeerStatus>,
}

#[derive(Deserialize, Debug, Clone)]
struct PeerStatus {
    #[serde(rename = "DNSName", default)]
    dns_name: String,
    #[serde(rename = "HostName", default)]
    host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Vec<String>,
    #[serde(rename = "Online", default)]
    online: bool,
}

#[derive(Deserialize, Debug)]
struct PingResult {
    #[serde(rename = "Err")]
    err: Option<String>,
    #[serde(rename = "LatencySeconds")]
    latency_seconds: Option<f64>,
    #[serde(rename = "Endpoint")]
    endpoint: Option<String>,
    #[serde(rename = "PeerRelay")]
    peer_relay: Option<String>,
    #[serde(rename = "DERPRegionCode")]
    derp_region_code: Option<String>,
}

#[derive(Clone, Debug)]
struct PeerTarget {
    name: String,
    ip: String,
}

fn normalize_name(peer: &PeerStatus) -> String {
    if !peer.dns_name.is_empty() {
        peer.dns_name.trim_end_matches('.').to_string()
    } else if !peer.host_name.is_empty() {
        peer.host_name.clone()
    } else {
        "unknown".to_string()
    }
}

fn parse_ping_type(input: &str) -> Result<&'static str> {
    match input.to_ascii_lowercase().as_str() {
        "disco" => Ok("disco"),
        "tsmp" => Ok("TSMP"),
        "icmp" => Ok("ICMP"),
        "peerapi" => Ok("peerapi"),
        other => Err(anyhow!(
            "invalid ping type '{other}'. Use one of: disco, tsmp, icmp, peerapi"
        )),
    }
}

fn build_transport(args: &Args) -> Result<Transport> {
    if let Some(addr) = &args.addr {
        let base = if addr.starts_with("http://") {
            addr.clone()
        } else {
            format!("http://{addr}")
        };
        let client = Client::new();
        return Ok(Transport::Tcp {
            base,
            auth: args.password.clone(),
            client,
        });
    }

    let socket = args
        .socket
        .clone()
        .unwrap_or_else(|| DEFAULT_LINUX_SOCKET.to_string());
    if cfg!(target_os = "macos") && args.addr.is_none() {
        if !Path::new(&socket).exists() {
            eprintln!(
                "Note: macOS GUI app uses LocalAPI over TCP. Set --addr/--password or TS_LOCALAPI_ADDR/TS_LOCALAPI_PASSWORD if the unix socket is unavailable."
            );
        }
    }
    let client = Client::unix();
    Ok(Transport::Unix {
        socket: PathBuf::from(socket),
        client,
    })
}

struct CheckOutput {
    title: String,
    lines: Vec<String>,
}

#[async_trait]
trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, ctx: &CheckContext) -> Result<CheckOutput>;
}

struct CheckContext {
    args: Args,
    localapi: Option<LocalApiClient>,
}

#[cfg(target_os = "linux")]
struct OledConfig {
    bus: String,
    addr: u16,
}

#[cfg(target_os = "linux")]
struct OledDisplay {
    display: Ssd1306<
        I2CInterface<I2cdev>,
        DisplaySize128x64,
        BufferedGraphicsMode<DisplaySize128x64>,
    >,
}

#[cfg(not(target_os = "linux"))]
struct OledDisplay;

#[cfg(target_os = "linux")]
fn parse_i2c_addr(input: &str) -> Result<u16> {
    let trimmed = input.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).context("parse hex i2c address")
    } else {
        trimmed.parse::<u16>().context("parse i2c address")
    }
}

#[cfg(target_os = "linux")]
fn oled_config_from_args(args: &Args) -> Result<OledConfig> {
    Ok(OledConfig {
        bus: args.oled_i2c_bus.clone(),
        addr: parse_i2c_addr(&args.oled_i2c_addr)?,
    })
}

#[cfg(target_os = "linux")]
impl OledDisplay {
    fn new(config: &OledConfig) -> Result<Self> {
        let mut i2c = I2cdev::new(&config.bus).context("open I2C bus")?;
        i2c.set_slave_address(config.addr)
            .context("set OLED I2C address")?;
        let interface = I2CDisplayInterface::new(i2c);
        let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
            .into_buffered_graphics_mode();
        display
            .init()
            .map_err(|e| anyhow!("init OLED failed: {:?}", e))?;
        display
            .flush()
            .map_err(|e| anyhow!("flush OLED failed: {:?}", e))?;
        Ok(Self { display })
    }

    fn render_lines(&mut self, lines: &[String]) -> Result<()> {
        self.display.clear_buffer();
        let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
        for (idx, line) in lines.iter().take(OLED_MAX_LINES).enumerate() {
            let y = (idx as i32) * 10;
            Text::with_baseline(line, Point::new(0, y), style, Baseline::Top)
                .draw(&mut self.display)
                .map_err(|e| anyhow!("draw OLED text failed: {:?}", e))?;
        }
        self.display
            .flush()
            .map_err(|e| anyhow!("flush OLED failed: {:?}", e))?;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl OledDisplay {
    fn render_lines(&mut self, _lines: &[String]) -> Result<()> {
        Ok(())
    }
}

fn init_oled(args: &Args) -> Result<Option<OledDisplay>> {
    if !args.oled {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    {
        let config = oled_config_from_args(args)?;
        return Ok(Some(OledDisplay::new(&config)?));
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(anyhow!("OLED output is only supported on Linux"))
    }
}

struct PingCheck;

#[async_trait]
impl Check for PingCheck {
    fn name(&self) -> &'static str {
        "ping"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckOutput> {
        let client = ctx
            .localapi
            .as_ref()
            .ok_or_else(|| anyhow!("LocalAPI client is not configured"))?;
        let args = &ctx.args;
        let ping_type = parse_ping_type(&args.ping_type)?;
        let timeout = Duration::from_secs(args.timeout_secs);

        let status = client.get_status(timeout).await.context("fetch status")?;
        let mut peers = Vec::new();

        for peer in status.peers.values() {
            if peer.tailscale_ips.is_empty() {
                continue;
            }
            if !args.include_offline && !peer.online {
                continue;
            }
            peers.push(PeerTarget {
                name: normalize_name(peer),
                ip: peer.tailscale_ips[0].clone(),
            });
        }

        if args.include_self {
            if let Some(me) = status.me.as_ref() {
                if let Some(ip) = me.tailscale_ips.first() {
                    peers.push(PeerTarget {
                        name: normalize_name(me),
                        ip: ip.clone(),
                    });
                }
            }
        }

        let mut lines = Vec::new();
        if peers.is_empty() {
            lines.push("No peers found.".to_string());
            return Ok(CheckOutput {
                title: "Ping".to_string(),
                lines,
            });
        }

        let semaphore = std::sync::Arc::new(Semaphore::new(args.concurrency.max(1)));
        let mut handles = Vec::new();

        for peer in peers {
            let client = client.clone();
            let permit = semaphore.clone().acquire_owned().await?;
            let ping_type = ping_type.to_string();
            let size = args.size;
            let timeout = timeout;
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let result = client.ping(&peer.ip, &ping_type, size, timeout).await;
                (peer, result)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.context("join task")?);
        }

        results.sort_by(|a, b| {
            let a_lat = a
                .1
                .as_ref()
                .ok()
                .and_then(|r| r.latency_seconds)
                .unwrap_or(f64::MAX);
            let b_lat = b
                .1
                .as_ref()
                .ok()
                .and_then(|r| r.latency_seconds)
                .unwrap_or(f64::MAX);
            a_lat
                .partial_cmp(&b_lat)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        lines.push(format!(
            "{:<8}  {:<30}  {:<15}  {}",
            "latency", "peer", "ip", "path"
        ));

        for (peer, result) in results {
            match result {
                Ok(res) => {
                    if let Some(err) = res.err.as_ref().filter(|e| !e.is_empty()) {
                        lines.push(format!(
                            "{:<8}  {:<30}  {:<15}  error: {}",
                            "error", peer.name, peer.ip, err
                        ));
                        continue;
                    }
                    let latency_ms = res.latency_seconds.unwrap_or_default() * 1000.0;
                    let path = if let Some(code) = res.derp_region_code.as_ref() {
                        format!("derp {}", code)
                    } else if let Some(relay) = res.peer_relay.as_ref() {
                        format!("relay {}", relay)
                    } else if let Some(endpoint) = res.endpoint.as_ref() {
                        format!("direct {}", endpoint)
                    } else {
                        "unknown".to_string()
                    };
                    lines.push(format!(
                        "{:>6.1}ms  {:<30}  {:<15}  {}",
                        latency_ms, peer.name, peer.ip, path
                    ));
                }
                Err(err) => {
                    lines.push(format!(
                        "{:<8}  {:<30}  {:<15}  error: {}",
                        "error", peer.name, peer.ip, err
                    ));
                }
            }
        }

        Ok(CheckOutput {
            title: "Ping".to_string(),
            lines,
        })
    }
}

struct DiskUsageCheck;

#[async_trait]
impl Check for DiskUsageCheck {
    fn name(&self) -> &'static str {
        "disks"
    }

    async fn run(&self, _ctx: &CheckContext) -> Result<CheckOutput> {
        let mut disks = Disks::new_with_refreshed_list();
        disks.refresh();

        let mut lines = Vec::new();
        lines.push(format!(
            "{:>8}  {:>8}  {:>8}  {:>6}  {}",
            "used", "free", "total", "use%", "mount"
        ));

        for disk in disks.list() {
            let total = disk.total_space();
            let free = disk.available_space();
            let used = total.saturating_sub(free);
            let percent = if total > 0 {
                (used as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let fs = disk.file_system().to_string_lossy().to_string();
            let mount = disk.mount_point().display();
            let mount_display = if fs.is_empty() {
                format!("{mount}")
            } else {
                format!("{mount} ({fs})")
            };
            lines.push(format!(
                "{:>8}  {:>8}  {:>8}  {:>5.1}%  {}",
                format_bytes(used),
                format_bytes(free),
                format_bytes(total),
                percent,
                mount_display
            ));
        }

        if lines.len() == 1 {
            lines.push("No disks found.".to_string());
        }

        Ok(CheckOutput {
            title: "Disk usage".to_string(),
            lines,
        })
    }
}

struct InterfaceCheck;

#[async_trait]
impl Check for InterfaceCheck {
    fn name(&self) -> &'static str {
        "interfaces"
    }

    async fn run(&self, _ctx: &CheckContext) -> Result<CheckOutput> {
        let mut ifaces = get_if_addrs().context("list interfaces")?;
        ifaces.sort_by(|a, b| a.name.cmp(&b.name));

        let mut lines = Vec::new();
        lines.push(format!(
            "{:<12}  {:<5}  {:<39}  {}",
            "iface", "type", "address", "netmask"
        ));

        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            let (family, ip, mask) = match &iface.addr {
                IfAddr::V4(v4) => ("ipv4", v4.ip.to_string(), v4.netmask.to_string()),
                IfAddr::V6(v6) => ("ipv6", v6.ip.to_string(), v6.netmask.to_string()),
            };
            lines.push(format!(
                "{:<12}  {:<5}  {:<39}  {}",
                iface.name, family, ip, mask
            ));
        }

        if lines.len() == 1 {
            lines.push("No interfaces found.".to_string());
        }

        Ok(CheckOutput {
            title: "Interfaces".to_string(),
            lines,
        })
    }
}

struct SystemUsageCheck;

#[async_trait]
impl Check for SystemUsageCheck {
    fn name(&self) -> &'static str {
        "system"
    }

    async fn run(&self, _ctx: &CheckContext) -> Result<CheckOutput> {
        let mut sys = System::new();
        sys.refresh_cpu();
        time::sleep(Duration::from_millis(200)).await;
        sys.refresh_cpu();
        sys.refresh_memory();

        let cpu = sys.global_cpu_info().cpu_usage();
        let mem = read_memory_stats(&sys)?;

        let mut lines = Vec::new();
        lines.push(format!("cpu: {:.1}%", cpu));
        lines.push(format!(
            "mem: {} / {}",
            format_bytes(mem.used_bytes),
            format_bytes(mem.total_bytes)
        ));
        lines.push(format!(
            "swap: {} / {}",
            format_bytes(mem.swap_used_bytes),
            format_bytes(mem.swap_total_bytes)
        ));

        Ok(CheckOutput {
            title: "System".to_string(),
            lines,
        })
    }
}

struct VcgencmdCheck;

#[async_trait]
impl Check for VcgencmdCheck {
    fn name(&self) -> &'static str {
        "vcgencmd"
    }

    async fn run(&self, _ctx: &CheckContext) -> Result<CheckOutput> {
        let mut lines = Vec::new();
        match read_rpi_metrics() {
            Ok(metrics) => {
                let temp_c = metrics.temp_milli_c as f64 / 1000.0;
                let arm_mhz = metrics.arm_hz as f64 / 1_000_000.0;
                let core_mhz = metrics.core_hz as f64 / 1_000_000.0;
                lines.push(format!("temp_c: {:.1}", temp_c));
                lines.push(format!("arm_clock_mhz: {:.1}", arm_mhz));
                lines.push(format!("core_clock_mhz: {:.1}", core_mhz));
                lines.push(format!("throttled: 0x{:08x}", metrics.throttled));

                let mut flags = Vec::new();
                let value = metrics.throttled;
                let set = |bit: u32| (value & (1 << bit)) != 0;
                flags.push(format!("undervoltage: {}", yes_no(set(0))));
                flags.push(format!("freq_capped: {}", yes_no(set(1))));
                flags.push(format!("throttled_now: {}", yes_no(set(2))));
                flags.push(format!("undervoltage_occurred: {}", yes_no(set(16))));
                flags.push(format!("freq_capped_occurred: {}", yes_no(set(17))));
                flags.push(format!("throttled_occurred: {}", yes_no(set(18))));

                let known_mask = (1 << 0)
                    | (1 << 1)
                    | (1 << 2)
                    | (1 << 16)
                    | (1 << 17)
                    | (1 << 18);
                let unknown = value & !known_mask;
                if unknown != 0 {
                    flags.push(format!("other_bits: 0x{:08x}", unknown));
                }

                lines.extend(flags);
            }
            Err(err) => {
                lines.push(format!("error: {}", err));
            }
        }

        Ok(CheckOutput {
            title: "Raspberry Pi (vcgencmd)".to_string(),
            lines,
        })
    }
}

#[derive(Clone, Debug)]
struct RpiMetrics {
    temp_milli_c: u32,
    throttled: u32,
    arm_hz: u32,
    core_hz: u32,
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[derive(Clone, Debug)]
struct MemoryStats {
    total_bytes: u64,
    used_bytes: u64,
    swap_total_bytes: u64,
    swap_used_bytes: u64,
}

fn read_memory_stats(sys: &System) -> Result<MemoryStats> {
    #[cfg(target_os = "linux")]
    {
        return read_memory_stats_linux();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let total_bytes = sys.total_memory();
        let used_bytes = sys.used_memory();
        let swap_total_bytes = sys.total_swap();
        let swap_used_bytes = sys.used_swap();
        return Ok(MemoryStats {
            total_bytes,
            used_bytes,
            swap_total_bytes,
            swap_used_bytes,
        });
    }
}

#[cfg(target_os = "linux")]
fn read_memory_stats_linux() -> Result<MemoryStats> {
    let content = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let mut mem_total_kb = None;
    let mut mem_available_kb = None;
    let mut mem_free_kb = None;
    let mut swap_total_kb = None;
    let mut swap_free_kb = None;

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let key = parts
            .next()
            .unwrap_or("")
            .trim_end_matches(':');
        let value = match parts.next() {
            Some(v) => v.parse::<u64>().ok(),
            None => None,
        };
        match (key, value) {
            ("MemTotal", Some(v)) => mem_total_kb = Some(v),
            ("MemAvailable", Some(v)) => mem_available_kb = Some(v),
            ("MemFree", Some(v)) => mem_free_kb = Some(v),
            ("SwapTotal", Some(v)) => swap_total_kb = Some(v),
            ("SwapFree", Some(v)) => swap_free_kb = Some(v),
            _ => {}
        }
    }

    let total_kb = mem_total_kb.ok_or_else(|| anyhow!("MemTotal not found"))?;
    let available_kb = mem_available_kb.or(mem_free_kb).unwrap_or(0);
    let used_kb = total_kb.saturating_sub(available_kb);
    let swap_total_kb = swap_total_kb.unwrap_or(0);
    let swap_free_kb = swap_free_kb.unwrap_or(0);
    let swap_used_kb = swap_total_kb.saturating_sub(swap_free_kb);

    Ok(MemoryStats {
        total_bytes: total_kb.saturating_mul(1024),
        used_bytes: used_kb.saturating_mul(1024),
        swap_total_bytes: swap_total_kb.saturating_mul(1024),
        swap_used_bytes: swap_used_kb.saturating_mul(1024),
    })
}

#[cfg(target_os = "linux")]
fn read_rpi_metrics() -> Result<RpiMetrics> {
    use std::fs::OpenOptions;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/vcio")
        .context("open /dev/vcio")?;
    let fd = file.as_raw_fd();

    let temp_milli_c = mailbox_get_temperature(fd)?;
    let throttled = mailbox_get_throttled(fd)?;
    let arm_hz = mailbox_get_clock_measured(fd, CLOCK_ARM)?;
    let core_hz = mailbox_get_clock_measured(fd, CLOCK_CORE)?;

    Ok(RpiMetrics {
        temp_milli_c,
        throttled,
        arm_hz,
        core_hz,
    })
}

#[cfg(not(target_os = "linux"))]
fn read_rpi_metrics() -> Result<RpiMetrics> {
    Err(anyhow!("vcgencmd check requires Raspberry Pi Linux (/dev/vcio)"))
}

#[cfg(target_os = "linux")]
const TAG_GET_TEMPERATURE: u32 = 0x0003_0006;
#[cfg(target_os = "linux")]
const TAG_GET_THROTTLED: u32 = 0x0003_0046;
#[cfg(target_os = "linux")]
const TAG_GET_CLOCK_RATE_MEASURED: u32 = 0x0003_0047;
#[cfg(target_os = "linux")]
const CLOCK_ARM: u32 = 3;
#[cfg(target_os = "linux")]
const CLOCK_CORE: u32 = 4;

#[cfg(target_os = "linux")]
fn mailbox_get_temperature(fd: i32) -> Result<u32> {
    let mut value = [0u32, 0u32];
    mailbox_property(fd, TAG_GET_TEMPERATURE, 4, &mut value)?;
    Ok(value[1])
}

#[cfg(target_os = "linux")]
fn mailbox_get_throttled(fd: i32) -> Result<u32> {
    let mut value = [0xffffu32];
    mailbox_property(fd, TAG_GET_THROTTLED, 0, &mut value)?;
    Ok(value[0])
}

#[cfg(target_os = "linux")]
fn mailbox_get_clock_measured(fd: i32, clock_id: u32) -> Result<u32> {
    let mut value = [clock_id, 0u32];
    mailbox_property(fd, TAG_GET_CLOCK_RATE_MEASURED, 4, &mut value)?;
    Ok(value[1])
}

#[cfg(target_os = "linux")]
fn mailbox_property(fd: i32, tag: u32, request_len_bytes: u32, value: &mut [u32]) -> Result<()> {
    let value_size_bytes = (value.len() * 4) as u32;
    let mut buf: Vec<u32> = Vec::with_capacity(2 + 3 + value.len() + 1);
    buf.push(0);
    buf.push(0);
    buf.push(tag);
    buf.push(value_size_bytes);
    buf.push(request_len_bytes);
    buf.extend_from_slice(value);
    buf.push(0);
    buf[0] = (buf.len() * 4) as u32;

    let ret = unsafe { libc::ioctl(fd, ioctl_mbox_property(), buf.as_mut_ptr()) };
    if ret < 0 {
        return Err(anyhow!(
            "mailbox ioctl failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if (buf[1] & 0x8000_0000) == 0 {
        return Err(anyhow!("mailbox response error: 0x{:08x}", buf[1]));
    }

    let value_start = 5;
    let value_end = value_start + value.len();
    value.copy_from_slice(&buf[value_start..value_end]);
    Ok(())
}

#[cfg(target_os = "linux")]
fn ioctl_mbox_property() -> libc::c_ulong {
    const IOC_NRBITS: u32 = 8;
    const IOC_TYPEBITS: u32 = 8;
    const IOC_SIZEBITS: u32 = 14;

    const IOC_NRSHIFT: u32 = 0;
    const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
    const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
    const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

    const IOC_READ: u32 = 2;
    const IOC_WRITE: u32 = 1;
    const VCIO_IOC_MAGIC: u32 = 100;

    let size = std::mem::size_of::<*mut libc::c_void>() as u32;
    let dir = IOC_READ | IOC_WRITE;
    let nr = 0u32;
    let request = (dir << IOC_DIRSHIFT)
        | (VCIO_IOC_MAGIC << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT);
    request as libc::c_ulong
}

struct CheckInfo {
    name: &'static str,
    description: &'static str,
}

fn available_checks() -> Vec<CheckInfo> {
    vec![
        CheckInfo {
            name: "ping",
            description: "Tailscale peer latency via LocalAPI ping",
        },
        CheckInfo {
            name: "disks",
            description: "Free/used space across mounted drives",
        },
        CheckInfo {
            name: "interfaces",
            description: "Local IP addresses for all interfaces",
        },
        CheckInfo {
            name: "system",
            description: "CPU usage, memory, and swap",
        },
        CheckInfo {
            name: "vcgencmd",
            description: "Raspberry Pi firmware metrics (temp, throttling, clocks)",
        },
    ]
}

fn build_check(name: &str) -> Option<Box<dyn Check>> {
    match name {
        "ping" => Some(Box::new(PingCheck)),
        "disks" => Some(Box::new(DiskUsageCheck)),
        "interfaces" | "ifaces" => Some(Box::new(InterfaceCheck)),
        "system" | "cpu" | "mem" => Some(Box::new(SystemUsageCheck)),
        "vcgencmd" | "rpi" => Some(Box::new(VcgencmdCheck)),
        _ => None,
    }
}

fn selected_checks(args: &Args) -> Result<Vec<Box<dyn Check>>> {
    if args.check.is_empty() {
        return Ok(vec![
            Box::new(PingCheck),
            Box::new(DiskUsageCheck),
            Box::new(InterfaceCheck),
            Box::new(SystemUsageCheck),
            Box::new(VcgencmdCheck),
        ]);
    }

    let mut checks = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for raw in &args.check {
        let name = raw.trim().to_ascii_lowercase();
        if name == "all" {
            return Ok(vec![
                Box::new(PingCheck),
                Box::new(DiskUsageCheck),
                Box::new(InterfaceCheck),
                Box::new(SystemUsageCheck),
                Box::new(VcgencmdCheck),
            ]);
        }
        if !seen.insert(name.clone()) {
            continue;
        }
        let check = build_check(&name)
            .ok_or_else(|| anyhow!("unknown check '{name}'. Use --list-checks to see options"))?;
        checks.push(check);
    }

    Ok(checks)
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut idx = 0;
    while value >= 1024.0 && idx < UNITS.len() - 1 {
        value /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{:.0}{}", value, UNITS[idx])
    } else {
        format!("{:.1}{}", value, UNITS[idx])
    }
}

async fn run_checks(checks: &[Box<dyn Check>], ctx: &CheckContext) -> Result<Vec<CheckOutput>> {
    let mut outputs = Vec::with_capacity(checks.len());
    for check in checks {
        outputs.push(check.run(ctx).await?);
    }
    Ok(outputs)
}

fn print_outputs(outputs: &[CheckOutput]) {
    for (idx, output) in outputs.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        println!("== {} ==", output.title);
        for line in &output.lines {
            println!("{}", line);
        }
    }
}

fn truncate_line(line: &str, max_cols: usize) -> String {
    let trimmed = line.trim();
    let len = trimmed.chars().count();
    if len <= max_cols {
        return trimmed.to_string();
    }
    if max_cols <= 3 {
        return trimmed.chars().take(max_cols).collect();
    }
    let mut out: String = trimmed.chars().take(max_cols - 3).collect();
    out.push_str("...");
    out
}

fn build_oled_lines(outputs: &[CheckOutput]) -> Vec<String> {
    let mut lines = Vec::new();
    for output in outputs {
        lines.push(format!("[{}]", output.title));
        lines.extend(output.lines.iter().cloned());
    }

    let mut filtered = Vec::new();
    for line in lines {
        if filtered.len() >= OLED_MAX_LINES {
            break;
        }
        let trimmed = truncate_line(&line, OLED_MAX_COLS);
        if !trimmed.is_empty() {
            filtered.push(trimmed);
        }
    }

    if filtered.is_empty() {
        filtered.push("no data".to_string());
    }

    filtered
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_checks {
        for check in available_checks() {
            println!("{:<8} {}", check.name, check.description);
        }
        return Ok(());
    }

    let checks = selected_checks(&args)?;
    let needs_localapi = checks.iter().any(|c| c.name() == "ping");
    let localapi = if needs_localapi {
        Some(LocalApiClient::new(build_transport(&args)?))
    } else {
        None
    };

    let mut oled = init_oled(&args)?;
    let ctx = CheckContext { args, localapi };

    if ctx.args.continuous {
        let interval = Duration::from_secs(ctx.args.interval_secs.max(1));
        let mut ticker = time::interval(interval);
        loop {
            let outputs = run_checks(&checks, &ctx).await?;
            print_outputs(&outputs);
            if let Some(oled) = oled.as_mut() {
                let oled_lines = build_oled_lines(&outputs);
                oled.render_lines(&oled_lines)?;
            }
            ticker.tick().await;
        }
    } else {
        let outputs = run_checks(&checks, &ctx).await?;
        print_outputs(&outputs);
        if let Some(oled) = oled.as_mut() {
            let oled_lines = build_oled_lines(&outputs);
            oled.render_lines(&oled_lines)?;
        }
    }

    Ok(())
}
