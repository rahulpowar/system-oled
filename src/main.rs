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
use get_if_addrs::{get_if_addrs, IfAddr};
use hyper::body::to_bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, HOST};
use hyper::{Body, Client, Method, Request, StatusCode};
use hyperlocal::{UnixClientExt, UnixConnector};
use serde::Deserialize;
use sysinfo::Disks;
use tokio::sync::Semaphore;
use tokio::time;
use urlencoding::encode;

const LOCALAPI_HOST: &str = "local-tailscaled.sock";
const DEFAULT_LINUX_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

#[derive(Parser, Debug, Clone)]
#[command(about = "Run system checks (Tailscale latency, disk usage, etc.)", version)]
struct Args {
    /// Checks to run (ping, disks, interfaces, vcgencmd). If omitted, runs all checks.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    check: Vec<String>,

    /// List available checks and exit
    #[arg(long)]
    list_checks: bool,

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
            "{:<12}  {:<5}  {:<39}  {:<39}  {}",
            "iface", "type", "address", "netmask", "flags"
        ));

        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            let (family, ip, mask) = match &iface.addr {
                IfAddr::V4(v4) => ("ipv4", v4.ip.to_string(), v4.netmask.to_string()),
                IfAddr::V6(v6) => ("ipv6", v6.ip.to_string(), v6.netmask.to_string()),
            };
            let mut flags = Vec::new();
            let flag_text = if flags.is_empty() {
                "-".to_string()
            } else {
                flags.join(",")
            };
            lines.push(format!(
                "{:<12}  {:<5}  {:<39}  {:<39}  {}",
                iface.name, family, ip, mask, flag_text
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
    mailbox_property(fd, TAG_GET_THROTTLED, 4, &mut value)?;
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
    const IOC_DIRBITS: u32 = 2;

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

    let ctx = CheckContext { args, localapi };

    for (idx, check) in checks.iter().enumerate() {
        let output = check.run(&ctx).await?;
        if idx > 0 {
            println!();
        }
        println!("== {} ==", output.title);
        for line in output.lines {
            println!("{}", line);
        }
    }

    Ok(())
}
