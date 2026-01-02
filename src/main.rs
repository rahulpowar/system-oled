use std::time::Duration;

use anyhow::{anyhow, Result};
#[cfg(target_os = "linux")]
use anyhow::Context;
use clap::Parser;
use tokio::time;

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
#[cfg(target_os = "linux")]
use linux_embedded_hal::I2cdev;
#[cfg(target_os = "linux")]
use ssd1306::mode::BufferedGraphicsMode;
#[cfg(target_os = "linux")]
use ssd1306::prelude::*;
#[cfg(target_os = "linux")]
use ssd1306::I2CDisplayInterface;
#[cfg(target_os = "linux")]
use ssd1306::Ssd1306;

mod checks;
mod tailscale;

const DEFAULT_OLED_I2C_BUS: &str = "/dev/i2c-1";
const DEFAULT_OLED_I2C_ADDR: &str = "0x3c";
const DEFAULT_OLED_PAGE_SECS: u64 = 10;
const OLED_MAX_COLS: usize = 21;
const OLED_MAX_LINES: usize = 6;

#[derive(Parser, Debug, Clone)]
#[command(about = "Run system checks (Tailscale latency, disk usage, etc.)", version)]
pub struct Args {
    /// Checks to run (ping, tailscale, disks, interfaces, system, vcgencmd). If omitted, runs all checks.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    check: Vec<String>,

    /// List available checks and exit
    #[arg(long)]
    list_checks: bool,

    /// Run continuously and refresh output (forced when --oled is set)
    #[arg(long)]
    continuous: bool,

    /// Poll interval in seconds for continuous/OLED mode
    #[arg(long, default_value_t = 15)]
    interval_secs: u64,

    /// Render output to the Argon ONE V5 OLED (I2C)
    #[arg(long)]
    oled: bool,

    /// Enable Argon ONE V5 button to cycle OLED pages (Linux only)
    #[arg(long)]
    oled_button: bool,

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

#[cfg(not(target_os = "linux"))]
fn spawn_oled_button_watcher() -> Result<Option<tokio::sync::mpsc::UnboundedReceiver<()>>> {
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
fn validate_oled_button_access() -> Result<()> {
    Err(anyhow!("OLED button support requires Linux"))
}

async fn run_checks(
    checks: &[Box<dyn checks::Check>],
    ctx: &checks::CheckContext,
) -> Result<Vec<checks::CheckOutput>> {
    let mut outputs = Vec::with_capacity(checks.len());
    for check in checks {
        outputs.push(check.run(ctx).await?);
    }
    Ok(outputs)
}

fn print_outputs(outputs: &[checks::CheckOutput]) {
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

fn build_oled_pages(outputs: &[checks::CheckOutput]) -> Vec<Vec<String>> {
    let mut pages = Vec::new();
    for output in outputs {
        let mut lines = Vec::new();
        lines.push(truncate_line(&format!("[{}]", output.title), OLED_MAX_COLS));
        for line in &output.lines {
            if lines.len() >= OLED_MAX_LINES {
                break;
            }
            let trimmed = truncate_line(line, OLED_MAX_COLS);
            if !trimmed.is_empty() {
                lines.push(trimmed);
            }
        }
        if lines.len() == 1 {
            lines.push("no data".to_string());
        }
        pages.push(lines);
    }

    if pages.is_empty() {
        pages.push(vec!["no data".to_string()]);
    }

    pages
}

#[cfg(target_os = "linux")]
fn spawn_oled_button_watcher() -> Result<Option<tokio::sync::mpsc::UnboundedReceiver<()>>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        if let Err(err) = oled_button_loop(tx) {
            eprintln!("OLED button watcher stopped: {err}");
        }
    });
    Ok(Some(rx))
}

#[cfg(target_os = "linux")]
fn validate_oled_button_access() -> Result<()> {
    let _ = open_oled_button_handle()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_oled_button_handle() -> Result<gpio_cdev::LineEventHandle> {
    use std::path::Path;

    const GPIO_LINE: u32 = 4;
    let mut chip_paths: Vec<String> = Vec::new();
    for path in ["/dev/gpiochip4", "/dev/gpiochip0"] {
        if Path::new(path).exists() {
            chip_paths.push(path.to_string());
        }
    }
    if let Ok(entries) = std::fs::read_dir("/dev") {
        let mut extra = Vec::new();
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("gpiochip") {
                    extra.push(format!("/dev/{name}"));
                }
            }
        }
        extra.sort();
        for path in extra {
            if !chip_paths.contains(&path) {
                chip_paths.push(path);
            }
        }
    }

    let mut errors = Vec::new();
    for path in &chip_paths {
        match try_open_button_line(path, GPIO_LINE) {
            Ok(events) => return Ok(events),
            Err(err) => errors.push(format!("{path}: {err}")),
        }
    }

    let detail = if errors.is_empty() {
        "no gpiochip devices found".to_string()
    } else {
        errors.join("; ")
    };
    Err(anyhow!(
        "unable to open GPIO line {GPIO_LINE} for OLED button ({detail}). If the Argon daemon is running, it may already own the line (stop argononeoledd/argononed to enable button cycling)."
    ))
}

#[cfg(target_os = "linux")]
fn oled_button_loop(tx: tokio::sync::mpsc::UnboundedSender<()>) -> Result<()> {
    use gpio_cdev::EventType;

    let mut handle = open_oled_button_handle()?;
    const MIN_PRESS_MS: u64 = 100;
    const MAX_PRESS_MS: u64 = 2000;
    let mut pressed_at: Option<std::time::Instant> = None;

    loop {
        let event = handle.get_event().context("read GPIO event")?;
        match event.event_type() {
            EventType::RisingEdge => {
                pressed_at = Some(std::time::Instant::now());
            }
            EventType::FallingEdge => {
                if let Some(start) = pressed_at.take() {
                    let elapsed = start.elapsed();
                    let ms = elapsed.as_millis() as u64;
                    if ms >= MIN_PRESS_MS && ms <= MAX_PRESS_MS {
                        let _ = tx.send(());
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn try_open_button_line(
    path: &str,
    line: u32,
) -> Result<gpio_cdev::LineEventHandle> {
    use gpio_cdev::{Chip, EventRequestFlags, LineRequestFlags};

    let mut chip = Chip::new(path)?;
    let line = chip.get_line(line)?;
    let flags = LineRequestFlags::INPUT;
    line.events(flags, EventRequestFlags::BOTH_EDGES, "system-oled")
        .map_err(|err| err.into())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_checks {
        for check in checks::available_checks() {
            println!("{:<10} {}", check.name, check.description);
        }
        return Ok(());
    }

    let checks = checks::selected_checks(&args)?;
    let needs_localapi = checks
        .iter()
        .any(|c| checks::requires_localapi(c.name()));
    let localapi = if needs_localapi {
        Some(tailscale::build_localapi_client(&args)?)
    } else {
        None
    };

    let mut oled = init_oled(&args)?;
    let ctx = checks::CheckContext { args, localapi };

    let force_continuous = ctx.args.continuous || oled.is_some();

    if force_continuous {
        let interval = Duration::from_secs(ctx.args.interval_secs.max(1));
        let mut ticker = time::interval(interval);
        let page_interval = Duration::from_secs(DEFAULT_OLED_PAGE_SECS);
        let mut page_ticker =
            time::interval_at(time::Instant::now() + page_interval, page_interval);
        let mut outputs = run_checks(&checks, &ctx).await?;
        print_outputs(&outputs);
        let mut pages = build_oled_pages(&outputs);
        let mut page_idx = 0usize;
        if let Some(oled) = oled.as_mut() {
            oled.render_lines(&pages[page_idx])?;
        }

        if ctx.args.oled_button && oled.is_some() {
            validate_oled_button_access()?;
        }
        let mut button_rx = if oled.is_some() && ctx.args.oled_button {
            spawn_oled_button_watcher()?
        } else {
            None
        };

        loop {
            if let Some(rx) = button_rx.as_mut() {
                tokio::select! {
                    _ = ticker.tick() => {
                        outputs = run_checks(&checks, &ctx).await?;
                        print_outputs(&outputs);
                        pages = build_oled_pages(&outputs);
                        if page_idx >= pages.len() {
                            page_idx = 0;
                        }
                        if let Some(oled) = oled.as_mut() {
                            oled.render_lines(&pages[page_idx])?;
                        }
                    }
                    _ = page_ticker.tick(), if oled.is_some() && pages.len() > 1 => {
                        page_idx = (page_idx + 1) % pages.len();
                        if let Some(oled) = oled.as_mut() {
                            oled.render_lines(&pages[page_idx])?;
                        }
                    }
                    msg = rx.recv() => {
                        if msg.is_none() {
                            button_rx = None;
                            continue;
                        }
                        if !pages.is_empty() {
                            page_idx = (page_idx + 1) % pages.len();
                            if let Some(oled) = oled.as_mut() {
                                oled.render_lines(&pages[page_idx])?;
                            }
                            page_ticker = time::interval_at(time::Instant::now() + page_interval, page_interval);
                        }
                    }
                }
            } else {
                tokio::select! {
                    _ = ticker.tick() => {
                        outputs = run_checks(&checks, &ctx).await?;
                        print_outputs(&outputs);
                        pages = build_oled_pages(&outputs);
                        if page_idx >= pages.len() {
                            page_idx = 0;
                        }
                        if let Some(oled) = oled.as_mut() {
                            oled.render_lines(&pages[page_idx])?;
                        }
                    }
                    _ = page_ticker.tick(), if oled.is_some() && pages.len() > 1 => {
                        page_idx = (page_idx + 1) % pages.len();
                        if let Some(oled) = oled.as_mut() {
                            oled.render_lines(&pages[page_idx])?;
                        }
                    }
                }
            }
        }
    } else {
        let outputs = run_checks(&checks, &ctx).await?;
        print_outputs(&outputs);
        if let Some(oled) = oled.as_mut() {
            let pages = build_oled_pages(&outputs);
            oled.render_lines(&pages[0])?;
        }
    }

    Ok(())
}
