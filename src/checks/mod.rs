use anyhow::{anyhow, Result};
use async_trait::async_trait;

use crate::tailscale::LocalApiClient;
use crate::Args;

pub mod disks;
pub mod interfaces;
pub mod ping;
pub mod system;
pub mod tailscale;
pub mod vcgencmd;

pub struct CheckOutput {
    pub title: String,
    pub lines: Vec<String>,
}

pub struct CheckContext {
    pub args: Args,
    pub localapi: Option<LocalApiClient>,
}

#[async_trait]
pub trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, ctx: &CheckContext) -> Result<CheckOutput>;
}

pub struct CheckInfo {
    pub name: &'static str,
    pub description: &'static str,
}

pub fn available_checks() -> Vec<CheckInfo> {
    vec![
        CheckInfo {
            name: "ping",
            description: "Tailscale peer latency via LocalAPI ping",
        },
        CheckInfo {
            name: "tailscale",
            description: "Tailnet and device DNS names",
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

pub fn build_check(name: &str) -> Option<Box<dyn Check>> {
    match name {
        "ping" => Some(Box::new(ping::PingCheck)),
        "tailscale" | "ts" => Some(Box::new(tailscale::TailscaleCheck)),
        "disks" => Some(Box::new(disks::DiskUsageCheck)),
        "interfaces" | "ifaces" => Some(Box::new(interfaces::InterfaceCheck)),
        "system" | "cpu" | "mem" => Some(Box::new(system::SystemUsageCheck)),
        "vcgencmd" | "rpi" => Some(Box::new(vcgencmd::VcgencmdCheck)),
        _ => None,
    }
}

pub fn selected_checks(args: &Args) -> Result<Vec<Box<dyn Check>>> {
    if args.check.is_empty() {
        return Ok(vec![
            Box::new(ping::PingCheck),
            Box::new(tailscale::TailscaleCheck),
            Box::new(disks::DiskUsageCheck),
            Box::new(interfaces::InterfaceCheck),
            Box::new(system::SystemUsageCheck),
            Box::new(vcgencmd::VcgencmdCheck),
        ]);
    }

    let mut checks = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for raw in &args.check {
        let name = raw.trim().to_ascii_lowercase();
        if name == "all" {
            return Ok(vec![
                Box::new(ping::PingCheck),
                Box::new(tailscale::TailscaleCheck),
                Box::new(disks::DiskUsageCheck),
                Box::new(interfaces::InterfaceCheck),
                Box::new(system::SystemUsageCheck),
                Box::new(vcgencmd::VcgencmdCheck),
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

pub fn requires_localapi(name: &str) -> bool {
    matches!(name, "ping" | "tailscale")
}

pub(crate) fn format_bytes(bytes: u64) -> String {
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
