use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use sysinfo::System;
use tokio::time;

use crate::checks::{format_bytes, Check, CheckContext, CheckOutput};

pub struct SystemUsageCheck;

#[async_trait]
impl Check for SystemUsageCheck {
    fn name(&self) -> &'static str {
        "system"
    }

    async fn run(&self, _ctx: &CheckContext) -> Result<CheckOutput> {
        let mut sys = System::new();
        sys.refresh_cpu();
        time::sleep(std::time::Duration::from_millis(200)).await;
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
        let _ = sys;
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
