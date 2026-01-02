use anyhow::Result;
use async_trait::async_trait;
use sysinfo::Disks;

use crate::checks::{format_bytes, Check, CheckContext, CheckOutput};

pub struct DiskUsageCheck;

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
