use anyhow::Context;
use async_trait::async_trait;
use get_if_addrs::{get_if_addrs, IfAddr};

use crate::checks::{Check, CheckContext, CheckOutput};

pub struct InterfaceCheck;

#[async_trait]
impl Check for InterfaceCheck {
    fn name(&self) -> &'static str {
        "interfaces"
    }

    async fn run(&self, _ctx: &CheckContext) -> anyhow::Result<CheckOutput> {
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
