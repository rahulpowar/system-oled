use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;

use crate::checks::{Check, CheckContext, CheckOutput};

pub struct TailscaleCheck;

#[async_trait]
impl Check for TailscaleCheck {
    fn name(&self) -> &'static str {
        "tailscale"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckOutput> {
        let client = ctx
            .localapi
            .as_ref()
            .ok_or_else(|| anyhow!("LocalAPI client is not configured"))?;
        let timeout = std::time::Duration::from_secs(ctx.args.timeout_secs);
        let status = client.get_status(timeout).await.context("fetch status")?;

        let tailnet_domain = status
            .current_tailnet
            .as_ref()
            .map(|t| t.magic_dns_suffix.trim_end_matches('.').to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let legacy = status.magic_dns_suffix.trim_end_matches('.').to_string();
                if legacy.is_empty() {
                    None
                } else {
                    Some(legacy)
                }
            });
        let device_domain = status
            .me
            .as_ref()
            .map(|me| me.dns_name.trim_end_matches('.').to_string())
            .filter(|s| !s.is_empty());

        let mut lines = Vec::new();
        lines.push(format!(
            "tailnet: {}",
            tailnet_domain.unwrap_or_else(|| "unknown".to_string())
        ));
        lines.push(format!(
            "device: {}",
            device_domain.unwrap_or_else(|| "unknown".to_string())
        ));

        Ok(CheckOutput {
            title: "Tailscale".to_string(),
            lines,
        })
    }
}
