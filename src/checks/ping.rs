use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::sync::Semaphore;

use crate::checks::{Check, CheckContext, CheckOutput};
use crate::tailscale::{normalize_name, parse_ping_type};

#[derive(Clone, Debug)]
struct PeerTarget {
    name: String,
    ip: String,
}

pub struct PingCheck;

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
