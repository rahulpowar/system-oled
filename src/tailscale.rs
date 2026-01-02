use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose;
use base64::Engine;
use hyper::body::to_bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, HOST};
use hyper::{Body, Client, Method, Request, StatusCode};
use hyperlocal::{UnixClientExt, UnixConnector};
use serde::Deserialize;
use tokio::time;
use urlencoding::encode;

use crate::Args;

const LOCALAPI_HOST: &str = "local-tailscaled.sock";
const DEFAULT_LINUX_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

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
pub struct LocalApiClient {
    transport: Transport,
}

impl LocalApiClient {
    fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub async fn get_status(&self, timeout: Duration) -> Result<Status> {
        let body = self
            .request(Method::GET, "/localapi/v0/status".to_string(), timeout)
            .await?;
        serde_json::from_slice(&body).context("decode status JSON")
    }

    pub async fn ping(
        &self,
        ip: &str,
        ping_type: &str,
        size: Option<usize>,
        timeout: Duration,
    ) -> Result<PingResult> {
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

pub fn build_localapi_client(args: &Args) -> Result<LocalApiClient> {
    if let Some(addr) = &args.addr {
        let base = if addr.starts_with("http://") {
            addr.clone()
        } else {
            format!("http://{addr}")
        };
        let client = Client::new();
        return Ok(LocalApiClient::new(Transport::Tcp {
            base,
            auth: args.password.clone(),
            client,
        }));
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
    Ok(LocalApiClient::new(Transport::Unix {
        socket: PathBuf::from(socket),
        client,
    }))
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
pub struct Status {
    #[serde(rename = "Peer", default)]
    pub peers: std::collections::HashMap<String, PeerStatus>,
    #[serde(rename = "Self")]
    pub me: Option<PeerStatus>,
    #[serde(rename = "MagicDNSSuffix", default)]
    pub magic_dns_suffix: String,
    #[serde(rename = "CurrentTailnet")]
    pub current_tailnet: Option<TailnetStatus>,
}

#[derive(Deserialize, Debug)]
pub struct TailnetStatus {
    #[serde(rename = "MagicDNSSuffix", default)]
    pub magic_dns_suffix: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PeerStatus {
    #[serde(rename = "DNSName", default)]
    pub dns_name: String,
    #[serde(rename = "HostName", default)]
    pub host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
    #[serde(rename = "Online", default)]
    pub online: bool,
}

#[derive(Deserialize, Debug)]
pub struct PingResult {
    #[serde(rename = "Err")]
    pub err: Option<String>,
    #[serde(rename = "LatencySeconds")]
    pub latency_seconds: Option<f64>,
    #[serde(rename = "Endpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "PeerRelay")]
    pub peer_relay: Option<String>,
    #[serde(rename = "DERPRegionCode")]
    pub derp_region_code: Option<String>,
}

pub fn normalize_name(peer: &PeerStatus) -> String {
    if !peer.dns_name.is_empty() {
        peer.dns_name.trim_end_matches('.').to_string()
    } else if !peer.host_name.is_empty() {
        peer.host_name.clone()
    } else {
        "unknown".to_string()
    }
}

pub fn parse_ping_type(input: &str) -> Result<&'static str> {
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
