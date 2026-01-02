use anyhow::{anyhow, Result};
#[cfg(target_os = "linux")]
use anyhow::Context;
use async_trait::async_trait;

use crate::checks::{Check, CheckContext, CheckOutput};

pub struct VcgencmdCheck;

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
    use std::os::unix::io::AsRawFd;

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
    const MAX_WORDS: usize = 32;
    #[repr(align(16))]
    struct MailboxBuf {
        data: [u32; MAX_WORDS],
    }

    let value_size_bytes = (value.len() * 4) as u32;
    let required_words = 2 + 3 + value.len() + 1;
    let total_words = ((required_words + 3) / 4) * 4;
    if total_words > MAX_WORDS {
        return Err(anyhow!("mailbox buffer too large"));
    }

    let mut buf = MailboxBuf { data: [0; MAX_WORDS] };
    buf.data[0] = (total_words * 4) as u32;
    buf.data[1] = 0;
    buf.data[2] = tag;
    buf.data[3] = value_size_bytes;
    buf.data[4] = request_len_bytes;
    buf.data[5..5 + value.len()].copy_from_slice(value);
    buf.data[5 + value.len()] = 0;

    let ret = unsafe { libc::ioctl(fd, ioctl_mbox_property(), buf.data.as_mut_ptr()) };
    if ret < 0 {
        return Err(anyhow!(
            "mailbox ioctl failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if (buf.data[1] & 0x8000_0000) == 0 {
        return Err(anyhow!("mailbox response error: 0x{:08x}", buf.data[1]));
    }

    let value_start = 5;
    let value_end = value_start + value.len();
    value.copy_from_slice(&buf.data[value_start..value_end]);
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
