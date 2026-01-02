# system-oled

CLI to list Tailscale peer latency using the LocalAPI.

## Requirements
- Tailscale is installed and running.

## Usage

Linux (unix socket; default uses TS_SOCKET or /var/run/tailscale/tailscaled.sock):

```bash
cargo run --release -- --ping-type disco
```

macOS GUI app (local TCP + password):

```bash
TS_LOCALAPI_ADDR=127.0.0.1:41641 \
TS_LOCALAPI_PASSWORD=your-password-here \
cargo run --release -- --ping-type disco
```

You can also pass flags instead of env vars:

```bash
cargo run --release -- --addr 127.0.0.1:41641 --password your-password-here
```

## Checks (plugins)

By default all checks run. To run a subset:

```bash
cargo run --release -- --check ping
cargo run --release -- --check tailscale
cargo run --release -- --check disks
cargo run --release -- --check interfaces
cargo run --release -- --check system
cargo run --release -- --check vcgencmd
cargo run --release -- --check ping,tailscale,disks,interfaces,system,vcgencmd
```

List available checks:

```bash
cargo run --release -- --list-checks
```

## Continuous mode + OLED (Argon ONE V5)

OLED mode runs continuously and renders one check per page on the Argon ONE V5 OLED over I2C:

```bash
cargo run --release -- --oled --interval-secs 15
```

You can override the I2C bus or address if needed:

```bash
cargo run --release -- --oled --oled-i2c-bus /dev/i2c-1 --oled-i2c-addr 0x3c
```

Defaults target the Argon ONE V5 OLED (SSD1306 128x64 at I2C address 0x3c). Pages auto‑rotate
every 10 seconds if you don’t press the button. Each check is split across multiple OLED pages
if it exceeds the screen, and long lines scroll horizontally instead of being truncated.
To enable page switching with the Argon ONE V5 button:

```bash
cargo run --release -- --oled --oled-button
```
Enable `--oled-button` to use the Argon ONE V5 power button to cycle pages. This exits with an
error if the GPIO line is not accessible (for example, if argononeoledd/argononed owns the line).

### Raspberry Pi (vcgencmd) check

The `vcgencmd` check reads Raspberry Pi firmware metrics (temperature,
throttling state, measured ARM/core clock rates) directly via `/dev/vcio`
without invoking the `vcgencmd` CLI.

## macOS App Store GUI: find LocalAPI password

The App Store GUI uses a local TCP port with a password. The port and password
are exposed via a `sameuserproof-PORT-TOKEN` file held by the IPNExtension
process. You can extract them like this:

```bash
lsof -n -a -c IPNExtension -F | grep -o "sameuserproof-[0-9]*-[a-f0-9]*" | head -1
```

The `PORT` is the number after the first dash, and the `TOKEN` is the hex value
after the second dash. Then set:

```bash
TS_LOCALAPI_ADDR=127.0.0.1:PORT
TS_LOCALAPI_PASSWORD=TOKEN
```

If you're using the standalone macOS variant (not App Store), the port and token
are written under `/Library/Tailscale` as `ipnport` and `sameuserproof-<port>`.

## Options

```
--ping-type <disco|tsmp|icmp|peerapi>  Ping type (defaults to disco)
--check <ping|tailscale|disks|interfaces|system|vcgencmd|all>   Checks to run (defaults to all)
--list-checks                         List available checks and exit
--continuous                          Run continuously and refresh output (forced when --oled)
--interval-secs <n>                   Poll interval for continuous/OLED mode (default 15)
--oled                                Render output to Argon ONE V5 OLED (I2C)
--oled-button                         Enable Argon ONE V5 button to cycle OLED pages
--oled-i2c-bus <path>                 OLED I2C bus (default /dev/i2c-1)
--oled-i2c-addr <addr>                OLED I2C address (default 0x3c)
--size <bytes>                        Optional ping payload size
--timeout-secs <n>                    Request timeout in seconds (default 5)
--concurrency <n>                     Max concurrent pings (default 8)
--include-offline                     Include offline peers
--include-self                        Include this node in results
--addr <host:port>                    LocalAPI TCP address (macOS GUI)
--password <token>                    LocalAPI TCP password (macOS GUI)
--socket <path>                       LocalAPI unix socket path (Linux)
```
