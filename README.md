# DesckVB RAT (v2.9) — Modular .NET RAT, Multi-Stage Delivery & Plugin Ecosystem  
### Toolchain Linkage to “Pjoao1578”

**Author:** ShadowOpCode  
**X/Twitter:** https://x.com/ShadowOpCode

This repository accompanies a full technical report documenting an **active malware ecosystem** centered around **DesckVB RAT**, a **modular .NET Remote Access Trojan** observed in live campaigns in early 2026.

The analysis reconstructs the **entire infection lifecycle**, from initial JavaScript delivery to in-memory execution, C2 communication, and on-demand plugin deployment.

> ⚠️ This repository does **not** distribute malicious binaries.  
> It contains research material, indicators of compromise, and defensive insights only.
<img width="1536" height="1024" alt="DesckVB RAT" src="https://github.com/user-attachments/assets/db59109c-19db-45a4-9da8-40c5a5bd9dee" />

---

## 📄 Report

- **PDF:** `DesckVB_RAT.pdf`
- Main topics covered:
  - Multi-stage infection chain (WSH JavaScript → PowerShell → .NET loader → RAT)
  - Runtime decryption of C2 configuration (host, port, mutex, flags)
  - Reconstruction of the **custom TCP C2 protocol** using historical PCAP data
  - In-depth analysis of modular plugins (keylogger, webcam, AV enum, network probe)
  - Builder analysis (v2.6) in isolated environment
  - OSINT-supported **toolchain linkage** analysis

---

## TL;DR (for people who “just want the point”)

- **DesckVB RAT is not interesting because it is new**, but because it is **stable, modular, and operationally mature**.
- The **plugin-based architecture** allows attackers to selectively deploy capabilities post-compromise.
- Even with inactive C2 infrastructure, **historical PCAP data** enables reliable reconstruction of:
  - protocol structure
  - command semantics
  - plugin delivery mechanisms
- Repeated references to *“Pjoao1578”* across plugins, metadata, and build paths strongly support **shared toolchain / build environment linkage** (not blind attribution).

---

## 🔗 Observed Kill Chain (High Level)

### Stage 1 – WSH JavaScript
- Heavy string obfuscation
- Self-copy to `C:\Users\Public\`
- Relaunch via `wscript.exe //nologo`
- Dynamic reconstruction of a PowerShell payload (Base64)

### Stage 2/3 – PowerShell
- Runtime payload reconstruction
- Connectivity checks (Google domains)
- Anti-analysis logic (process / debugger checks)
- Download of decimal-encoded payload chunks
- In-memory reconstruction of a .NET assembly

### Stage 4 – .NET Loader (Fileless)
- `Assembly.Load()` with reflective invocation
- Execution gated by environment checks
- No dropped PE at rest

### Stage 5 – DesckVB RAT v2.9.0.0
- Runtime decryption of configuration:
  - C2 address and port
  - mutex
  - capability flags
  - C2 authentication password
- Persistent TCP beaconing with reconnect loop
- C2 observed as inactive (RST) during live analysis

---

## 📡 C2 Protocol & Plugin Delivery

Reconstructed from **historical PCAP data**:

- Plugin execution command:
RunBlugin||<BASE64_ENCODED_DLL>
- Consistent protocol elements:
- Field delimiter: `||`
- Message terminator (used by several plugins): `#Sucess#`

This protocol consistency is critical for **network-level detection and hunting**, even when infrastructure changes.

---

## 🧩 Analyzed Plugins (Overview)

- **DetectarAntivirus.dll**
- Enumerates installed security products
- Sends results back to C2

- **Keylogger.dll**
- Low-level keyboard hook (`SetWindowsHookEx`)
- Active window tracking
- Clipboard interception
- Exfiltration via custom TCP protocol

- **Webcam.dll**
- Uses DirectShow (AForge)
- Streams JPEG frames prefixed with `Cam||`
- Attempts to suppress camera LED via registry key
  (effect depends on OEM/driver)

- **Ping_Net.dll**
- ICMP RTT probe (default: `www.google.com.br`)
- Optional `mapa` command performs HTTP(S) fetch of attacker-supplied URLs

---

## 🧪 Builder (v2.6) Validation

A cracked version of the **DesckVB RAT builder (v2.6)** was executed in a **fully isolated lab environment** to compare:

- configuration structure
- plugin naming and layout
- protocol semantics
- versioning conventions

The overlap between builder output and live samples shows **strong continuity across versions**, supporting ecosystem-level clustering.

---

## 🕵️ Toolchain Linkage to “Pjoao1578”

The identifier *“Pjoao1578”* appears repeatedly and independently across:

- `CompanyName` metadata in multiple plugins  
(`Pjoao1578Developer`)
- Debug paths such as:
...\DesckVB Rat\V2.9.0.0\DLL\Blugin Stub\
- Prior public reporting tied to related loaders and tooling

### Correct conclusion
- **Strong evidence of shared toolchain / build environment / branding**
- Useful for **threat clustering and hunting**
- **Not sufficient for definitive personal attribution**

The report intentionally avoids over-attribution and treats these indicators with appropriate analytical rigor.

---

## 🧾 Indicators of Compromise (Excerpt)

> Full tables available in the report appendix.

### C2
- `manikandan83[.]mysynology[.]net:7535`

### Staging URLs (examples)
- `hxxps://andrefelipedonascime1768785037020[.]1552093[.]meusitehostgator[.]com[.]br/.../01.txt`
- `.../02.txt`
- `.../03.txt`
- `.../PeYes`

### SHA256 (examples)
- Stage 1 JS: `9d9cfe5b31a3b020e3c65d440d8355e33f7c056b087ec6aba3093ae1a099ac0`
- PowerShell: `347621f7a3392939d9bdbe8a6c9fda30ba9d3f23cb6733484da8e2993772b7f3`
- Loader: `a675f5a396de1fa732a9d83993884b397f02921bbcf34346fbed32c8f4053064`
- RAT: `affb29980bc9564f1b03fe977e9ca5c7adf254656d639632c4d14e34aa4fdff6`
- Webcam plugin: `ff051dde71487ea459899920ef7014dad8eee4df308eb360555f3e22232c9367`

---

## 🛡️ Detection & Hunting Guidance

### Endpoint Signals
- Obfuscated WSH JavaScript copied to `C:\Users\Public\`
- Execution via `wscript.exe //nologo`
- PowerShell building decimal byte arrays + `Assembly.Load()`
- Mutex:
nozgrb6ev4t4c7sc2hz7iwnnmmwahj54
- Process masquerading (`Update.exe`, `Microsoft` directories)

### Network Signals
- Beacon format containing:
Desk||<machine>||<user>||<locale>||2.9.0.0||
- Plugin delivery via `RunBlugin||`
- Stable delimiter `||` and terminator `#Sucess#`

---

## 📚 Methodology

- Static analysis (strings, IL, metadata)
- Dynamic execution in isolated lab
- Network traffic reconstruction using historical PCAP
- Builder execution for structural comparison

---

## ⚠️ Disclaimer

This research is published for **defensive and analytical purposes only**.

- No malicious binaries are distributed
- Indicators may be reused or decay over time
- Attribution is handled conservatively:
- evidence supports **toolchain linkage and clustering**
- not definitive identification of an individual operator

---

## 📎 Citation

If you reference or reuse this research, please link:
- this repository
- the full PDF report
- the author’s X account (@ShadowOpCode)
