# macOS Hardening Helper (v0.16) for Apple Silicon

> Opinionated, interactive macOS hardening helper inspired by  
> [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide).[]

idea of possible adding features to project, base on own expirience in build own sec script

The design goal is:

- **No “magic one‑click hardening”** – the user is always asked before impactful changes.
- **Reproducibility** – changes are implemented as shell logic, not manual click-through steps.
- **Transparency** – clear logging, no hidden behavior, no automatic FileVault enablement.

The intent of this PR is not to prescribe a specific tool, but to suggest a few concrete, automatable improvements that could be reflected in the guide itself, with this helper serving as one possible implementation reference.[]

---

## Features Overview

### Base System Hardening

The helper implements and validates a number of recommendations that already exist in the guide (firewall, Gatekeeper, FileVault, privacy defaults), and may serve as a reference for adding more explicit, Apple Silicon–specific examples to the documentation.

In particular, the script:

- Enforces strict shell behavior for hardening-oriented scripts (`set -uo pipefail`, error traps, clear log levels).
- Bootstraps **Homebrew** without using root and with explicit `brew --prefix` handling.

These patterns could be mirrored in the guide as “example shell snippets” for readers who prefer reproducible command-line steps over purely GUI instructions.

---

### 1.1 Security Tooling Orchestration

The script implements a lightweight “security tooling orchestrator” on top of Homebrew and pipx:

1. **Homebrew formulas:**

   - `lynis` — system audit.

2. **Homebrew casks (Objective-See & friends):**

   - `LuLu` (firewall)
   - `BlockBlock` 
   - `KnockKnock`
   - `DoNotDisturb`
   - `OverSight`
   - `pareto-security` (daily use regular user app)
   - Mergen.app https://github.com/sametsazak/mergen (analog lynis with gui and CIS Benchmark) Note: verify the project is actively maintained before recommending it in a production hardening workflow.

   

### 1.2 Vulnerability & Dependency Scanning

The script encourages regular vulnerability scanning of packages and dependencies:

- **Homebrew package CVEs:**
  - Integrates `brew-vulns` tap and formula.
  - Installs or updates `brew-vulns`.
  - Warns if the binary is not in `PATH` and suggests how to fix it.
- **Python dependency CVEs:**
  - Installs **pipx** when needed.
  - Installs or upgrades **pip-audit** via pipx.
  - Checks for outdated pip-audit versions and offers to upgrade.
  - Encourages running `pip-audit` against Python environments

### 1.3 CIS-Style pmset Baseline

For mobile and desktop use (not hardened servers), the script:

- Displays current `pmset -g` values for transparency.
- Offers to apply a CIS‑style baseline:
  - `sleep` = 15 minutes
  - `displaysleep` = 10 minutes
  - `womp` = 0 (Wake on network disabled)

The user can accept or decline this baseline. On hardened server/lab setups, it is explicitly marked as optional and potentially undesirable.

## 2. Additional Hardening Suggestions for the Guide

Beyond the existing content, there are a few small, targeted changes that would strengthen local security and auditability while remaining easy to explain and to automate.

### 2.1 Disable interactive root login

For single‑user laptops and workstations where interactive root is not required, the guide could recommend explicitly disabling the root account and its login shell.

Example steps:

```sh
# Disable the root account
sudo dsenableroot -d

# Ensure the root user cannot obtain an interactive shell
sudo dscl . -create /Users/root UserShell /usr/bin/false
```

This keeps root available for privilege escalation via `sudo` while reducing the risk of an attacker obtaining a persistent, interactive root shell via local or remote login.

### 2.2 Improve sudo audit logging

The guide already emphasizes the importance of `sudo` hygiene; a small addition would be to demonstrate how to log successful `sudo` calls through a dedicated [file] in `/etc/sudoers.d`, instead of editing `/etc/sudoers` directly.

For example:

```sh
sudo visudo -f /etc/sudoers.d/cis_sudoconfig
# inside that :
Defaults log_allowed #write detailed log with timestamp each use of sudo command 
Defaults timestamp_type=tty #request user write sudo password in each new terminal session
Defaults timestamp_timeout=0 #set default sudo timeout to 0 seconds, make request password each time for use sudo (by default its 15 minutes)
```

This pattern keeps local hardening aligned with common CIS-style recommendations, improves forensic visibility, and is easy to deploy in both manual and automated setups.

### 2.3 Encourage Secure Keyboard Entry in Terminal

Terminal sessions are often where secrets (passwords, API keys, passphrases) are typed, yet many users are unaware of **Secure Keyboard Entry** in Terminal.app, which prevents other processes from eavesdropping on keystrokes.

The guide could:

- Explicitly recommend enabling Secure Keyboard Entry:
  - Manually via: `Terminal > Settings > Profiles > Keyboard > Use Secure Keyboard Entry`
  
  `Enable Secure Keyboard Entry in Terminal (unless you use YubiKey or applications such as TextExpander).`
  
- And, for managed environments, mention that this can be enforced via MDM by shipping a profile with:
  - `PayloadType` = `com.apple.Terminal`
  - `SecureKeyboardEntry` = `true`
  
  > Already in the guide: *"Enable Secure Keyboard Entry in Terminal..."*
  > Suggested addition: MDM enforcement note (`PayloadType: com.apple.Terminal`, `SecureKeyboardEntry: true`) for managed environments

---

## 3. Idea of Separated Profiles for Web Browsing

### 3.1 VPN Daily Profile Module (Concept)

Goal: reasonable privacy and security for everyday use without breaking too many workflows.

### Core Ideas

- Require a trusted VPN client:
  - Example: OpenVPN, WireGuard, or a reputable first‑party macOS client.
- Integrate with the rest of the hardening ecosystem:
  - Ensure macOS Application Firewall is enabled.
  - Leverage `dnscrypt-proxy` or provider’s DNS to avoid leaks.
- Provide simple checks:
  - External IP/VPN status check (`curl` to a trusted endpoint).
  - DNS leak test (opening well‑known test sites in the browser).
  - Optional logging via Privoxy / proxy toggles.

### Typical Workflow

1. User starts the VPN Daily profile script.
2. Script checks:
   - Is the VPN client installed?
   - Is the connection up? (Basic IP + DNS checks)
3. Script optionally:
   - Launches the VPN client if not running.
   - Configures system DNS toward:
     - Trusted resolver (e.g., Quad9), and/or
     - Local `dnscrypt-proxy` if installed.
4. Script prints clear “safe to use / not safe to use” status and links to DNS/IP leak tests.

No VPN provider is hardcoded; the module is meant to be adapted to the user’s provider of choice.

### 3.2 Paranoid Tor Profile Module (Concept)

**File:** `profile-paranoid-tor.sh`

Goal: maximize network anonymity at the cost of convenience and performance.

### Threat Model

- Assumes the user is willing to:
  - Accept slower connections.
  - Compartmentalize activities into Tor‑only contexts.
  - Respect strict “no direct clearnet from this profile” rules.

### Core Ideas

- Use Tor (or Tor Browser Bundle) as the primary egress:
  - Optionally route traffic through local SOCKS proxy exposed by Tor.
- Integrate with Privoxy / dnscrypt‑proxy where appropriate:
  - HTTP proxying via Privoxy → Tor.
  - DNS handled by Tor / dnscrypt to minimize leaks.
- Tight firewall rules:
  - Limit outbound traffic to Tor and local proxies.
  - Optionally block all non‑Tor outbound connections from selected network interfaces or user contexts.

### Typical Workflow

1. User starts the Paranoid Tor profile script.
2. Script checks:
   - Is Tor/Tor Browser installed?
   - Is Privoxy installed (if using Privoxy + Tor chain)?
3. Script:
   - Starts Tor/Privoxy if needed.
   - Adjusts system / application proxy settings to route selected traffic via Tor.
   - Optionally adds stricter PF rules or app‑level constraints (conceptual; exact rules depend on user’s environment and risk tolerance).
4. Script prints:
   - Which interfaces/ports are restricted.
   - Which applications are expected to use Tor‑only paths.
   - How to revert back to a normal profile.

The Tor profile is intentionally designed as an **opt‑in “mode”**, not something that silently rewires the entire system without the user’s consent.

## 4. How this aligns with the guide

The helper intentionally follows the same philosophy as the original guide:

- All impactful changes are optional, explained, and logged.
- Defaults aim for a reasonable balance between security and usability for a single macOS client, not an enterprise fleet.[]
- Hardening steps are implemented as small, auditable shell functions that map directly to guide sections (firewall, privacy defaults, security tooling, power management).[]

By incorporating the additional points above (root account lockdown, sudo logging via `/etc/sudoers.d`, and Secure Keyboard Entry / MDM hints), the guide would:

- Cover a few important but currently under‑documented macOS knobs.
- Provide concrete command-line and configuration examples that are easy to automate.
- Stay consistent with the existing “teach, don’t blindly automate” philosophy while acknowledging that many users will script these steps as shown in this helper.