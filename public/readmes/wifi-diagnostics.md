# WiFi Diagnostics Tool

A lightweight, portable WiFi diagnostics collector for **macOS and Windows**. It gathers comprehensive wireless and network information and packages it into a single ZIP — ready to send to IT support or keep for your own records. No installation required.

Download the file(s) for your platform from the buttons above, then follow the steps below.

## What it collects

System and hardware info, IP configuration, routing and active connections, DNS settings, proxy configuration, MTU fragmentation tests, WiFi adapter and driver details, the current connection (signal, BSSID, channel, rates), visible networks, saved profiles, ARP / IPv6 neighbours, firewall status, and recent WiFi logs — all saved to a timestamped report and zipped. Windows additionally includes the built-in WLAN HTML report; macOS adds richer signal data from the hidden `airport` utility.

## macOS — how to run

1. Download **wifi_diagnostics.sh** (button above).
2. Open **Terminal** (Applications → Utilities → Terminal).
3. Go to your Downloads folder: `cd ~/Downloads`
4. Make it executable: `chmod +x wifi_diagnostics.sh`
5. Run it: `./wifi_diagnostics.sh`
6. Enter your Mac password when prompted (a few commands need it).
7. Find `WiFi_Report_YYYYMMDD_HHMMSS.zip` in the same folder.

Requires macOS 11 Big Sur or later (tested through macOS 15). Every tool used is built into macOS — no Homebrew or third-party installs.

## Windows — how to run

1. Download **WiFi_Diagnostics.ps1** and **Run_WiFi_Diagnostics.bat** (buttons above) into the **same folder**.
2. Double-click **Run_WiFi_Diagnostics.bat**.
3. Accept the UAC prompt (Administrator rights are needed for full output).
4. It finishes and closes on its own; find `WiFi_Report_YYYYMMDD_HHMMSS.zip` in the same folder.

Requires Windows 10 or 11 with PowerShell 5.1+ (built in). The launcher uses `-ExecutionPolicy Bypass` for that single run only — it does not change your system's PowerShell policy.

## Privacy & security

All data stays on your machine — nothing is uploaded or transmitted. Both scripts are plain text you can review before running. They collect network configuration data only — never passwords, WiFi keys, personal files, or browser data. Saved network names may be listed, but their passwords are never extracted or logged.

## About the MTU tests

Both versions run two ping tests with the "Don't Fragment" flag, at 1472 and 1500 bytes. If the **1472** test fails, your effective MTU is below 1500 — common on VPNs, PPPoE/DSL, or misconfigured networks — which can cause slow or broken connections for some applications.
