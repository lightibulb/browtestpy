# LeakGuard local agent (Layer 3)

Collects what a remote server cannot see: MAC randomization status per
interface, VPN interfaces, DNS resolvers, and hostname.

Runs on Linux, Termux, macOS, Windows. Python 3.9+ and stdlib only.
No pip install required.

## Usage

    python leakguard_agent.py

    python leakguard_agent.py --json

    python leakguard_agent.py --report https://your-app.onrender.com

    python leakguard_agent.py --report http://localhost:8000 --attach SCAN_ID

## What each check means

- **MAC randomized**: the 2nd hex character of the MAC is in {2,6,A,E}.
  That bit is set by the OS when randomizing. Permanent MACs are trackable
  across public networks by nearby observers.
- **VPN interfaces**: names starting with tun/tap/wg/utun/ppp/ipsec.
  Presence means a tunnel is up on the host.
- **DNS resolvers**: from /etc/resolv.conf (Unix) or ipconfig /all (Windows).
  Compare against your VPN provider's expected resolvers.
- **Hostname**: default-looking hostnames (DESKTOP-XXXXX, user-laptop)
  can be a weak fingerprint.
