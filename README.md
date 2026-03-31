# Axios Supply Chain Attack Scanner

On **March 31, 2026**, axios (`1.14.1` and `0.30.4`) was compromised via npm account takeover. A malicious `postinstall` hook deploys a platform-specific RAT that self-deletes after execution. Full details: [Socket.dev writeup](https://socket.dev/blog/axios-npm-package-compromised) | [@feross thread](https://x.com/feross/status/2038807290422370479)

## Run Without Cloning

**Bash (macOS / Linux):**

```bash
curl -fsSL https://raw.githubusercontent.com/ankushKun/amirekt/main/scan-axios.sh | bash -s ~/Developer
```

**PowerShell (Windows):**

```powershell
irm https://raw.githubusercontent.com/ankushKun/amirekt/main/scan-axios.sh -OutFile scan-axios.sh; bash scan-axios.sh "$env:USERPROFILE\Developer"
```

> If you don't have bash on Windows, use WSL or Git Bash. Replace `~/Developer` with your projects root.

**Quick grep (no script needed):**

```bash
find ~/Developer -maxdepth 5 \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -not -path "*/node_modules/*" -exec grep -lE "axios@(1\.14\.1|0\.30\.4)|\"axios\".*\"(1\.14\.1|0\.30\.4)\"|plain-crypto-js" {} +
```

No output = clean. File paths = affected.

## What It Scans

| Check | Details |
|-------|---------|
| **Lockfiles** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` for resolved versions `1.14.1` / `0.30.4` and malicious deps (`plain-crypto-js`, `@shadanai/openclaw`, `@qqbrowser/openclaw-qbot`) |
| **node_modules** | Installed axios and `plain-crypto-js` packages on disk |
| **package.json** | Caret/tilde ranges that could resolve to compromised versions |
| **IOC artifacts** | RAT files: `/Library/Caches/com.apple.act.mond` (macOS), `/tmp/ld.py` (Linux), `%PROGRAMDATA%\wt.exe` (Windows) |
| **Payload hashes** | SHA-256 scan of `/tmp`, `/Library/Caches`, and temp dirs to catch renamed/moved payloads ([source](https://x.com/cyb3rjerry/status/2038835112071278608)) |
| **C2 connections** | Active connections to attacker IP `142.11.206.73` |

### Known Payload Hashes (SHA-256)

| Stage | Hash |
|-------|------|
| Windows Stage 1 | `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd` |
| Windows Stage 2 | `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` |
| macOS | `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` |
| Linux | `fcb81618bb15edfedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` |

*Credit: [@cyb3rjerry](https://x.com/cyb3rjerry/status/2038835112071278608)*

## Usage (cloned)

```bash
chmod +x scan-axios.sh
./scan-axios.sh ~/Developer
```

Exit code `0` = clean, `1` = issues found. Works in CI:

```bash
./scan-axios.sh . || echo "ACTION REQUIRED"
```

## If You're Affected

### Lockfile references bad version but you haven't run `npm install`

1. **Don't run `npm install`** — it will trigger the malicious postinstall hook
2. Pin axios: `"axios": "1.14.0"` (remove `^`)
3. `rm -rf node_modules package-lock.json && npm install`

### You ran `npm install` while compromised version was live

**The RAT had full system access. Treat as full compromise.**

1. **Disconnect from the network** — cut C2 communication to `sfrclak[.]com:8000`
2. **Kill RAT processes and delete artifacts:**

   | Platform | Kill | Delete |
   |----------|------|--------|
   | macOS | `sudo pkill -f com.apple.act.mond` | `/Library/Caches/com.apple.act.mond` |
   | Linux | `pkill -f ld.py` | `/tmp/ld.py` |
   | Windows | `taskkill /F /IM wt.exe` | `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.*` |

3. **Check persistence** — LaunchAgents/LaunchDaemons (macOS), crontab/systemd (Linux), Task Scheduler/registry Run keys (Windows)
4. **Rotate ALL credentials** — SSH keys, npm/Git/cloud tokens, `.env` secrets, browser sessions, password manager if vault was unlocked, CI/CD secrets
5. **Audit lateral movement** — check `last`, shell history, `known_hosts`, DNS logs for C2 domain
6. **Audit CI/CD** — if any runner ran `npm install` during the window, rotate all CI secrets and check for unauthorized publishes
7. **Consider clean OS reinstall** — RAT could have modified system binaries or installed rootkits. Reinstall from clean media, not backups.
8. **Notify your security team** if on a corporate machine

### Clean scan

Harden against future attacks:
- Pin exact versions (no `^` / `~`)
- Use `npm install --ignore-scripts` and audit postinstall hooks
- Use `npm ci` in CI for lockfile integrity
- Enable npm 2FA
- Use [Socket.dev](https://socket.dev) or [Snyk](https://snyk.io) for supply chain monitoring

## Sources

- [Socket.dev: axios npm package compromised](https://socket.dev/blog/axios-npm-package-compromised)
- [@feross on X](https://x.com/feross/status/2038807290422370479)

## License

MIT
