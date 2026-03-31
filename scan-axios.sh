#!/usr/bin/env bash
# scan-axios.sh — Scan for projects affected by the axios supply chain attack (March 31, 2026)
#
# Compromised versions: axios@1.14.1, axios@0.30.4
# Malicious dependency: plain-crypto-js@4.2.1
# Attack: npm account takeover (jasonsaayman) → RAT deployment via postinstall hook
# C2: sfrclak[.]com:8000 / 142.11.206.73
#
# Usage: ./scan-axios.sh [directory]   (defaults to current directory)

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCAN_DIR="${1:-.}"
FOUND_ISSUES=0

log_critical() { echo -e "${RED}[CRITICAL]${NC} $*"; }
log_warn()     { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_info()     { echo -e "${CYAN}[INFO]${NC} $*"; }
log_ok()       { echo -e "${GREEN}[OK]${NC} $*"; }

echo -e "${BOLD}=== Axios Supply Chain Attack Scanner ===${NC}"
echo -e "Compromised versions: ${RED}axios@1.14.1${NC}, ${RED}axios@0.30.4${NC}"
echo -e "Malicious dependency: ${RED}plain-crypto-js@4.2.1${NC}"
echo -e "Scanning: ${BOLD}$(cd "$SCAN_DIR" && pwd)${NC}"
echo ""

# ---------------------------------------------------------------------------
# 1. Check lockfiles for compromised axios versions
# ---------------------------------------------------------------------------
check_lockfile() {
    local lockfile="$1"
    local project_dir
    project_dir="$(dirname "$lockfile")"

    # Check for compromised axios versions
    if grep -qE '"axios".*"(1\.14\.1|0\.30\.4)"' "$lockfile" 2>/dev/null || \
       grep -qE 'axios@(1\.14\.1|0\.30\.4)' "$lockfile" 2>/dev/null || \
       grep -qE '"version":\s*"(1\.14\.1|0\.30\.4)"' "$lockfile" 2>/dev/null; then
        log_critical "Compromised axios version found in: $lockfile"
        grep -nE '(1\.14\.1|0\.30\.4)' "$lockfile" 2>/dev/null | head -5 | while read -r line; do
            echo -e "  ${RED}→ $line${NC}"
        done
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
    fi

    # Check for malicious dependency plain-crypto-js
    if grep -q 'plain-crypto-js' "$lockfile" 2>/dev/null; then
        log_critical "Malicious dependency 'plain-crypto-js' found in: $lockfile"
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
    fi

    # Check for other known malicious packages from this campaign
    if grep -qE '@shadanai/openclaw|@qqbrowser/openclaw-qbot' "$lockfile" 2>/dev/null; then
        log_critical "Related malicious package found in: $lockfile"
        grep -nE '@shadanai/openclaw|@qqbrowser/openclaw-qbot' "$lockfile" 2>/dev/null | head -5 | while read -r line; do
            echo -e "  ${RED}→ $line${NC}"
        done
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
    fi
}

# ---------------------------------------------------------------------------
# 2. Check installed node_modules for compromised axios
# ---------------------------------------------------------------------------
check_node_modules() {
    local pkg_json="$1"
    local dir
    dir="$(dirname "$pkg_json")"

    if [[ -f "$pkg_json" ]]; then
        local version
        version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" 2>/dev/null | head -1 | grep -o '"[^"]*"$' | tr -d '"')
        local name
        name=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" 2>/dev/null | head -1 | grep -o '"[^"]*"$' | tr -d '"')

        if [[ "$name" == "axios" && ("$version" == "1.14.1" || "$version" == "0.30.4") ]]; then
            log_critical "Compromised axios@${version} INSTALLED at: $dir"
            FOUND_ISSUES=$((FOUND_ISSUES + 1))
        fi

        if [[ "$name" == "plain-crypto-js" ]]; then
            log_critical "Malicious package 'plain-crypto-js' INSTALLED at: $dir"
            FOUND_ISSUES=$((FOUND_ISSUES + 1))
        fi
    fi
}

# ---------------------------------------------------------------------------
# 3. Check package.json for vulnerable version ranges
# ---------------------------------------------------------------------------
check_package_json() {
    local pkg="$1"

    # Look for axios dependency with a caret/tilde range that could resolve to compromised version
    if grep -qE '"axios"' "$pkg" 2>/dev/null; then
        local spec
        spec=$(grep -oE '"axios"\s*:\s*"[^"]*"' "$pkg" 2>/dev/null | head -1)
        if echo "$spec" | grep -qE '(\^1\.|~1\.14\.|1\.14\.1|0\.30\.4|\^0\.30\.)'; then
            log_warn "Potentially vulnerable axios range in: $pkg"
            echo -e "  ${YELLOW}→ $spec${NC}"
            echo -e "  ${YELLOW}  Check your lockfile to see which version actually resolved${NC}"
            FOUND_ISSUES=$((FOUND_ISSUES + 1))
        fi
    fi
}

# ---------------------------------------------------------------------------
# 4. Check for IOC artifacts on the local machine
# ---------------------------------------------------------------------------
check_local_iocs() {
    echo -e "${BOLD}--- Checking for IOC artifacts on this machine ---${NC}"

    local ioc_files=()
    # macOS
    ioc_files+=("/Library/Caches/com.apple.act.mond")
    # Linux
    ioc_files+=("/tmp/ld.py")

    # Windows-style paths (in case running under WSL/Git Bash)
    if [[ -n "${PROGRAMDATA:-}" ]]; then
        ioc_files+=("${PROGRAMDATA}/wt.exe")
    fi
    if [[ -n "${TEMP:-}" ]]; then
        ioc_files+=("${TEMP}/6202033.vbs" "${TEMP}/6202033.ps1")
    fi

    for f in "${ioc_files[@]}"; do
        if [[ -e "$f" ]]; then
            log_critical "IOC file found: $f — THIS MACHINE MAY BE COMPROMISED"
            FOUND_ISSUES=$((FOUND_ISSUES + 1))
        fi
    done

    # Check for C2 connections
    if command -v lsof &>/dev/null; then
        if lsof -i @142.11.206.73 2>/dev/null | grep -q .; then
            log_critical "Active connection to C2 IP 142.11.206.73 detected!"
            FOUND_ISSUES=$((FOUND_ISSUES + 1))
        fi
    fi

    log_ok "IOC artifact check complete"
}

# ---------------------------------------------------------------------------
# Run scans
# ---------------------------------------------------------------------------

# Scan lockfiles
echo -e "${BOLD}--- Scanning lockfiles ---${NC}"
lockfile_count=0
while IFS= read -r -d '' lockfile; do
    check_lockfile "$lockfile"
    lockfile_count=$((lockfile_count + 1))
done < <(find "$SCAN_DIR" -maxdepth 5 \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -not -path "*/node_modules/*" -print0 2>/dev/null)
log_info "Scanned $lockfile_count lockfile(s)"
echo ""

# Scan installed node_modules for axios
echo -e "${BOLD}--- Scanning node_modules for compromised installs ---${NC}"
nm_count=0
while IFS= read -r -d '' pkg; do
    check_node_modules "$pkg"
    nm_count=$((nm_count + 1))
done < <(find "$SCAN_DIR" -maxdepth 6 -path "*/node_modules/axios/package.json" -print0 2>/dev/null)
# Also check for plain-crypto-js in node_modules
while IFS= read -r -d '' pkg; do
    check_node_modules "$pkg"
done < <(find "$SCAN_DIR" -maxdepth 6 -path "*/node_modules/plain-crypto-js/package.json" -print0 2>/dev/null)
log_info "Checked $nm_count installed axios package(s)"
echo ""

# Scan package.json files for vulnerable ranges
echo -e "${BOLD}--- Scanning package.json for vulnerable ranges ---${NC}"
pkg_count=0
while IFS= read -r -d '' pkg; do
    check_package_json "$pkg"
    pkg_count=$((pkg_count + 1))
done < <(find "$SCAN_DIR" -maxdepth 4 -name "package.json" -not -path "*/node_modules/*" -print0 2>/dev/null)
log_info "Scanned $pkg_count package.json file(s)"
echo ""

# Check local IOCs
check_local_iocs
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo -e "${BOLD}=== Scan Complete ===${NC}"
if [[ $FOUND_ISSUES -gt 0 ]]; then
    echo -e "${RED}Found $FOUND_ISSUES issue(s)!${NC}"
    echo ""

    # Determine severity: IOC artifacts mean active compromise, lockfile hits mean exposure
    IOC_HIT=false
    for f in "/Library/Caches/com.apple.act.mond" "/tmp/ld.py"; do
        [[ -e "$f" ]] && IOC_HIT=true
    done
    if [[ -n "${PROGRAMDATA:-}" && -e "${PROGRAMDATA}/wt.exe" ]]; then IOC_HIT=true; fi
    if [[ -n "${TEMP:-}" ]] && [[ -e "${TEMP}/6202033.vbs" || -e "${TEMP}/6202033.ps1" ]]; then IOC_HIT=true; fi

    if $IOC_HIT; then
        echo -e "${RED}${BOLD}!!!  RAT ARTIFACTS DETECTED — THIS MACHINE IS LIKELY COMPROMISED  !!!${NC}"
        echo ""
        echo -e "${BOLD}IMMEDIATE ACTIONS (do these NOW):${NC}"
        echo ""
        echo -e "  ${RED}1. DISCONNECT FROM THE NETWORK${NC}"
        echo "     Disconnect Wi-Fi / unplug ethernet immediately to cut C2 communication."
        echo ""
        echo -e "  ${RED}2. KILL MALICIOUS PROCESSES${NC}"
        echo "     macOS:   sudo rm -f /Library/Caches/com.apple.act.mond"
        echo "              ps aux | grep -E 'com.apple.act.mond|osascript' and kill PIDs"
        echo "     Linux:   rm -f /tmp/ld.py && pkill -f 'ld.py'"
        echo "     Windows: taskkill /F /IM wt.exe & del %PROGRAMDATA%\\wt.exe"
        echo "              del %TEMP%\\6202033.vbs %TEMP%\\6202033.ps1"
        echo ""
        echo -e "  ${RED}3. ROTATE ALL CREDENTIALS — ASSUME EVERYTHING IS STOLEN${NC}"
        echo "     The RAT had full system access. Rotate ALL of the following:"
        echo "     - SSH keys:          ~/.ssh/id_* (regenerate and replace on all services)"
        echo "     - GPG keys:          Revoke and regenerate"
        echo "     - npm/PyPI tokens:   Revoke from npmjs.com/pypi.org settings"
        echo "     - Git credentials:   GitHub/GitLab PATs, app passwords"
        echo "     - Cloud credentials: AWS keys, GCP service accounts, Azure tokens"
        echo "     - .env files:        Every API key, DB password, secret in every project"
        echo "     - Browser sessions:  Log out of all sessions, change passwords"
        echo "     - Password manager:  Change master password if it was unlocked"
        echo ""
        echo -e "  ${RED}4. CHECK FOR PERSISTENCE${NC}"
        echo "     The RAT may have installed persistence mechanisms:"
        echo "     macOS:   Check ~/Library/LaunchAgents/ and /Library/LaunchDaemons/"
        echo "              Check login items: System Settings > General > Login Items"
        echo "     Linux:   Check crontab -l, ~/.bashrc, ~/.profile, systemd user units"
        echo "     Windows: Check Task Scheduler, startup folder, registry Run keys"
        echo ""
        echo -e "  ${RED}5. FORENSIC INVESTIGATION${NC}"
        echo "     - Save system logs before they rotate (Console.app on macOS, journalctl on Linux)"
        echo "     - Check network logs / DNS history for connections to sfrclak[.]com or 142.11.206.73"
        echo "     - Review 'last' and shell history for unauthorized access"
        echo "     - If on a corporate network: notify your security team immediately"
        echo ""
        echo -e "  ${RED}6. CONSIDER A CLEAN OS REINSTALL${NC}"
        echo "     A RAT with full system access could have modified system binaries."
        echo "     The safest recovery is a full wipe and reinstall from known-good media."
        echo ""
    else
        echo -e "${YELLOW}${BOLD}COMPROMISED PACKAGE DETECTED IN PROJECT FILES${NC}"
        echo ""
        echo -e "${BOLD}NEXT STEPS:${NC}"
        echo ""
        echo -e "  ${YELLOW}1. DO NOT RUN 'npm install' IN AFFECTED PROJECTS${NC}"
        echo "     Running install could trigger the postinstall hook and deploy the RAT."
        echo "     If your lockfile pins the compromised version, installing WILL pull it."
        echo ""
        echo -e "  ${YELLOW}2. FIX THE DEPENDENCY${NC}"
        echo "     In each affected package.json, pin axios to a safe version:"
        echo "       \"axios\": \"1.14.0\"    (remove ^ or ~ prefix)"
        echo "     Then delete node_modules and the lockfile, and reinstall:"
        echo "       rm -rf node_modules package-lock.json && npm install"
        echo ""
        echo -e "  ${YELLOW}3. CHECK IF THE COMPROMISED VERSION WAS EVER INSTALLED${NC}"
        echo "     If you or CI ran 'npm install' while the compromised version was live,"
        echo "     the RAT may have already executed and self-deleted. Check for IOC files:"
        echo "       macOS:   ls -la /Library/Caches/com.apple.act.mond"
        echo "       Linux:   ls -la /tmp/ld.py"
        echo "       Windows: dir %PROGRAMDATA%\\wt.exe"
        echo "     Also check network logs for connections to 142.11.206.73 or sfrclak[.]com"
        echo ""
        echo -e "  ${YELLOW}4. IF IT WAS INSTALLED — TREAT AS FULL COMPROMISE${NC}"
        echo "     The RAT self-deletes from node_modules after running, so absence of"
        echo "     IOC files doesn't guarantee safety if the version was ever installed."
        echo "     If in doubt, rotate all credentials (SSH keys, API tokens, .env secrets,"
        echo "     cloud credentials, npm tokens, browser sessions)."
        echo ""
        echo -e "  ${YELLOW}5. AUDIT CI/CD PIPELINES${NC}"
        echo "     - Check if any CI builds ran 'npm install' during the attack window"
        echo "     - Rotate all CI secrets and tokens if they did"
        echo "     - Check for unauthorized npm publishes from your packages"
        echo ""
        echo -e "  ${YELLOW}6. REMOVE MALICIOUS PACKAGES${NC}"
        echo "     Remove these from your dependency tree if present:"
        echo "       npm uninstall plain-crypto-js @shadanai/openclaw @qqbrowser/openclaw-qbot"
        echo ""
        echo -e "  ${YELLOW}7. PREVENT FUTURE ATTACKS${NC}"
        echo "     - Pin exact dependency versions (remove ^ and ~ from package.json)"
        echo "     - Use 'npm install --ignore-scripts' and audit before running postinstall"
        echo "     - Enable npm 2FA and use short-lived OIDC tokens for publishing"
        echo "     - Consider using Socket.dev, npm audit, or Snyk for supply chain monitoring"
        echo ""
    fi
    exit 1
else
    log_ok "No compromised axios versions or IOC artifacts found."
    echo ""
    echo -e "${BOLD}Stay safe:${NC}"
    echo "  - Pin exact dependency versions (avoid ^ and ~ ranges)"
    echo "  - Run 'npm audit' regularly"
    echo "  - Use 'npm install --ignore-scripts' and review postinstall hooks"
    echo "  - Consider tools like Socket.dev for supply chain monitoring"
    exit 0
fi
