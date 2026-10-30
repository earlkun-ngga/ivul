
#!/usr/bin/env bash
# ============================================================
# INSPEKTORAT VULN LINUX (IVUL)
# Version : 1.1
# Target  : CVE-2026-98432
# Support : Ubuntu 20.04 / 22.04 / 24.04 / 26.04 LTS
# Mode    : Auto Audit + Manual MPTCP Disable
# ============================================================

set -u
export LC_ALL=C

CVE="CVE-2026-98432"
VERSION="1.1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

line() {
    printf '%s\n' "============================================================"
}

info() {
    printf "${CYAN}[INFO]${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

header() {
    clear 2>/dev/null || true

    line
    printf "${BOLD}          INSPEKTORAT VULN LINUX (IVUL)${NC}\n"
    printf "                  Version %s\n" "$VERSION"
    line
    printf " Target : %s\n" "$CVE"
    printf " Mode   : Ubuntu Kernel Security Audit\n"
    printf " Action : Manual MPTCP Mitigation\n"
    line
    echo
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "Informasi OS tidak ditemukan."
        exit 1
    fi

    # shellcheck disable=SC1091
    source /etc/os-release

    if [[ "${ID:-}" != "ubuntu" ]]; then
        error "Aplikasi hanya mendukung Ubuntu."
        exit 1
    fi

    case "${VERSION_ID:-}" in
        20.04|22.04|24.04|26.04)
            success "OS Supported"
            ;;
        *)
            error "Versi Ubuntu tidak didukung: ${VERSION_ID:-unknown}"
            exit 1
            ;;
    esac

    printf " OS           : %s\n" "${PRETTY_NAME:-Ubuntu}"
    printf " Architecture : %s\n" "$(uname -m)"
    printf " Hostname     : %s\n" "$(hostname)"
    echo
}

check_kernel() {
    line
    printf "${BOLD}[AUTO] KERNEL INFORMATION${NC}\n"
    line

    RUNNING_KERNEL=$(uname -r)

    printf " Kernel aktif : %s\n" "$RUNNING_KERNEL"
    echo
    printf " Kernel terpasang:\n"

    dpkg-query -W -f='${binary:Package} ${Version}\n' \
        'linux-image-[0-9]*' 2>/dev/null |
        while IFS= read -r kernel; do
            [[ -n "$kernel" ]] && printf "  - %s\n" "$kernel"
        done

    echo

    CURRENT_PACKAGE="linux-image-${RUNNING_KERNEL}"

    if dpkg-query -W -f='${Status}' \
        "$CURRENT_PACKAGE" 2>/dev/null |
        grep -q "install ok installed"; then

        success "Kernel aktif terdaftar dalam paket Ubuntu."
    else
        warning "Kernel aktif tidak ditemukan sebagai paket linux-image biasa."
        warning "Bisa menggunakan custom kernel."
    fi

    echo
}

check_cve() {
    line
    printf "${BOLD}[AUTO] CVE SECURITY CHECK${NC}\n"
    line

    printf " CVE    : %s\n" "$CVE"
    printf " Kernel : %s\n" "$(uname -r)"
    echo

    # Jangan menilai status CVE hanya dari uname -r.
    # Ubuntu dapat menerapkan security backport.
    # Gunakan Ubuntu Pro Client dalam mode dry-run.

    CVE_STATUS="UNKNOWN"

    if command -v pro >/dev/null 2>&1; then

        info "Memeriksa advisory menggunakan Ubuntu Pro Client..."

        if command -v timeout >/dev/null 2>&1; then
            RESULT=$(timeout 30s pro fix --dry-run "$CVE" \
                </dev/null 2>&1) || true
        else
            RESULT=$(pro fix --dry-run "$CVE" \
                </dev/null 2>&1) || true
        fi

        if echo "$RESULT" | grep -Eiq \
            "${CVE} is resolved"; then
            CVE_STATUS="SAFE"

        elif echo "$RESULT" | grep -Eiq \
            "${CVE} is not resolved"; then
            CVE_STATUS="VULNERABLE"

        else
            CVE_STATUS="UNKNOWN"
        fi

    else
        warning "Ubuntu Pro Client (pro) tidak tersedia."
    fi

    case "$CVE_STATUS" in

        SAFE)
            printf "${GREEN}"
            printf " STATUS : FIXED / NOT AFFECTED\n"
            printf " RESULT : CVE resolved menurut Ubuntu Pro Client\n"
            printf "${NC}"
            ;;

        VULNERABLE)
            printf "${RED}"
            printf " STATUS : VULNERABLE / NOT RESOLVED\n"
            printf " RESULT : CVE belum terselesaikan\n"
            printf "${NC}"
            ;;

        *)
            printf "${YELLOW}"
            printf " STATUS : UNKNOWN / UNVERIFIED\n"
            printf " RESULT : Status patch belum dapat dipastikan\n"
            printf "${NC}"
            ;;
    esac

    echo
    printf " Advisory:\n"
    printf " https://ubuntu.com/security/%s\n" "$CVE"
    echo

    warning "Nomor kernel saja tidak cukup untuk menentukan status patch."
    warning "Disable MPTCP bukan perbaikan menyeluruh CVE."
    echo
}

check_mptcp() {
    line
    printf "${BOLD}[AUTO] MPTCP CONFIGURATION${NC}\n"
    line

    MPTCP_FILE="/proc/sys/net/mptcp/enabled"

    if [[ ! -f "$MPTCP_FILE" ]]; then
        warning "MPTCP tidak tersedia pada kernel ini."
        MPTCP_STATE="UNAVAILABLE"
    else
        MPTCP_STATE=$(cat "$MPTCP_FILE")

        case "$MPTCP_STATE" in
            1)
                printf "${YELLOW} MPTCP : ENABLED (1)${NC}\n"
                ;;
            0)
                printf "${GREEN} MPTCP : DISABLED (0)${NC}\n"
                ;;
            *)
                warning "MPTCP status tidak diketahui."
                ;;
        esac
    fi

    echo

    MIGRATE=$(sysctl -n net.ipv4.tcp_migrate_req 2>/dev/null || true)

    printf " TCP Migrate Request : %s\n" "${MIGRATE:-N/A}"
    echo
}

disable_mptcp() {
    line
    printf "${BOLD}          ANTISIPASI URGENT${NC}\n"
    line

    echo " Action : Disable MPTCP sementara"
    echo " Scope  : Runtime kernel / current network namespace"
    echo " Reboot : Tidak diperlukan"
    echo
    warning "Tidak memperbaiki seluruh jalur CVE-2026-98432."
    warning "Aplikasi khusus MPTCP dapat terpengaruh."
    echo

    if [[ "$MPTCP_STATE" == "UNAVAILABLE" ]]; then
        warning "MPTCP tidak tersedia. Tidak ada perubahan."
        exit 0
    fi

    if [[ "$MPTCP_STATE" == "0" ]]; then
        success "MPTCP sudah dalam kondisi DISABLED."
        exit 0
    fi

    read -r -p "Antisipasi urgent (disable MPTCP) Y/N [N]: " ANSWER

    case "$ANSWER" in
        Y|y)
            echo

            if [[ $EUID -ne 0 ]]; then
                error "Perlu akses root untuk mengubah MPTCP."
                error "Jalankan: sudo ./Ivul.sh"
                exit 1
            fi

            info "Menonaktifkan MPTCP sementara..."

            if sysctl -w net.mptcp.enabled=0; then
                echo

                VERIFY=$(sysctl -n net.mptcp.enabled 2>/dev/null || true)

                if [[ "$VERIFY" == "0" ]]; then
                    success "MPTCP berhasil dinonaktifkan."
                    printf "${GREEN} STATUS : DISABLED (0)${NC}\n"
                    echo
                    info "Tidak ada restart service atau reboot."
                    info "Perubahan tidak dibuat permanen."
                    echo
                    printf " Rollback:\n"
                    printf " sudo sysctl -w net.mptcp.enabled=1\n"
                else
                    error "Verifikasi MPTCP gagal."
                    exit 1
                fi
            else
                error "Gagal menonaktifkan MPTCP."
                exit 1
            fi
            ;;

        N|n|"")
            echo
            info "Action dibatalkan."
            info "Tidak ada konfigurasi yang diubah."
            ;;

        *)
            echo
            warning "Input tidak valid. Default N."
            info "Aplikasi ditutup tanpa perubahan."
            ;;
    esac
}

main() {
    header
    check_os
    check_kernel
    check_cve
    check_mptcp
    disable_mptcp

    echo
    line
    printf " IVUL v%s - Finished\n" "$VERSION"
    line
}

main
