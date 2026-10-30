
check_kernel() {
    line
    printf "${BOLD}[AUTO] KERNEL INFORMATION${NC}\n"
    line

    RUNNING_KERNEL=$(uname -r)

    printf " Kernel aktif : %s\n" "$RUNNING_KERNEL"
    echo

    CURRENT_PACKAGE="linux-image-${RUNNING_KERNEL}"

    if dpkg-query -W -f='${Status}' \
        "$CURRENT_PACKAGE" 2>/dev/null |
        grep -q "install ok installed"; then

        success "Kernel aktif terdaftar dalam paket Ubuntu."
    else
        warning "Kernel aktif tidak ditemukan sebagai paket linux-image biasa."
        warning "Kemungkinan menggunakan custom kernel."
    fi

    echo
}
