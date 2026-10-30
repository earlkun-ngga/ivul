Inspektorat Vuln Linux (Ubuntu) - Antisipasi Cepat CVE-2026-98432

30/10/2026 - 19:49 GM+7 di https://ubuntu.com/security/CVE-2026-98432 Masih belum ada update untuk patching fix CVE tersebut untuk Ubuntu 20-26,
maka dari itu, bisa menggunakan tools IVUL ini untuk antisipasi sementara dan cepat, fungsi nya untuk mengecek kerentanan CVE-2026-98432,
dan melakukan Disable kernel MPTCP yang menjadi fokus celah pada CVE ini.

cd ivul
//1. Set Permission
chmod +x ivul.sh
bash -n ivul.sh

//2. Running
sudo ./ivul.sh


~Earl-Angga