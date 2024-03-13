from core.config.librareis import *
from core.config.config import (
    BACKUPDIR,
    CURRTENTDIR,
    TORRC,
    TOR_UID,
    TOR_PORT,
    TOR_DNS,
    TOR_EXCLUDE,
)
from core.assets.alerts import *
from core.assets.banner import logo, banner
from core.assets.about import about
from core.config.functions import (
    exec_command,
    get_process,
    clear,
    is_started,
    check_update,
)

def check_backup_dir():
    if path.exists(BACKUPDIR) != True:
        INFO(f"Creating {BACKUPDIR}")
        exec_command(f"mkdir {BACKUPDIR}")

def start_service(s):
    cmd = ["systemctl", "is-active", s]
    service = get_process(cmd)
    if service != "active":
        WARN(s + " is not active")
        exec_command(f"systemctl start {s}")
        MSG(f"started {s} service")
    else:
        WARN(f"{s} is active")
        exec_command(f"systemctl reload {s}")
        MSG(f"reloaded {s} service")


# stop tor service
def stop_service(s):
    cmd = ["systemctl", "is-active", s]
    service = get_process(cmd)
    if service == "active":
        WARN(s + " is active")
        exec_command(f"systemctl stop {s}")
        MSG(f"stopped {s} service")
    else:
        WARN(f"{s} is not active")


def start_browser_anonymization():
    MSG("firefox browser anonymization started")
    if path.isdir("/etc/firefox-esr") == True or path.isdir("/etc/firefox") == True:
        exec_command(
            f"cp {CURRTENTDIR}/core/sources/anongt.js /etc/firefox-esr > /dev/null"
        )
        exec_command(
            f"cp {CURRTENTDIR}/core/sources/anongt.js /etc/firefox > /dev/null"
        )
    else:
        WARN(
            "Browser anonymization only supports firefox and firefox not found on your system"
        )


def stop_browser_anonymization():
    exec_command("rm -fr /etc/firefox-esr/anongt.js > /dev/null")
    exec_command("rm -fr /etc/firefox/anongt.js > /dev/null")
    MSG("firefox browser anonymization stopped")

def safekill():
    WARN("killing dangerous processes & applications")
    exec_command("service network-manager force-reload > /dev/null 2>&1")
    exec_command(
        "killall -q dnsmasq nscd chrome dropbox skype icedove thunderbird firefox firefox-esr chromium xchat hexchat transmission steam firejail pidgin /usr/lib/firefox-esr/firefox-esr"
    )

    exec_command(
        "bleachbit -c bash.history system.cache system.clipboard system.custom system.recent_documents system.rotated_logs system.tmp system.trash adobe_reader.cache chromium.cache chromium.session chromium.history chromium.form_history elinks.history emesene.cache epiphany.cache firefox.cache firefox.crash_reports firefox.url_history firefox.forms flash.cache flash.cookies google_chrome.cache google_chrome.history google_chrome.form_history google_chrome.search_engines google_chrome.session google_earth.temporary_files links2.history opera.cache opera.form_history opera.history > /dev/null 2>&1"
    )

    MSG("dangerous processes & applications killed")

def flush_iptables():
    exec_command("/usr/sbin/iptables -F")
    exec_command("/usr/sbin/iptables -t nat -F")

def wipe():
    exec_command("swapoff -a")
    exec_command("swapon -a")
    exec_command("echo 1024 > /proc/sys/vm/min_free_kbytes")
    exec_command("echo 3 > /proc/sys/vm/drop_caches")
    exec_command("echo 1 > /proc/sys/vm/oom_kill_allocating_task")
    exec_command("echo 1 > /proc/sys/vm/overcommit_memory")
    exec_command("echo 0 > /proc/sys/vm/oom_dump_tasks")

    exec_command("dhclient -r > /dev/null 2>&1")
    exec_command("rm -f /var/lib/dhcp/dhclient* > /dev/null 2>&1")

    log_list = (
        "/var/log/messages",
        "/var/log/auth.log",
        "/var/log/kern.log",
        "/var/log/cron.log",
        "/var/log/maillog",
        "/var/log/boot.log",
        "/var/log/mysqld.log",
        "/var/log/secure",
        "/var/log/utmp",
        "/var/log/wtmp",
        "/var/log/yum.log",
        "/var/log/system.log",
        "/var/log/DiagnosticMessages",
        "~/.zsh_history",
        "~/.bash_history",
    )
    for log in log_list:
        if path.isfile(log) == True or path.isdir(log) == True:
            exec_command(f"shred -vfzu {log} > /dev/null 2>&1")

    MSG("cleaned config & logs")


# get ip
def get_info():
    try:
        get_info = get(
            "http://ip-api.com/json/?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
            verify=True,
        )

        ip = get_info.json()["query"]
        status = get_info.json()["status"]
        continent = get_info.json()["continent"]
        continentCode = get_info.json()["continentCode"]
        country = get_info.json()["country"]
        countryCode = get_info.json()["countryCode"]
        region = get_info.json()["region"]
        regionName = get_info.json()["regionName"]
        city = get_info.json()["city"]
        district = get_info.json()["district"]
        zip = get_info.json()["zip"]
        lat = get_info.json()["lat"]
        lon = get_info.json()["lon"]
        timezone = get_info.json()["timezone"]
        offset = get_info.json()["offset"]
        currency = get_info.json()["currency"]
        isp = get_info.json()["isp"]
        org = get_info.json()["org"]
        AS = get_info.json()["as"]
        asname = get_info.json()["asname"]
        reverse = get_info.json()["reverse"]
        mobile = get_info.json()["mobile"]
        proxy = get_info.json()["proxy"]
        hosting = get_info.json()["hosting"]

        info = f"""
    #IP: {ip}
    Status: {status}
    Continent: {continent}
    ContinentCode: {continentCode}
    Country: {country}
    CountryCode: {countryCode}
    Region: {region}
    RegionName: {regionName}
    City: {city}
    District: {district}
    ZIP: {zip}
    LAT: {lat}
    LON: {lon}
    TimeZone: {timezone}
    Offset: {offset}
    Currency: {currency}
    ISP: {isp}
    ORG: {org}
    AS: {AS}
    ASName: {asname}
    Reverse: {reverse}
    Mobile: {mobile}
    Proxy: {proxy}
    Hosting: {hosting}
    """
        print(green(info))
    except:
        ERROR("Remote #IP: unknown")

def backup_torrc():
    exec_command(f"mv {TORRC} {BACKUPDIR}/torrc.bak")
    exec_command(f"chmod 644 {BACKUPDIR}/torrc.bak")
    MSG("backed up tor config")

def backup_resolv_conf():
    exec_command(f"mv /etc/resolv.conf {BACKUPDIR}/resolv.conf.bak")
    exec_command(f"chmod 644 {BACKUPDIR}/resolv.conf.bak")
    MSG("backed up nameservers")
def backup_iptables():
    exec_command(f"iptables-save > {BACKUPDIR}/iptables.rules.bak")
    exec_command(f"chmod 644 {BACKUPDIR}/iptables.rules.bak")
    MSG("backed up iptables rules")

def backup_sysctl():
    exec_command(f"sysctl -a > {BACKUPDIR}/sysctl.conf.bak")
    exec_command(f"chmod 644 {BACKUPDIR}/sysctl.conf.bak")
def restore_torrc():
    if path.isfile(BACKUPDIR + "/torrc.bak"):
        exec_command("rm -f /etc/tor/torrc")
        exec_command(f"mv {BACKUPDIR}/torrc.bak /etc/tor/torrc")
        MSG("restored tor config")

def restore_resolv_conf():
    if path.isfile(BACKUPDIR + "/resolv.conf.bak"):
        exec_command(f"rm -f {BACKUPDIR}/resolv.conf")
        exec_command(f"mv {BACKUPDIR}/resolv.conf.bak /etc/resolv.conf")
        MSG("restored nameservers")

def restore_iptables():
    if path.isfile(BACKUPDIR + "/iptables.rules.bak"):
        exec_command(f"iptables-restore < {BACKUPDIR}/iptables.rules.bak")
        exec_command(f"rm -f {BACKUPDIR}/iptables.rules.bak")
        MSG("restored iptables rules")

def restore_sysctl():
    if path.isfile(BACKUPDIR + "/sysctl.conf.bak"):
        exec_command(f"sysctl -p {BACKUPDIR}/sysctl.conf.bak > /dev/null 2>&1")
        exec_command(f"rm -f {BACKUPDIR}/sysctl.conf.bak")
        MSG("restored sysctl rules")
def gen_resolv_conf():
    nameservers = """ 
# generated by anongt
nameserver 127.0.0.1
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 208.67.222.222
nameserver 208.67.220.220
nameserver 8.8.8.8
nameserver 8.8.4.4
"""
    exec_command(f'cat > "/etc/resolv.conf" <<EOF {nameservers}')
    exec_command("chmod 644 /etc/resolv.conf")
    MSG("configured nameservers")

# config
def gen_torrc():
    torconfig = f""" 
# generated by anongt
User {TOR_UID}
DataDirectory /var/lib/tor
VirtualAddrNetwork 10.192.0.0/10
AutomapHostsOnResolve 1
AutomapHostsSuffixes .exit,.onion
#define tor ports and explicitly declare some security flags
TransPort 127.0.0.1:{TOR_PORT} IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
SocksPort 127.0.0.1:9050 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
ControlPort 9051
HashedControlPassword 16:5F620905DFFAC449600612AEE018C59D62198F8DFBD2B4C746E05376D7
#use tor to resolve domain names
DNSPort 127.0.0.1:{TOR_DNS}
    exec_command(f'cat > "{TORRC}" <<EOF {torconfig}')
    exec_command(f"chmod 644 {TORRC}")
    MSG("configured tor")

def apply_iptables_rules():
    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -m owner --uid-owner {TOR_UID} -j RETURN"
    )

    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports {TOR_DNS}"
    )
    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports {TOR_DNS}"
    )
    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m owner --uid-owner {TOR_UID} -m udp --dport 53 -j REDIRECT --to-ports {TOR_DNS}"
    )

    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports {TOR_PORT}"
    )
    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -p udp -d 10.192.0.0/10 -j REDIRECT --to-ports {TOR_PORT}"
    )

    cmd = f""" 
    for NET in {TOR_EXCLUDE} 127.0.0.0/9 127.128.0.0/10; do
        /usr/sbin/iptables -t nat -A OUTPUT -d "$NET" -j RETURN
        /usr/sbin/iptables -A OUTPUT -d "$NET" -j ACCEPT
    done
    """
    exec_command(cmd)

    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports {TOR_PORT}"
    )
    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports {TOR_PORT}"
    )
    exec_command(
        f"/usr/sbin/iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports {TOR_PORT}"
    )

    exec_command(
        "/usr/sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
    )

    exec_command(
        f"/usr/sbin/iptables -A OUTPUT -m owner --uid-owner {TOR_UID} -j ACCEPT"
    )
    exec_command("/usr/sbin/iptables -A OUTPUT -j REJECT")

    exec_command("/usr/sbin/iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT")
    exec_command("/usr/sbin/iptables -A INPUT -i lo -j ACCEPT")

    exec_command("/usr/sbin/iptables -A INPUT -j DROP")

    exec_command("/usr/sbin/iptables -A FORWARD -j DROP")

    exec_command("/usr/sbin/iptables -A OUTPUT -m state --state INVALID -j DROP")
    exec_command("/usr/sbin/iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT")

    exec_command(
        f"iptables -A OUTPUT -m owner --uid-owner {TOR_UID} -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT"
    )
    exec_command("/usr/sbin/iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT")
    exec_command(
        f'/usr/sbin/iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport "{TOR_PORT}" --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT'
    )

    MSG("applied iptables rules")

def apply_sysctl_rules():
    exec_command('/sbin/sysctl -w net.ipv4.tcp_ecn=0 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.tcp_max_orphans=16384 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.tcp_orphan_retries=0 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.tcp_no_metrics_save=1 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.tcp_moderate_rcvbuf=1 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.unix.max_dgram_qlen=50 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.neigh.default.gc_thresh3=2048 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.neigh.default.gc_thresh2=1024 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.neigh.default.gc_thresh1=32 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.neigh.default.gc_interval=30 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.neigh.default.proxy_qlen=96 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.neigh.default.unres_qlen=6 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.tcp_ecn=1 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.tcp_reordering=3 > "/dev/null"')


    exec_command('/sbin/sysctl -w net.ipv4.tcp_retries2=15 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.tcp_retries1=3 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.tcp_slow_start_after_idle=0 > "/dev/null"')

    #(kernel > 3.7)
    exec_command('/sbin/sysctl -w net.ipv4.tcp_fastopen=3 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.route.flush=1 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv6.route.flush=1 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.tcp_syncookies=1 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.tcp_rfc1337=1 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.conf.default.rp_filter=1 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.conf.all.rp_filter=1 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.conf.default.log_martians=1 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.conf.all.log_martians=1 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0 > "/dev/null"')
    exec_command(
        '/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0 > "/dev/null"'
    )
    exec_command('/sbin/sysctl -w net.ipv4.conf.all.secure_redirects=0 > "/dev/null"')
    exec_command(
        '/sbin/sysctl -w net.ipv4.conf.default.secure_redirects=0 > "/dev/null"'
    )
    exec_command('/sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0 > "/dev/null"')
    exec_command(
        '/sbin/sysctl -w net.ipv6.conf.default.accept_redirects=0 > "/dev/null"'
    )
    exec_command('/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0 > "/dev/null"')

    exec_command('/sbin/sysctl -w net.ipv4.icmp_echo_ignore_all=1 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv6.conf.all.disable_ipv6=1 > "/dev/null"')
    exec_command('/sbin/sysctl -w net.ipv6.conf.default.disable_ipv6=1 > "/dev/null"')

    MSG("applied sysctl rules")
class Anonymous:
    def Start():
        clear()
        print(red(logo))
        if is_started() == 1:
            ERROR("Anonymous Mode is already started")

        else:
            MSG("Start Anonymous Mode")

            cmd = input(
                f"{yellow('Do you want kill dangerous applications? ')} "
            ).lower()
            if cmd == "y" or cmd == "":
                safekill()
            check_backup_dir()

            backup_torrc()
            backup_iptables()

            backup_sysctl()

            flush_iptables()

            gen_torrc()
          
            gen_resolv_conf()
            start_service("tor")
            apply_iptables_rules()

            apply_sysctl_rules()

            start_browser_anonymization()

            wipe()
            exec_command(
                "xdg-open 'https://check.torproject.org/?lang=en' > /dev/null 2>&1"
            )

            exec_command(f"touch {BACKUPDIR}/started")
            MSG("Anonymous Mode Started")

    def Stop():
        clear()
        print(red(logo))
        if is_started() == 0:
            ERROR("Anonymous Mode is already stopped")

        else:
            MSG("Stop Anonymous Mode")

            cmd = input(
                f"{yellow('Do you want kill dangerous applications? ')} "
            ).lower()
            if cmd == "y" or cmd == "":
        
                safekill()

            check_backup_dir()

            restore_sysctl()

            exec_command(
                "/sbin/sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null 2>&1"
            )
            exec_command(
                "/sbin/sysctl -w net.ipv6.conf.default.disable_ipv6=0 > /dev/null 2>&1"
            )
            flush_iptables()
            restore_iptables()
            stop_service("tor")
            restore_torrc()
            restore_resolv_conf()

            stop_browser_anonymization()

 
            wipe()

            exec_command("killall tor > /dev/null 2>&1")

            exec_command(f"rm -f {BACKUPDIR}/started")
            MSG("Anonymous Mode Stoped")

    def Status():
        if is_started() == 1:
            exec_command(
                "xterm -geometry 140x40 -e nyx -c /usr/share/AnonGT/core/assets/nyx.txt &"
            )
            clear()
            banner()
        else:
            clear()
            print(red(logo))
            ERROR("AnonGT is stopped")

    def MyInfo():
        clear()
        print(red(logo))

        get_info()

    def Change_ID():
        clear()
        print(red(logo))

        # check if stopped
        if is_started() == 0:
            ERROR("Anonymous Mode is already stopped")

        else:
            WARN("changing tor identity")
            stop_service("tor")
            sleep(1)
            start_service("tor")
            MSG("tor identity changed")

    def Change_Mac():
        clear()
        print(red(logo))

        WARN("Changing Mac Addresses")
        IFACES = netifaces.interfaces()
        for IFACE in IFACES:
            if IFACE != "lo":
                exec_command(f'ip link set {IFACE} down > "/dev/null"')
                exec_command(f'macchanger -r {IFACE} > "/dev/null"')
                exec_command(f'ip link set {IFACE} up > "/dev/null"')
        MSG("changed mac addresses")

    def Reverte_Mac():
        clear()
        print(red(logo))

        WARN("Reverting Mac Addresses")
        IFACES = netifaces.interfaces()
        for IFACE in IFACES:
            if IFACE != "lo":
                exec_command(f'ip link set {IFACE} down > "/dev/null"')
                exec_command(f'macchanger -p {IFACE} > "/dev/null"')
                exec_command(f'ip link set {IFACE} up > "/dev/null"')

        MSG("reverted mac addresses")

    def Wipe():
        clear()
        print(red(logo))

        wipe()

    def CheckUpdate():
        clear()
        print(red(logo))

        check_update()

    def About():
        clear()
        print(red(logo))

        about()
