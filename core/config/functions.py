from core.config.librareis import *
from core.assets.alerts import *
from core.config.config import BACKUPDIR
from core.config.config import VERSION

def check_root():
    if getuid() != 0:
        ERROR("This script must be run as root")
        exit(1)
# execute command
def exec_command(cmd):
    system(cmd)
# clear
def clear():
    system("clear")
# terminal
def get_process(cmd):
    with tempfile.TemporaryFile() as tempf:
        proc = subprocess.Popen(cmd, stdout=tempf)
        proc.wait()
        tempf.seek(0)
        result = tempf.read().decode("utf-8").strip()
        return result

def is_started():
    if path.isfile(f"{BACKUPDIR}/started"):
        return 1
    else:
        return 0
def anongt_isactive():
    if is_started() == 1:
        return f"{red('AnonGT:')} {green('started')}"
    else:
        return f"{red('AnonGT:')}  {yellow('stopped')}"

#serviço tor
def tor_isacttive():
    cmd = ["systemctl", "is-active", "tor"]
    TORSTATUS = get_process(cmd)
    if TORSTATUS == "active":
        return f"{red('TOR:')} {green(TORSTATUS)}"
    else:
        return f"{red('TOR:')} {yellow(TORSTATUS)}"
#verif. atualização
def check_update():
    MSG(f"Version: {VERSION}")
    MSG("Checking Update...")

    try:
        result = get(
            "https://raw.githubusercontent.com/gt0day/AnonGT/main/version.txt",
            verify=True,
        ).content
        v = result.decode("utf-8").strip("\n")

        if v != VERSION:
            WARN("Please Update AnonGT!")
            INFO(f"VERSION: {v}")
            INFO("Go to https://github.com/gt0day/AnonGT")
        else:
            MSG("AnonGT Latest Version.")

    except Exception as e:
        ERROR(e)
    except:
        ERROR("Please Check Your Internet Connection")


# func converta
def listToString(s):
    str1 = " "

    # return string
    return str1.join(s)
