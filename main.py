import sys
sys.dont_write_bytecode = True
import subprocess
from loading import clear_screen, loading_state
import readline
import os
import difflib
import shutil
import time
import zipfile
import io
from INTERFACEPLUGS.blackout.blackout import BlackoutESP32
import platform

def get_pip_install_args(packages):
    """
    Returns the correct pip install argument list, using --break-system-packages only if supported and on Linux.
    """
    python_bin = sys.executable
    system_name = platform.system().lower()
    use_break = False
    if system_name == 'linux':
        try:
            out = subprocess.check_output([python_bin, '-m', 'pip', 'help', 'install'], text=True)
            if '--break-system-packages' in out:
                use_break = True
        except Exception:
            pass
    if use_break:
        return ['install', '--break-system-packages'] + packages
    else:
        return ['install'] + packages

VERSION = "0.1.0"
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[38;2;204;103;102m"
PINK = "\033[38;2;227;148;220m"
YELLOW = "\033[93m"
GREEN = "\033[38;2;180;189;104m"
BLUE = "\033[34m"
DAEMON_ASCII_ART = """
                        *
                     *
          (\___/)     (
          \ (- -)     )\ *
          c\   >'    ( #
            )-_/      '
     _______| |__    ,|//
    # ___ `  ~   )  ( /
    \,|  | . ' .) \ /#
   _( /  )   , / \ / |
    //  ;;,,;,;   \,/
     _,#;,;;,;,;
    /,i;;;,,;#,;
   ((  %;;,;,;;,;
    ))  ;#;,;%;;,,
  _//    ;,;; ,#;,
 /_)     #,;  //
        //    \|_
        \|_    |#\


PWNING SYSTEMS WITH PWN0S 
meatspace? it moves so slow. me, i like the net. it moves fast <3
"""
INTERFACEPLUG_ASCII_ART = """
 ____________________________________________________
T ================================================= |T
| ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|[L
| __________________________________________________[|
|I __==___________  ___________     .  ,. _ .   __  T|
||[_j  L_I_I_I_I_j  L_I_I_I_I_j    /|/V||(g/|   ==  l|
lI _______________________________  _____  _________I]
 |[__I_I_I_I_I_I_I_I_I_I_I_I_I_I_] [__I__] [_I_I_I_]|
 |[___I_I_I_I_I_I_I_I_I_I_I_I_L  I   ___   [_I_I_I_]|
 |[__I_I_I_I_I_I_I_I_I_I_I_I_I_L_I __I_]_  [_I_I_T ||
 |[___I_I_I_I_I_I_I_I_I_I_I_I____] [_I_I_] [___I_I_j|
 | [__I__I_________________I__L_]                   |
 |                                                  |  
 l__________________________________________________j
 
 
PWNING SYSTEMS WITH PWN0S 
meatspace? it moves so slow. me, i like the net. it moves fast <3
"""
QUICKHACK_ASCII_ART = """
                                 |     |
                                 \\_V_//
                                 \/=|=\/
                                  [=v=]
                                __\___/_____
                               /..[  _____  ]
                              /_  [ [  M /] ]
                             /../.[ [ M /@] ]
                            <-->[_[ [M /@/] ]
                           /../ [.[ [ /@/ ] ]
      _________________]\ /__/  [_[ [/@/ C] ]
     <_________________>>0---]  [=\ \@/ C / /
        ___      ___   ]/000o   /__\ \ C / /
           \    /              /....\ \_/ /
        ....\||/....           [___/=\___/
       .    .  .    .          [...] [...]
      .      ..      .         [___/ \___]
      .    0 .. 0    .         <---> <--->
   /\/\.    .  .    ./\/\      [..]   [..]
  / / / .../|  |\... \ \ \    _[__]   [__]_
 / / /       \/       \ \ \  [____>   <____]
 
 
PWNING SYSTEMS WITH PWN0S 
meatspace? it moves so slow. me, i like the net. it moves fast <3
"""
COMMAND_ALIASES = {
    "quickhack": "qh",
    "daemon": "d",
    "interfaceplug": "ifp",
    "brainwipe": "bw",
    "exit": "q",
    "quit": "q",
    "shortcirc": "sc",
    "ping": "pg",
    "seeker": "sk",
    "filedaemon": "fd",
    "blackout": "b",
    "deck": "dk",
    "icepick": "ic",
    "rabids": "rb",
}
SHORT_TO_FULL = {v: k for k, v in COMMAND_ALIASES.items()}
COMMANDS = list(COMMAND_ALIASES.keys()) + list(SHORT_TO_FULL.keys())
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CURRENT_COMMAND = None
ASCII_ART_PATH = os.path.join(PROJECT_ROOT, 'ascii.txt')
try:
    with open(ASCII_ART_PATH, 'r', encoding='utf-8') as f:
        ASCII_ART = f.read()
except Exception:
    ASCII_ART = ''
def print_ascii_art():
    global CURRENT_COMMAND
    if CURRENT_COMMAND == "quickhack":
        print()
        print(f"{YELLOW}{QUICKHACK_ASCII_ART}{RESET}")
        print()
    elif CURRENT_COMMAND == "daemon":
        print()
        print(f"{RED}{DAEMON_ASCII_ART}{RESET}")
        print()
    elif CURRENT_COMMAND == "interfaceplug":
        print()
        print(f"{BLUE}{INTERFACEPLUG_ASCII_ART}{RESET}")
        print()
    else:
        if ASCII_ART:
            print()
            print(ASCII_ART)
            print()
def completer(text, state):
    options = [cmd for cmd in COMMANDS if cmd.startswith(text)]
    if state < len(options):
        return options[state] + ' '
    return None
readline.set_completer(completer)
readline.parse_and_bind('tab: complete')
HISTFILE = '.pwn0s_history'
try:
    readline.read_history_file(HISTFILE)
except (FileNotFoundError, PermissionError):
    pass
import atexit
def save_history():
    try:
        readline.write_history_file(HISTFILE)
    except (PermissionError, OSError):
        pass
atexit.register(save_history)
def print_command_guide():
    print(f"{BOLD}{PINK}Available Commands:{RESET}")
    print(f"  {PINK}quickhack{RESET} (qh)     - {YELLOW}Network tools and utilities{RESET}")
    print(f"  {PINK}daemon{RESET} (d)         - {YELLOW}Background services and automation{RESET}")
    print(f"  {PINK}interfaceplug{RESET} (ifp) - {YELLOW}Hardware and interface tools{RESET}")
    print(f"  {PINK}exit{RESET} (q)           - {YELLOW}Exit PWN0S{RESET}")
    print()
def print_quickhack_guide():
    print(f"{BOLD}{PINK}quickhack Command Options:{RESET}")
    print(f"  {PINK}shortcirc{RESET} (sc)     - {YELLOW}Denial-of-service toolkit{RESET}")
    print(f"  {PINK}ping{RESET} (pg)          - {YELLOW}Information gathering and tracking{RESET}")
    print(f"  {PINK}icepick{RESET} (ic)       - {YELLOW}EXE dropper/runner for red team ops{RESET}")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  quickhack shortcirc -t 192.168.1.1:80 -m UDP -ti 60")
    print(f"  qh sc -t 192.168.1.1:80 -m UDP -ti 60")
    print(f"  quickhack ping -i 8.8.8.8")
    print(f"  qh pg -i 8.8.8.8")
    print(f"  quickhack icepick -t C:\\Users\\victim\\Desktop\\app1.exe -p C:\\Users\\victim\\Desktop\\payload.exe")
    print(f"  qh ic -t C:\\Users\\victim\\Desktop\\app1.exe -p C:\\Users\\victim\\Desktop\\payload.exe")
    print(f"  quickhack ping -s -t 1 -p 8080")
    print(f"  qh pg -s -t 1 -p 8080")
def print_shortcirc_guide():
    print(f"{BOLD}{PINK}shortcirc - Denial-of-Service Toolkit{RESET}")
    print(f"{YELLOW}Description:{RESET} Advanced DDoS toolkit with multiple attack vectors")
    print()
    print(f"{BOLD}{PINK}Options:{RESET}")
    print(f"  -target, -t <ip:port/url/phone>  Target specification")
    print(f"  -method, -m <attack_type>        Attack method (SMS/EMAIL/NTP/UDP/SYN/ICMP/POD/MEMCACHED/HTTP/SLOWLORIS)")
    print(f"  -time, -ti <seconds>              Attack duration")
    print(f"  -threads, -th <count>             Number of threads (1-200)")
    print(f"  -h                                Show this help")
    print()
    print(f"{YELLOW}Attack Methods:{RESET}")
    print(f"  SMS/EMAIL     - SMS/Email bombing")
    print(f"  NTP/UDP/SYN   - Network flooding")
    print(f"  ICMP/POD      - Ping of Death")
    print(f"  MEMCACHED     - Memcached amplification")
    print(f"  HTTP/SLOWLORIS- HTTP-based attacks")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  shortcirc -t 192.168.1.1:80 -m UDP -ti 60 -th 10")
    print(f"  sc -t example.com -m HTTP -ti 120 -th 50")
def print_ping_guide():
    print(f"{BOLD}{PINK}ping - Information Gathering Toolkit{RESET}")
    print(f"{YELLOW}Description:{RESET} Comprehensive OSINT and tracking tools")
    print()
    print(f"{BOLD}{PINK}Options:{RESET}")
    print(f"  -ip, -i <address>                IP address tracker")
    print(f"  -sip, -si                        Show your IP address")
    print(f"  -pn, -p <number>                 Phone number tracker")
    print(f"  -ut, -u <username>               Username tracker")
    print(f"  -seeker, -s                      Launch seeker phishing toolkit")
    print(f"  -h                               Show this help")
    print(f"  -q                               Exit")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  ping -i 8.8.8.8")
    print(f"  pg -i 8.8.8.8")
    print(f"  ping -p +1234567890")
    print(f"  pg -p +1234567890")
    print(f"  ping -u username")
    print(f"  pg -u username")
    print(f"  ping -s -t 1 -p 8080")
    print(f"  pg -s -t 1 -p 8080")
def print_seeker_guide():
    print(f"{BOLD}{PINK}seeker - Phishing Toolkit{RESET}")
    print(f"{YELLOW}Description:{RESET} Advanced phishing framework with location tracking")
    print()
    print(f"{BOLD}{PINK}Options:{RESET}")
    print(f"  -t, --template <num>         Template number (required)")
    print(f"  -k, --kml <filename>         KML filename")
    print(f"  -p, --port <port>            Web server port (default: 8080)")
    print(f"  -u, --update                 Check for updates")
    print(f"  -v, --version                Show version")
    print(f"  -d, --debugHTTP <bool>       Disable HTTPS redirection")
    print(f"  -tg, --telegram <token:chatId> Telegram bot API token")
    print(f"  -wh, --webhook <url>         Webhook URL")
    print()
    print(f"{YELLOW}Short Forms:{RESET}")
    print(f"  -t <num> (template)")
    print(f"  -k <filename> (kml)")
    print(f"  -p <port> (port)")
    print(f"  -u (update)")
    print(f"  -v (version)")
    print(f"  -d <bool> (debugHTTP)")
    print(f"  -tg <token:chatId> (telegram)")
    print(f"  -wh <url> (webhook)")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  seeker -t 1 -p 8080")
    print(f"  sk -t 2 -k output.kml")
def print_daemon_guide():
    print(f"{BOLD}{PINK}daemon Command Options:{RESET}")
    print(f"  {PINK}filedaemon{RESET} (fd)       - {YELLOW}HTTP file server{RESET}")
    print(f"  {PINK}brainwipe{RESET} (bw)         - {YELLOW}Website Cloning and SEToolkit Integration{RESET}")
    print(f"  {PINK}rabids{RESET} (rb)             - {YELLOW}Rabids Spider Payload Builder{RESET}")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  daemon -fd -s")
    print(f"  d fd -s")
    print(f"  daemon -bw https://example.com")
    print(f"  d bw https://example.com")
    print(f"  daemon -rb -spider -lhost 192.168.1.1 -lport 8080 -key abcdef -output output.html")
    print(f"  d rb -spider -lhost 192.168.1.1 -lport 8080 -key abcdef -output output.html")
def print_filedaemon_guide():
    print(f"{BOLD}{PINK}filedaemon - HTTP File Server{RESET}")
    print(f"{YELLOW}Description:{RESET} Simple HTTP server for file sharing and payload delivery")
    print()
    print(f"{BOLD}{PINK}Options:{RESET}")
    print(f"  -start, -s                   Start HTTP server")
    print(f"  -clean, -c                   Clean 'dir' folder contents")
    print(f"  -h                           Show this help")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  filedaemon -s")
    print(f"  fd -c")
def print_brainwipe_guide():
    print(f"{BOLD}{PINK}brainwipe - Website Cloning and SEToolkit Integration{RESET}")
    print(f"{YELLOW}Description:{RESET} Clones target websites or serves phishing templates for credential harvesting. Supports phishing customization options.")
    print()
    print(f"{BOLD}{PINK}Usage:{RESET}")
    print(f"  brainwipe <url> [-phonecode|-pc] [-emailcode|-ec] [-buttoncolor|-bc <hex>] [-redirecturl|-ru <url>]")
    print(f"  brainwipe -template <name> [-phonecode|-pc] [-emailcode|-ec] [-buttoncolor|-bc <hex>] [-redirecturl|-ru <url>]")
    print(f"  bw <url> ... | bw -template <name> ...")
    print()
    print(f"{BOLD}{PINK}Options:{RESET}")
    print(f"  -template <name>         Serve a phishing template from the sites directory")
    print(f"  -phonecode, -pc         Add phone verification code field")
    print(f"  -emailcode, -ec         Add email verification code field")
    print(f"  -buttoncolor, -bc <hex> Set login button color (default: #007bff)")
    print(f"  -redirecturl, -ru <url> Redirect after form submission")
    print()
    print(f"{YELLOW}Examples:{RESET}")
    print(f"  brainwipe -template facebook -pc -bc #ff0000 -ru https://google.com")
    print(f"  bw -template google_new -ec")
    print(f"  brainwipe https://example.com -ec")
    print()
    print(f"{YELLOW}Automatic Features:{RESET}")
    print(f"  - Web server starts automatically on http://localhost:8000")
    print(f"  - Credentials are logged to credentials.txt")
    print(f"  - Always cleans up cloned files after completion")
    print(f"  - Always runs SEToolkit after cloning")
def print_interfaceplug_guide():
    print(f"{BOLD}{PINK}interfaceplug Command Options:{RESET}")
    print(f"  {PINK}blackout{RESET} (b)     - {YELLOW}ESP32 hardware interface{RESET}")
    print(f"  {PINK}deck{RESET}             - {YELLOW}SSH connection manager{RESET}")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  interfaceplug -blackout -scan")
    print(f"  interfaceplug -blackout -connect 192.168.1.100")
    print(f"  interfaceplug -deck")
def print_blackout_guide():
    print(f"{BOLD}{PINK}blackout - ESP32 Hardware Interface{RESET}")
    print(f"{YELLOW}Description:{RESET} ESP32 microcontroller communication and control")
    print()
    print(f"{BOLD}{PINK}Options:{RESET}")
    print(f"  -connect <server_ip>         Connect to ESP32 server")
    print(f"  -scan                        Scan available serial ports")
    print(f"  -connect -p <device>         Connect to specific ESP32 device")
    print(f"  -send <command>              Send command to ESP32")
    print(f"  -h                           Show this help")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  blackout -scan")
    print(f"  blackout -connect 192.168.1.100")
    print(f"  blackout -connect -p /dev/ttyUSB0")
    print(f"  blackout -send 'LED_ON'")
def print_deck_guide():
    print(f"{BOLD}{PINK}deck - SSH Connection Manager{RESET}")
    print(f"{YELLOW}Description:{RESET} Automated SSH connection using stored credentials")
    print()
    print(f"{BOLD}{PINK}Options:{RESET}")
    print(f"  -username <user>             SSH username")
    print(f"  -ip <address>                Target IP address")
    print(f"  -password <pass>             SSH password")
    print(f"  -h                           Show this help")
    print()
    print(f"{YELLOW}Usage Examples:{RESET}")
    print(f"  deck                                    # Use existing config.json")
    print(f"  deck -username admin -ip 192.168.1.100 -password mypass123")
    print()
    print(f"{YELLOW}Configuration:{RESET}")
    print(f"  Config file: INTERFACEPLUGS/deck/config.json")
    print(f"  Format: {{\"username\": \"user\", \"ip\": \"ip\", \"password\": \"pass\"}}")
def print_icepick_guide():
    print(f"{BOLD}{PINK}icepick - EXE Dropper/Runner{RESET}")
    print(f"{YELLOW}Description:{RESET} Drops and runs embedded EXE payloads (red team/offsec use). Always self-compiles on first run if needed.")
    print()
    print(f"{BOLD}{PINK}Usage:{RESET}")
    print(f"  quickhack icepick -t <target exe path> -p <payload exe path>")
    print(f"  qh ic -t <target exe path> -p <payload exe path>")
    print()
    print(f"{YELLOW}Features:{RESET}")
    print(f"  - Drops and executes embedded EXE payloads on Windows targets.")
    print(f"  - No arguments needed; always self-compiles if required.")
    print(f"  - For red team and offensive security operations.")
    print()
    print(f"{YELLOW}Options:{RESET}")
    print(f"  -t <target exe path>   Path to the first EXE to drop and run (visible)")
    print(f"  -p <payload exe path>  Path to the second EXE to drop and run (silent)")
    print()
    print(f"{YELLOW}Note:{RESET} This tool is intended for authorized testing only.")
def suggest_command(user_cmd, valid_cmds):
    matches = difflib.get_close_matches(user_cmd, valid_cmds, n=2, cutoff=0.6)
    if matches:
        print(f"{YELLOW}Did you mean: {', '.join(matches)}{RESET}")
def suggest_subcommand_option(user_opt, valid_opts):
    matches = difflib.get_close_matches(user_opt, valid_opts, n=2, cutoff=0.6)
    if matches:
        print(f"{YELLOW}Did you mean: {', '.join(matches)}{RESET}")
def run_command(cmdline):
    global CURRENT_COMMAND
    parts = cmdline.strip().split()
    if not parts:
        return True
    cmd = parts[0].lower()
    main_categories = ["quickhack", "qh", "daemon", "d", "interfaceplug", "ifp"]
    if cmd in main_categories:
        if len(parts) > 1:
            subcmd = parts[1]
            if not subcmd.startswith("-"):
                print(f"{RED}[!] Subcommands must start with a dash (e.g., d -brainwipe, d -filedaemon, qh -ping, qh -shortcirc, etc.).{RESET}")
                print(f"    Example: d -brainwipe ...   qh -ping ...   d -filedaemon ...   -exit")
                return False
    elif not cmd.startswith("-"):
        print(f"{RED}[!] Commands must start with a dash (e.g., -brainwipe, -filedaemon, -ping, -shortcirc, etc.) except for daemon, quickhack, and interfaceplug.{RESET}")
        print(f"    Example: d -brainwipe ...   qh -ping ...   d -filedaemon ...   -exit")
        return False
    else:
        cmd = cmd[1:]
        parts[0] = cmd
    if cmd in SHORT_TO_FULL:
        cmd = SHORT_TO_FULL[cmd]
        parts[0] = cmd
    BASIC_TERMINAL_COMMANDS = [
        'ls', 'pwd', 'cat', 'echo', 'mkdir', 'rm', 'touch', 'cp', 'mv', 'whoami', 'date', 'head', 'tail', 'grep', 'find', 'chmod', 'chown', 'rmdir', 'tree', 'df', 'du', 'which', 'uname', 'ps', 'kill', 'top'
    ]
    if cmd in BASIC_TERMINAL_COMMANDS:
        try:
            result = subprocess.run(parts, capture_output=True, text=True)
            if result.stdout:
                print(result.stdout, end='')
            if result.stderr:
                print(f"{RED}{result.stderr}{RESET}", end='')
        except Exception as e:
            print(f"{RED}[!] Failed to execute command: {e}{RESET}")
        return True
    allowed_no_dash = list(COMMAND_ALIASES.keys()) + list(SHORT_TO_FULL.keys())
    if cmd not in allowed_no_dash and not cmd.startswith("-"):
        print(f"{RED}[!] Unknown command '{cmd}'{RESET}")
        suggest_command(cmd, COMMANDS)
        return False
    if cmd.startswith("-"):
        cmd = cmd[1:]
        if cmd in SHORT_TO_FULL:
            cmd = SHORT_TO_FULL[cmd]
        parts[0] = cmd
    if cmd == "quickhack":
        if len(parts) < 2:
            print(f"{RED}[!] Usage: quickhack <tool> [options]{RESET}")
            print_quickhack_guide()
            return False
        tool = parts[1].lstrip('-')
        SUBCOMMAND_ALIASES = {"shortcirc": "sc", "ping": "pg", "seeker": "sk", "icepick": "ic"}
        SHORT_TO_SUB = {v: k for k, v in SUBCOMMAND_ALIASES.items()}
        all_subs = list(SUBCOMMAND_ALIASES.keys()) + list(SHORT_TO_SUB.keys())
        if tool in SHORT_TO_SUB:
            tool = SHORT_TO_SUB[tool]
            parts[1] = tool
        if tool == "help":
            print_quickhack_guide()
            return True
        if tool in all_subs:
            if len(parts) > 2 and parts[2] in ["help", "-help", "-h"]:
                if tool == "shortcirc":
                    print_shortcirc_guide()
                    return True
                elif tool == "ping":
                    print_ping_guide()
                    return True
                elif tool == "seeker":
                    print_seeker_guide()
                    return True
                elif tool == "icepick":
                    print_icepick_guide()
                    return True
            if tool == "shortcirc":
                valid_opts = ['-target', '-t', '-method', '-m', '-time', '-ti', '-threads', '-th', '-h', '-help']
                for arg in parts[2:]:
                    if arg.startswith('-') and arg not in valid_opts and not arg.startswith('--'):
                        print(f"{RED}[!] Unknown option '{arg}' for shortcirc{RESET}")
                        suggest_subcommand_option(arg, valid_opts)
                        print_shortcirc_guide()
                        return False
            if tool == "ping":
                valid_opts = ['-ip', '-i', '-pn', '-p', '-ut', '-u', '-sip', '-si', '-h', '-help', '-q', '-seeker', '-s']
                is_seeker = '-seeker' in parts[2:] or '-s' in parts[2:]
                if is_seeker:
                    seeker_index = next((i for i, x in enumerate(parts) if x in ['-seeker', '-s']), None)
                    seeker_args = parts[seeker_index+1:] if seeker_index is not None else []
                    if len(seeker_args) > 0 and seeker_args[0] in ["help", "-help", "-h"]:
                        print_seeker_guide()
                        return False
                    with loading_state(message="Installing requirements for seeker...", duration=2, print_ascii_art=print_ascii_art):
                        pass
                    requirements = ["requests", "argparse", "packaging", "psutil"]
                    print(f"{YELLOW}[*] Installing requirements...{RESET}")
                    try:
                        subprocess.run([sys.executable, "-m", "pip"] + get_pip_install_args(requirements), check=True)
                    except subprocess.CalledProcessError:
                        print(f"{RED}[!] Failed to install requirements{RESET}")
                        return False
                    with loading_state(message="Invoking seeker toolkit...", duration=2, print_ascii_art=print_ascii_art):
                        pass
                    script_path = os.path.join(PROJECT_ROOT, "QUICKHACKS", "ping", "seeker.py")
                    seeker_arg_map = {
                        '-t': '--template', '--template': '--template',
                        '-k': '--kml', '--kml': '--kml',
                        '-p': '--port', '--port': '--port',
                        '-u': '--update', '--update': '--update',
                        '-v': '--version', '--version': '--version',
                        '-d': '--debugHTTP', '--debugHTTP': '--debugHTTP',
                        '-tg': '--telegram', '--telegram': '--telegram',
                        '-wh': '--webhook', '--webhook': '--webhook',
                    }
                    seeker_final_args = []
                    i = 0
                    while i < len(seeker_args):
                        arg = seeker_args[i]
                        if arg in seeker.arg_map:
                            seeker_final_args.append(seeker.arg_map[arg])
                            if i+1 < len(seeker_args) and not seeker_args[i+1].startswith('-'):
                                seeker_final_args.append(seeker_args[i+1])
                                i += 1
                        else:
                            seeker_final_args.append(arg)
                        i += 1
                    try:
                        subprocess.run([sys.executable, script_path] + seeker_final_args)
                    except FileNotFoundError:
                        print(f"{RED}[!] seeker script not found{RESET}")
                    return False
                for arg in parts[2:]:
                    if arg.startswith('-') and arg not in valid_opts and not arg.startswith('--'):
                        print(f"{RED}[!] Unknown option '{arg}' for ping{RESET}")
                        suggest_subcommand_option(arg, valid_opts)
                        print_ping_guide()
                        return False
                if is_seeker and ('-h' in parts[2:] or '--help' in parts[2:]):
                    print_seeker_guide()
                    return False
            if tool == "shortcirc":
                with loading_state(message="Installing requirements for shortcirc...", duration=2, print_ascii_art=print_ascii_art):
                    pass
                requirements = ["requests", "scapy", "wget", "argparse", "colorama", "humanfriendly"]
                print(f"{YELLOW}[*] Installing requirements...{RESET}")
                try:
                    subprocess.run([sys.executable, "-m", "pip"] + get_pip_install_args(requirements), check=True)
                except subprocess.CalledProcessError:
                    print(f"{RED}[!] Failed to install requirements{RESET}")
                    return False
                with loading_state(message="Invoking shortcirc toolkit...", duration=2, print_ascii_art=print_ascii_art):
                    pass
                script_path = os.path.join(PROJECT_ROOT, "QUICKHACKS", "shortcirc", "shortcirc.py")
                try:
                    subprocess.run([sys.executable, script_path] + parts[2:])
                except FileNotFoundError:
                    print(f"{RED}[!] shortcirc script not found{RESET}")
                return False
            if tool == "ping":
                if len(parts) > 2 and (parts[2] == "-seeker" or parts[2] == "-s"):
                    return False
                with loading_state(message="Installing requirements for ping...", duration=2, print_ascii_art=print_ascii_art):
                    pass
                requirements = ["requests", "phonenumbers"]
                print(f"{YELLOW}[*] Installing requirements...{RESET}")
                try:
                    subprocess.run([sys.executable, "-m", "pip"] + get_pip_install_args(requirements), check=True)
                except subprocess.CalledProcessError:
                    print(f"{RED}[!] Failed to install requirements{RESET}")
                    return False
                with loading_state(message="Invoking ping toolkit...", duration=2, print_ascii_art=print_ascii_art):
                    pass
                script_path = os.path.join(PROJECT_ROOT, "QUICKHACKS", "ping", "ping.py")
                try:
                    subprocess.run([sys.executable, script_path] + parts[2:])
                except FileNotFoundError:
                    print(f"{RED}[!] ping script not found{RESET}")
                return False
        with loading_state(message=f"Launching {tool}...", duration=2, print_ascii_art=print_ascii_art):
            pass
        try:
            subprocess.run([tool] + parts[2:])
        except FileNotFoundError:
            print(f"{RED}[!] Tool '{tool}' not found{RESET} {YELLOW}Make sure it's installed in your environment or in your PATH.{RESET}")
            return False
        return False
    elif cmd == "daemon":
        if len(parts) < 2:
            print(f"{RED}[!] Usage: daemon <service> [options]{RESET}")
            print_daemon_guide()
            return False
        service = parts[1]
        DAEMON_SUBS = {"-filedaemon": "-fd", "-brainwipe": "-bw", "-rabids": "-rb"}
        SHORT_TO_DAEMON = {v: k for k, v in DAEMON_SUBS.items()}
        if service in SHORT_TO_DAEMON:
            service = SHORT_TO_DAEMON[service]
            parts[1] = service
        if service == "help":
            print_daemon_guide()
            return True
        elif service == "-filedaemon":
            if len(parts) > 2 and parts[2] in ["help", "-help", "-h"]:
                print_filedaemon_guide()
                return True
            valid_opts = ['-start', '-s', '-clean', '-c', '-h', '-help']
            for arg in parts[2:]:
                if arg.startswith('-') and arg not in valid_opts and not arg.startswith('--'):
                    print(f"{RED}[!] Unknown option '{arg}' for filedaemon{RESET}")
                    suggest_subcommand_option(arg, valid_opts)
                    print_filedaemon_guide()
                    return False
            filedaemon_path = os.path.join(PROJECT_ROOT, "DAEMONS", "filedaemon", "filedaemon.py")
            args = [sys.executable, filedaemon_path] + parts[2:]
            with loading_state(message="Starting filedaemon server...", duration=2, print_ascii_art=print_ascii_art):
                pass
            try:
                subprocess.run(args, check=True)
            except subprocess.CalledProcessError:
                print(f"{RED}[!] filedaemon.py failed to run properly{RESET}")
                return False
            return True
        elif service == "-brainwipe":
            url = None
            template = None
            email_code = False
            phone_code = False
            button_color = None
            redirect_url = None
            template_list = False
            i = 2  # Start parsing options after the subcommand
            while i < len(parts):
                arg = parts[i]
                if arg in ("-emailcode", "-ec"):
                    email_code = True
                elif arg in ("-phonecode", "-pc"):
                    phone_code = True
                elif arg in ("-buttoncolor", "-bc") and i+1 < len(parts):
                    button_color = parts[i+1]
                    i += 1
                elif arg in ("-redirecturl", "-ru") and i+1 < len(parts):
                    redirect_url = parts[i+1]
                    i += 1
                elif arg in ("-template", "--template") and i+1 < len(parts):
                    template = parts[i+1]
                    i += 1
                elif arg in ("--template-list", "-template-list"):
                    template_list = True
                elif not arg.startswith('-') and url is None:
                    url = arg
                else:
                    print(f"{RED}[!] Unknown option '{arg}' for brainwipe{RESET}")
                    print_brainwipe_guide()
                    return False
                i += 1
            if template_list:
                sites_dir = os.path.join(PROJECT_ROOT, "DAEMONS", "Brainwipe", "sites")
                if not os.path.exists(sites_dir):
                    print(f"{RED}[-] No 'sites' directory found.{RESET}")
                    return True
                templates = [name for name in os.listdir(sites_dir) if os.path.isdir(os.path.join(sites_dir, name))]
                if not templates:
                    print(f"{RED}[-] No templates found in 'sites' directory.{RESET}")
                else:
                    print(f"{YELLOW}Available templates:{RESET}")
                    for t in sorted(templates):
                        print(f"  - {t}")
                return True
            with loading_state(message="Installing brainwipe dependencies...", duration=2, print_ascii_art=print_ascii_art):
                pass
            requirements = ["requests", "urllib3", "beautifulsoup4", "pexpect"]
            print(f"{YELLOW}[*] Installing brainwipe requirements...{RESET}")
            try:
                subprocess.run([sys.executable, "-m", "pip"] + get_pip_install_args(requirements), check=True)
            except subprocess.CalledProcessError:
                print(f"{RED}[!] Failed to install brainwipe requirements{RESET}")
                return False
            with loading_state(message="Launching brainwipe...", duration=2, print_ascii_art=print_ascii_art):
                pass
            brainwipe_path = os.path.join(PROJECT_ROOT, "DAEMONS", "Brainwipe", "brainwipe.py")
            args = [sys.executable, brainwipe_path]
            if url:
                args.append(url)
            if email_code:
                args.append("--email-code")
            if phone_code:
                args.append("--phone-code")
            if button_color:
                args.extend(["--button-color", button_color])
            if redirect_url:
                args.extend(["--redirect-url", redirect_url])
            if template:
                args.extend(["--template", template])
            try:
                subprocess.run(args)
            except FileNotFoundError:
                print(f"{RED}[!] brainwipe script not found at: {brainwipe_path}{RESET}")
                return False
            return True
        elif service == "-rabids":
            rabids_path = os.path.join(PROJECT_ROOT, "DAEMONS", "rabids", "rabids.py")
            valid_opts = ['-rabids', '-spider', '-lhost', '-lh', '-lport', '-lp', '-key', '-k', '-output', '-o', '-platform', '-pl', '-h', '--help']
            opt_map = {'-lh': '-lhost', '-lp': '-lport', '-k': '-key', '-o': '-output', '-pl': '-platform'}
            args = []
            i = 2
            show_help = False
            while i < len(parts):
                arg = parts[i]
                if arg in ('-h', '--help'):
                    show_help = True
                    break
                if arg in opt_map:
                    args.append(opt_map[arg])
                    if i+1 < len(parts) and not parts[i+1].startswith('-'):
                        args.append(parts[i+1])
                        i += 1
                else:
                    args.append(arg)
                i += 1
            if show_help or not args:
                try:
                    subprocess.run([sys.executable, rabids_path, '-h'])
                except FileNotFoundError:
                    print(f"{RED}[!] rabids script not found at: {rabids_path}{RESET}")
                return True
            if '-rabids' not in args:
                args.insert(0, '-rabids')
            if '-spider' not in args:
                print(f"{RED}[!] You must specify -spider for Rabids Spider Payload Builder.{RESET}")
                try:
                    subprocess.run([sys.executable, rabids_path, '-h'])
                except FileNotFoundError:
                    print(f"{RED}[!] rabids script not found at: {rabids_path}{RESET}")
                return False
            with loading_state(message="Launching Rabids Spider Payload Builder...", duration=2, print_ascii_art=print_ascii_art):
                pass
            try:
                subprocess.run([sys.executable, rabids_path] + args)
            except FileNotFoundError:
                print(f"{RED}[!] rabids script not found at: {rabids_path}{RESET}")
                return False
            return True
        else:
            print(f"{RED}[!] Unknown daemon service '{service}'. All daemon subcommands must start with a dash (e.g., -brainwipe, -filedaemon).{RESET}")
            print_daemon_guide()
            return False
    elif cmd == "interfaceplug":
        if len(parts) < 2:
            print(f"{RED}[!] Usage: interfaceplug <tool> [options]{RESET}")
            print()
            print_interfaceplug_guide()
            return False
        tool = parts[1].lstrip('-')
        if tool == "help":
            print_interfaceplug_guide()
            return True
        if tool in ["-blackout", "-b"]:
            if len(parts) > 2 and parts[2] in ["help", "-help", "-h"]:
                print_blackout_guide()
                return True
            blackout = BlackoutESP32(
                output_callback=lambda msg, t='system': print(msg),
                print_ascii_art=print_ascii_art,
                YELLOW=YELLOW,
                GREEN=GREEN,
                RED=RED,
                PINK=PINK,
                RESET=RESET
            )
            args = parts[2:]
            valid_blackout_opts = ["-connect", "-c", "-scan", "-send", "-p", "-pw", "-h", "-help"]
            if not args or (args[0] not in valid_blackout_opts and not (args[0] in ["-connect", "-c"] and len(args) > 1 and args[1] in ["-p", "-pw"])):
                print(f"{RED}[!] Unknown blackout subcommand or option: '{' '.join(args)}'{RESET}")
                suggest_subcommand_option(args[0] if args else '', valid_blackout_opts)
                print_blackout_guide()
                return False
            if args[0] in ["-connect", "-c"] and len(args) == 2:
                with loading_state(message=f"Connecting to server at {args[1]}...", duration=2, print_ascii_art=print_ascii_art):
                    blackout.connect_to_server(args[1])
                return True
            elif args[0] == "-scan":
                with loading_state(message="Scanning serial ports...", duration=2, print_ascii_art=print_ascii_art):
                    blackout.scan_serial_ports()
                return True
            elif args[0] in ["-connect", "-c"] and len(args) > 2 and args[1] in ["-p", "-pw"]:
                with loading_state(message=f"Connecting to ESP32 on {args[2]}...", duration=2, print_ascii_art=print_ascii_art):
                    blackout.connect_to_esp32(args[2])
                return True
            elif args[0] == "-send" and len(args) > 1:
                with loading_state(message=f"Sending command: {' '.join(args[1:])}...", duration=2, print_ascii_art=print_ascii_art):
                    blackout.send_esp32_command(' '.join(args[1:]))
                return True
            elif args[0] == "-h":
                print_blackout_guide()
                return False
            else:
                print(f"{RED}Usage: interfaceplug -blackout -connect <server_ip> | -scan | -connect -p <device> | -send <command>{RESET}")
            return False
        elif tool == "-deck":
            if len(parts) > 2 and parts[2] in ["help", "-help", "-h"]:
                print_deck_guide()
                return True
            with loading_state(message="Launching SSH connection manager...", duration=2, print_ascii_art=print_ascii_art):
                pass
            deck_path = os.path.join(PROJECT_ROOT, "INTERFACEPLUGS", "deck", "deck.py")
            try:
                subprocess.run([sys.executable, deck_path] + parts[2:])
            except FileNotFoundError:
                print(f"{RED}[!] deck script not found{RESET}")
                return False
            return True
        else:
            print(f"{RED}[!] Unknown interfaceplug tool '{tool}'{RESET}")
            print_interfaceplug_guide()
            return False
    elif cmd in ["exit", "quit", "q"]:
        clear_screen()
        print_ascii_art()
        print(f"{PINK}{BOLD}Goodbye!{RESET}")
        sys.exit(0)
        return False
    else:
        print(f"{RED}[!] Unknown command '{cmd}'{RESET}")
        suggest_command(cmd, COMMANDS)
        return False
def check_dependencies():
    import importlib
    import platform
    import subprocess
    import sys
    try:
        from tqdm import tqdm
        use_tqdm = True
    except ImportError:
        use_tqdm = False
    python_packages = [
        'requests', 'scapy', 'wget', 'argparse', 'colorama', 'humanfriendly', 
        'phonenumbers', 'packaging', 'psutil', 'tqdm', 'urllib3', 'beautifulsoup4',
        'selenium', 'webdriver-manager'
    ]
    missing = []
    print(f"{YELLOW}{BOLD}[*] Checking Python dependencies...{RESET}")
    iterator = tqdm(python_packages, desc="Checking", ncols=70) if use_tqdm else python_packages
    for pkg in iterator:
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing.append(pkg)
        if not use_tqdm:
            print(f"  {pkg}... {'OK' if pkg not in missing else 'MISSING'}")
            time.sleep(0.1)
    pip_bin = shutil.which('pip') or shutil.which('pip3')
    if missing:
        if pip_bin is None:
            print(f"{RED}{BOLD}[!] Missing system dependency:{RESET} pip (pip or pip3)")
            print(f"{YELLOW}Please install pip or pip3 manually!{RESET}")
            os_name = platform.system().lower()
            if os_name == 'darwin':
                print(f"  brew install python3")
            elif os_name == 'linux':
                print(f"  sudo apt install python3-pip")
            else:
                print(f"  Download Python from https://www.python.org/downloads/")
            print()
            print(f"{RED}{BOLD}[!] Continuing without pip. Some features may not work.{RESET}")
        print(f"{YELLOW}{BOLD}[*] Installing missing Python packages:{RESET} {', '.join(missing)}")
        try:
            subprocess.run([pip_bin] + get_pip_install_args(missing), check=True)
        except Exception as e:
            print(f"{RED}{BOLD}[!] Failed to install Python packages: {e}{RESET}")
            print(f"{RED}{BOLD}[!] Continuing without some Python packages. Some features may not work.{RESET}")
    system_bins = {
        'php': 'PHP',
        'msfvenom': 'msfvenom (Metasploit)',
        'wget': 'wget',
        'httrack': 'httrack',
        'monolith': 'monolith',
    }
    missing_bins = []
    print(f"{YELLOW}{BOLD}[*] Checking system dependencies...{RESET}")
    iterator = tqdm(system_bins.items(), desc="Checking", ncols=70) if use_tqdm else system_bins.items()
    for bin, name in iterator:
        if shutil.which(bin) is None:
            missing_bins.append((bin, name))
        if not use_tqdm:
            print(f"  {name} ({bin})... {'OK' if shutil.which(bin) else 'MISSING'}")
            time.sleep(0.1)
    if pip_bin is None:
        missing_bins.append(('pip/pip3', 'pip or pip3'))
    if missing_bins:
        print(f"{RED}{BOLD}[!] Missing system dependencies:{RESET}")
        for bin, name in missing_bins:
            print(f"  {YELLOW}{name}{RESET} ({bin})")
        print(f"\n{YELLOW}Please install the missing dependencies manually:{RESET}")
        os_name = platform.system().lower()
        for bin, name in missing_bins:
            if 'php' in bin:
                if os_name == 'darwin':
                    print(f"  brew install php")
                elif os_name == 'linux':
                    print(f"  sudo apt install php")
                else:
                    print(f"  Download PHP from https://www.php.net/downloads.php")
            elif 'msfvenom' in bin:
                print(f"  Install Metasploit from https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html")
            elif 'wget' in bin:
                if os_name == 'darwin':
                    print(f"  brew install wget")
                elif os_name == 'linux':
                    print(f"  sudo apt install wget")
                else:
                    print(f"  Download wget from https://www.gnu.org/software/wget/")
            elif 'httrack' in bin:
                if os_name == 'darwin':
                    print(f"  brew install httrack")
                elif os_name == 'linux':
                    print(f"  sudo apt install httrack")
                else:
                    print(f"  Download httrack from https://www.httrack.com/")
            elif 'monolith' in bin:
                print(f"  cargo install monolith")
            elif 'pip' in bin:
                if os_name == 'darwin':
                    print(f"  brew install python3")
                elif os_name == 'linux':
                    print(f"  sudo apt install python3-pip")
                else:
                    print(f"  Download Python from https://www.python.org/downloads/")
        print()
        print(f"{RED}{BOLD}[!] Continuing without some system dependencies. Some features may not work.{RESET}")
    print(f"{GREEN}{BOLD}[✓] All dependencies satisfied!{RESET}\n")
GITHUB_REPO_URL = "https://github.com/sarwaaaar/PWN0S"
GITHUB_ZIP_URL = "https://github.com/sarwaaaar/PWN0S/archive/refs/heads/main.zip"
LATEST_VERSION_URL = "https://raw.githubusercontent.com/sarwaaaar/PWN0S/main/main.py"
def get_latest_version():
    import requests
    try:
        resp = requests.get(LATEST_VERSION_URL, timeout=10)
        if resp.status_code == 200:
            import re
            match = re.search(r'VERSION\s*=\s*["\']([\d.]+)["\']', resp.text)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"{YELLOW}[!] Could not check for updates: {e}{RESET}")
    return None
def update_to_latest():
    import requests
    print(f"{YELLOW}{BOLD}[*] Downloading latest version from GitHub...{RESET}")
    try:
        resp = requests.get(GITHUB_ZIP_URL, stream=True, timeout=30)
        if resp.status_code == 200:
            zip_bytes = io.BytesIO(resp.content)
            with zipfile.ZipFile(zip_bytes) as z:
                for member in z.namelist():
                    if member.endswith('/'):
                        continue
                    target_path = os.path.join(PROJECT_ROOT, *member.split('/')[1:])
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with open(target_path, 'wb') as f:
                        f.write(z.read(member))
            print(f"{GREEN}{BOLD}[✓] Updated to latest version! Restarting...{RESET}")
            time.sleep(1)
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            print(f"{RED}[!] Failed to download latest version (HTTP {resp.status_code}){RESET}")
    except Exception as e:
        print(f"{RED}[!] Update failed: {e}{RESET}")
def check_and_update():
    print(f"{YELLOW}{BOLD}[*] Checking for updates...{RESET}")
    latest = get_latest_version()
    if latest and latest != VERSION:
        print(f"{PINK}New version available: {latest} (current: {VERSION}){RESET}")
        update_to_latest()
    elif latest:
        print(f"{GREEN}{BOLD}[✓] You are running the latest version ({VERSION}){RESET}")
    else:
        print(f"{YELLOW}[!] Could not determine latest version. Continuing...{RESET}")
def get_missing_dependencies():
    import importlib
    import platform
    import shutil
    import sys
    python_packages = [
        'requests', 'scapy', 'wget', 'argparse', 'colorama', 'humanfriendly', 
        'phonenumbers', 'packaging', 'psutil', 'tqdm', 'urllib3', 'beautifulsoup4',
        'selenium', 'webdriver-manager'
    ]
    missing = []
    for pkg in python_packages:
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing.append(pkg)
    system_bins = {
        'php': 'PHP',
        'msfvenom': 'msfvenom (Metasploit)',
        'wget': 'wget',
        'httrack': 'httrack',
        'monolith': 'monolith',
    }
    missing_bins = []
    for bin, name in system_bins.items():
        if shutil.which(bin) is None:
            missing_bins.append((bin, name))
    pip_bin = shutil.which('pip') or shutil.which('pip3')
    if pip_bin is None:
        missing_bins.append(('pip/pip3', 'pip or pip3'))
    return missing, missing_bins
def main():
    global CURRENT_COMMAND
    print()
    # Check for 'missing' command before anything else
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'missing':
        clear_screen()
        print_ascii_art()
        missing_py, missing_sys = get_missing_dependencies()
        if not missing_py and not missing_sys:
            print(f"{GREEN}{BOLD}[✓] No missing dependencies!{RESET}")
        else:
            if missing_py:
                print(f"{RED}{BOLD}[!] Missing Python packages:{RESET} {', '.join(missing_py)}")
            if missing_sys:
                print(f"{RED}{BOLD}[!] Missing system dependencies:{RESET}")
                for bin, name in missing_sys:
                    print(f"  {YELLOW}{name}{RESET} ({bin})")
        sys.exit(0)
    check_and_update()
    check_dependencies()
    clear_screen()
    print_ascii_art()
    print()
    while True:
        try:
            cmdline = input(f"{PINK}> {RESET}")
            if cmdline.strip().lower() in ["exit", "quit", "q"]:
                clear_screen()
                print_ascii_art()
                print(f"{PINK}{BOLD}Goodbye!{RESET}")
                print()
                sys.exit(0)
            if cmdline.strip().lower() == "missing":
                clear_screen()
                print_ascii_art()
                missing_py, missing_sys = get_missing_dependencies()
                if not missing_py and not missing_sys:
                    print(f"{GREEN}{BOLD}[✓] No missing dependencies!{RESET}")
                else:
                    if missing_py:
                        print(f"{RED}{BOLD}[!] Missing Python packages:{RESET} {', '.join(missing_py)}")
                    if missing_sys:
                        print(f"{RED}{BOLD}[!] Missing system dependencies:{RESET}")
                        for bin, name in missing_sys:
                            print(f"  {YELLOW}{name}{RESET} ({bin})")
                continue
            clear_screen()
            parts = cmdline.strip().split()
            if parts:
                cmd = parts[0].lower()
                if cmd in ["quickhack", "qh"]:
                    CURRENT_COMMAND = "quickhack"
                elif cmd in ["daemon", "d"]:
                    CURRENT_COMMAND = "daemon"
                elif cmd in ["interfaceplug", "ifp"]:
                    CURRENT_COMMAND = "interfaceplug"
                else:
                    CURRENT_COMMAND = None
            print_ascii_art()
            run_command(cmdline)
            print()
        except (KeyboardInterrupt, EOFError):
            clear_screen()
            print_ascii_art()
            print()
            continue
if __name__ == "__main__":
    REQUIREMENTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'requirements.txt')
    def install_requirements():
        import platform
        python_bin = sys.executable
        def try_pip_install(args):
            try:
                subprocess.check_call([python_bin, '-m', 'pip', 'install'] + args)
                return True
            except Exception:
                return False
        try:
            import pkg_resources
            with open(REQUIREMENTS_PATH) as f:
                required = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            installed = {pkg.key for pkg in pkg_resources.working_set}
            missing = [pkg for pkg in required if pkg.split('==')[0].lower() not in installed]
            if missing:
                print("[INFO] Installing missing dependencies: ", ', '.join(missing))
                # Only use --break-system-packages on Linux if pip supports it
                use_break = False
                system_name = platform.system().lower()
                if system_name == 'linux':
                    try:
                        out = subprocess.check_output([python_bin, '-m', 'pip', 'help', 'install'], text=True)
                        if '--break-system-packages' in out:
                            use_break = True
                    except Exception:
                        pass
                # Never use --break-system-packages on macOS or Windows
                if use_break:
                    if not try_pip_install(['--break-system-packages'] + missing):
                        try_pip_install(missing)
                else:
                    try_pip_install(missing)
        except ImportError:
            # If pkg_resources is not available, just run pip install
            use_break = False
            system_name = platform.system().lower()
            if system_name == 'linux':
                try:
                    out = subprocess.check_output([python_bin, '-m', 'pip', 'help', 'install'], text=True)
                    if '--break-system-packages' in out:
                        use_break = True
                except Exception:
                    pass
            pip_args = ['-r', REQUIREMENTS_PATH]
            # Never use --break-system-packages on macOS or Windows
            if use_break:
                if not try_pip_install(['--break-system-packages'] + pip_args):
                    try_pip_install(pip_args)
            else:
                try_pip_install(pip_args)
    install_requirements()
    main() 