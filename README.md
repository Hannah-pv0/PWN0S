## What's New

### v0.1.1

- Rabids payload builder is now Go-based for Windows payloads: generates, encrypts, and compiles a silent EXE with persistence and AV evasion. New command: `daemon -rb -spider -lh <ip> -lp <port> -k <key>` (or `d -rb -spider ...`).

- Added `icepick` quickhack command: EXE binder for red team/offsec use. Now supports arguments: `-target <target exe path> -p <payload exe path>`.

## Overview

PWN0S consolidates multiple cybersecurity capabilities into a single, streamlined interface, empowering security professionals with a robust platform for penetration testing and offensive security operations. Its key features include:

- **Quickhacks**: A suite of network reconnaissance and attack tools for rapid deployment during engagements, enabling swift intelligence gathering and exploitation.

- **Daemons**: Background services that automate payload generation, file serving, and persistent operations, reducing manual overhead in complex workflows.

- **Interface Plugs**: Hardware management utilities for interfacing with microcontrollers and other devices, enabling seamless integration with physical attack vectors.

## How to Install

1. **Clone the repository** (if you haven't already):

   ```bash
   git clone https://github.com/sarwaaaar/PWN0S.git
   cd PWN0S
   ```

2. **Install Python 3.8+**

   - Make sure you have Python 3.8 or newer installed. You can check your version with:
     ```bash
     python3 --version
     ```
   - If you need to install Python:
     - **macOS:**
       ```bash
       brew install python3
       ```
     - **Linux (Debian/Ubuntu):**
       ```bash
       sudo apt update && sudo apt install python3 python3-pip
       ```
     - **Windows:**
       Download from [python.org](https://www.python.org/downloads/)

3. **Install dependencies**

   - Install all required Python packages:
     ```bash
     python3 -m pip install --upgrade pip
     python3 -m pip install -r requirements.txt
     ```

4. **(Optional) Install system dependencies**

   - Some features require additional tools:
     - `php`, `go`, `cargo`, `msfvenom`, `wget`, `httrack`, `monolith`
   - On macOS (using Homebrew):
     ```bash
     brew install php go msfvenom wget httrack
     cargo install monolith
     ```
   - On Linux (Debian/Ubuntu):
     ```bash
     sudo apt install php go cargo metasploit-framework wget httrack
     cargo install monolith
     ```
   - For `msfvenom`, see [Metasploit installation guide](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html)

5. **Run PWN0S**
   ```bash
   python3 main.py
   ```

You're ready to use PWN0S! For command usage, see the Command Reference below.

## Command Reference

PWN0S provides a comprehensive command-line interface with extensive options and shortcuts, designed for efficiency and ease of use. Commands are organized into three main categories: **Quickhacks**, **Daemons**, and **Interface Plugs**, with additional support for standard system commands. Below are detailed tables for each category, followed by in-depth explanations of their functionality.

### Main Commands

| Full Command    | Shortcut | Description                             |
| --------------- | -------- | --------------------------------------- |
| `quickhack`     | `qh`     | Network reconnaissance and attack tools |
| `daemon`        | `d`      | Background services and automation      |
| `interfaceplug` | `ifp`    | Hardware and interface management       |
| `icepick`       | `ic`     | EXE dropper/runner for red team ops     |
| `exit`          | `q`      | Exit PWN0S                              |
| `quit`          | `q`      | Exit PWN0S                              |

The main commands serve as the entry points to PWN0S's core functionalities. `quickhack` (or `qh`) provides access to network-focused tools for reconnaissance and attacks, ideal for rapid deployment in penetration testing scenarios. `daemon` (or `d`) manages background services that automate tasks like payload generation and file serving, reducing manual effort. `interfaceplug` (or `ifp`) handles hardware interactions, enabling seamless integration with devices like the ESP32-S3 for WiFi hacking and IoT attacks. The `exit` or `quit` commands (`q`) allow users to safely terminate the PWN0S session. Help for any command can be accessed using `quickhack help`, `daemon help`, or `interfaceplug help`.

### Daemons

Daemons are background services that automate critical tasks such as payload delivery, file serving, and website cloning. They operate silently, ensuring operational efficiency during complex engagements.

#### File Daemon

| Command         | Shortcut   | Options      | Description                           |
| --------------- | ---------- | ------------ | ------------------------------------- |
| `daemon -fd -s` | `d -fd -s` | `-start, -s` | Start HTTP server for 'dir' folder    |
| `daemon -fd -c` | `d -fd -c` | `-clean, -c` | Remove all contents from 'dir' folder |
| `daemon -fd -h` | `d -fd -h` | `-h, -help`  | Show help message                     |

The File Daemon is a lightweight HTTP server designed for payload delivery and file sharing during engagements. Running on port 8000, it serves files from the `DAEMONS/filedaemon/dir/` directory, making it ideal for distributing exploits, scripts, or other resources to target systems. The `-start` (`-s`) option launches the server, while the `-clean` (`-c`) option removes all contents from the directory to maintain operational security by eliminating traces post-operation. This tool is particularly useful for delivering payloads generated by other PWN0S components, such as the Rabids daemon, ensuring seamless integration within the toolkit.

#### Rabids

| Command                                                               | Shortcut                                                         | Options                                                                                                                                                                                                          | Description                |
| --------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| `daemon -rb -spider -lh <ip> -lp <port> -k <key>`                     | `d -rb -spider -lh <ip> -lp <port> -k <key>`                     | `-spider`: Use Go-based Windows payload builder<br>`-lhost, -lh`: Listener IP<br>`-lport, -lp`: Listener port<br>`-key, -k`: XOR key (0-255)<br>`-h, -help`: Show help                                         | Go-based Windows payload   |

The Rabids daemon now supports a Go-based Windows payload builder (`-spider`), which automates the creation of XOR-encrypted payloads using Metasploit's `msfvenom`, embeds them into Go source code, and compiles a silent Windows executable with AV evasion and persistence. The generated EXE is saved to the `DAEMONS/rabids/bin/` directory. Use the new command:

```
daemon -rb -spider -lh <ip> -lp <port> -k <key>
```

or the shortcut:

```
d -rb -spider -lh <ip> -lp <port> -k <key>
```

This replaces the previous Rust-based workflow for Windows payloads. The EXE runs silently, hides itself, adds persistence, and evades Defender exclusions automatically.

#### Brainwipe

| Command                                      | Shortcut                                | Options                                                                                                                                                                                          | Description                           |
| -------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------- |
| `daemon -bw <url>`                           | `d -bw <url>`                           | (None)                                                                                                                                                                                           | Basic website cloning                 |
| `daemon -bw -template`                       | `d -bw -t`                              | --template-list                                                                                                                                                                                  | Website cloning from template         |
| `daemon -bw <url> -pc -bc <color> -ru <url>` | `d -bw <url> -pc -bc <color> -ru <url>` | `-phonecode, -pc`: Add phone verification<br>`-emailcode, -ec`: Add email verification<br>`-buttoncolor, -bc`: Button color (hex)<br>`-redirecturl, -ru`: Redirect URL<br>`-h, -help`: Show help | Advanced phishing with customizations |

Brainwipe is a powerful phishing toolkit integrated with SEToolkit, designed for credential harvesting through website cloning. It uses Selenium to accurately replicate target websites, modifying them to include phishing forms for capturing credentials. The cloned site is hosted on localhost:8000, with captured data logged to `credentials.txt`. Options like `-phonecode` and `-emailcode` add verification fields to enhance phishing realism, while `-buttoncolor` and `-redirecturl` allow customization of the phishing page's appearance and behavior. Automatic cleanup ensures traces are removed post-operation, maintaining operational security. This tool is ideal for social engineering assessments in controlled environments.

### Interface Plugs

Interface Plugs manage hardware interactions, enabling seamless integration with microcontrollers and other devices for physical and wireless attack vectors.

#### Deck

| Command                                                          | Shortcut                                               | Options                                                                                              | Description                    |
| ---------------------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | ------------------------------ |
| `interfaceplug -deck`                                            | `ifp -deck`                                            | (None)                                                                                               | Use existing SSH configuration |
| `interfaceplug -deck -username <user> -ip <ip> -password <pass>` | `ifp -deck -username <user> -ip <ip> -password <pass>` | `-username`: SSH username<br>`-ip`: Target IP<br>`-password`: SSH password<br>`-h, -help`: Show help | Set credentials and connect    |

**Configuration**:

```json
{
  "username": "admin",
  "ip": "192.168.1.100",
  "password": "mypass123"
}
```

The Deck plug is an SSH connection manager that simplifies remote access to target systems or C2 servers. It uses a `config.json` file for persistent credential storage, supporting both interactive and automated SSH sessions. Options like `-username`, `-ip`, and `-password` allow users to specify connection details, while the default command (`interfaceplug -deck`) uses stored credentials for quick access. Connection status monitoring and error handling ensure reliable operation, making Deck ideal for managing remote systems during engagements.

#### Blackout

| Command                                                 | Shortcut                                      | Options                                                                                                                                    | Description                      |
| ------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------- |
| `interfaceplug -blackout -scan`                         | `ifp -blackout -scan`                         | `-scan`: Scan serial ports                                                                                                                 | Scan available serial ports      |
| `interfaceplug -blackout -connect <ip>`                 | `ifp -blackout -connect <ip>`                 | `-connect, -c`: Connect to ESP32 server                                                                                                    | Connect to ESP32 server          |
| `interfaceplug -blackout -connect -p <path>`            | `ifp -blackout -connect -p <path>`            | `-connect -p, -pw`: Connect to specific device                                                                                             | Connect to specific ESP32 device |
| `interfaceplug -blackout -send <command>`               | `ifp -blackout -send <command>`               | `-send`: Send command to ESP32                                                                                                             | Send command to ESP32            |
| `interfaceplug -blackout -ghostesp -t <type> -s <ssid>` | `ifp -blackout -ghostesp -t <type> -s <ssid>` | `-ghostesp`: Run Ghost ESP WiFi attack<br>`-t`: Attack type (e.g., deauth, sniff, rogue-ap)<br>`-s`: Target SSID<br>`-h, -help`: Show help | Run Ghost ESP WiFi attack        |

The Blackout plug interfaces with ESP32-S3 microcontrollers running **Ghost ESP**, enabling advanced WiFi hacking and hardware-based attacks. Ghost ESP supports WiFi attacks such as deauthentication (`-t deauth`), packet sniffing (`-t sniff`), and rogue access point creation (`-t rogue-ap`), targeting specified SSIDs (`-s`). Beyond WiFi, Blackout manages serial port connections (`-scan`), connects to ESP32 servers (`-connect`), and sends commands (`-send`) for real-time interaction. This plug is critical for IoT exploitation and wireless network attacks, leveraging the ESP32-S3's capabilities for field operations.

### Quickhacks

Quickhacks provide fast, network-focused tools for reconnaissance and attacks, enabling rapid execution during engagements.

#### Shortcirc

| Command                                                          | Shortcut                                                  | Options                                                                                                                                                                                              | Description        |
| ---------------------------------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| `quickhack -sc -t <target> -m <method> -ti <time> -th <threads>` | `qh -sc -t <target> -m <method> -ti <time> -th <threads>` | `-target, -t`: Target (IP:port, URL, phone)<br>`-method, -m`: Attack method (e.g., UDP, HTTP, SMS)<br>`-time, -ti`: Duration (seconds)<br>`-threads, -th`: Threads (1-200)<br>`-h, -help`: Show help | Execute DoS attack |

**Attack Methods**:

- `SMS/EMAIL`: SMS and email flooding for targeted disruption.
- `NTP/UDP/SYN`: Network-level flooding attacks.
- `ICMP/POD`: Ping of Death and ICMP-based attacks.
- `MEMCACHED`: Amplification attacks leveraging vulnerable servers.
- `HTTP/SLOWLORIS`: Application-layer attacks targeting web servers.

Shortcirc is a denial-of-service (DoS) toolkit supporting multiple attack vectors, including network flooding (UDP, SYN, ICMP), application-layer attacks (HTTP, Slowloris), and social engineering attacks (SMS/Email bombing). Configurable options like `-time` and `-threads` allow users to control attack duration and intensity, while real-time monitoring provides visibility into attack progress. Advanced techniques like Memcached amplification and Slowloris enhance its effectiveness against modern targets, making it a versatile tool for stress-testing network resilience in authorized scenarios.

#### Ping

| Command                               | Shortcut                       | Options                                                                                                                                                                                                                                                                             | Description                    |
| ------------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `quickhack -pg -i <ip>`               | `qh -pg -i <ip>`               | `-ip, -i`: Track IP address                                                                                                                                                                                                                                                         | IP address tracking            |
| `quickhack -pg -sip`                  | `qh -pg -sip`                  | `-sip, -si`: Show own IP                                                                                                                                                                                                                                                            | Display user's IP address      |
| `quickhack -pg -p <phone>`            | `qh -pg -p <phone>`            | `-pn, -p`: Track phone number                                                                                                                                                                                                                                                       | Phone number tracking          |
| `quickhack -pg -u <username>`         | `qh -pg -u <username>`         | `-ut, -u`: Track username                                                                                                                                                                                                                                                           | Username enumeration           |
| `quickhack -pg -s -t <num> -p <port>` | `qh -pg -s -t <num> -p <port>` | `-seeker, -s`: Launch Seeker<br>`-t`: Template number<br>`-p`: Port (default: 8080)<br>`-k`: KML filename<br>`-tg`: Telegram token (token:chatId)<br>`-wh`: Webhook URL<br>`-u`: Check updates<br>`-v`: Show version<br>`-d`: Disable HTTPS<br>`-h, -help`: Show help<br>`-q`: Exit | Launch Seeker phishing toolkit |

The Ping tool is a comprehensive OSINT and reconnaissance toolkit for gathering intelligence on IPs, phone numbers, and usernames. It performs geolocation and tracking of IP addresses (`-ip`), identifies phone number carriers and locations (`-pn`), and enumerates social media accounts associated with usernames (`-ut`). The `-sip` option displays the user's own IP address for situational awareness. Integrated with the Seeker phishing toolkit, Ping supports advanced social engineering with location tracking and credential harvesting, offering features like KML file generation and webhook notifications (Telegram, Discord). This tool is essential for reconnaissance phases in penetration testing.

#### Icepick

| Command                                                    | Shortcut                                            | Options  | Description                        |
| ---------------------------------------------------------- | --------------------------------------------------- | -------- | ---------------------------------- |
| `quickhack -ic -t <target exe path> -p <payload exe path>` | `qh -ic -t <target exe path> -p <payload exe path>` | `-t, -p` | Drop and run embedded EXE payloads |

Icepick is an EXE dropper/runner for red team/offsec use. It allows you to specify the target executable path and the payload executable path using the `-t` and `-p` options. The tool will drop and run the specified EXE payloads on Windows targets

### System Commands

PWN0S supports standard system commands for convenience during operations.

| Category               | Commands                                                                                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------------------- |
| **File Operations**    | `ls`, `pwd`, `cat`, `echo`, `mkdir`, `rm`, `touch`, `cp`, `mv`, `chmod`, `chown`, `rmdir`, `tree`, `df`, `du` |
| **Process Management** | `ps`, `kill`, `top`, `whoami`                                                                                 |
| **Text Processing**    | `head`, `tail`, `grep`, `find`, `which`                                                                       |
| **System Information** | `uname`, `date`                                                                                               |

These system commands allow users to interact with the underlying operating system directly from the PWN0S interface, streamlining tasks like file management, process monitoring, and system information gathering. For example, `ls -la` lists directory contents, `ps aux | grep python` monitors running Python processes, and `cat /etc/passwd` inspects system files. This integration reduces the need to switch between PWN0S and a separate terminal, enhancing workflow efficiency.

### Command Shortcuts

PWN0S supports shorthand aliases for efficiency:

- `quickhack` = `qh`
- `daemon` = `d`
- `interfaceplug` = `ifp`
- `shortcirc` = `sc`
- `ping` = `pg`
- `rabids` = `rb`
- `filedaemon` = `fd`
- `brainwipe` = `bw`
- `blackout` = `b`
- `deck` = `dk`
- `icepick` = `ic`

## Future Features (Coming Soon)

PWN0S is actively under development, with several exciting features planned:

- **Advanced Malware Modules**: Support for researching and simulating cryptominers, ransomware, time bombs, and other malware types in controlled environments.
- **Expanded Hardware Capabilities**:
  - **Radio Hacking**: Integration with SDR for intercepting and manipulating wireless signals.
  - **RFID Card Reader/Writer**: Tools for cloning and modifying RFID tags.
  - **Infrared Communication**: Support for IR-based attacks on IoT and legacy devices.
  - **Keystroke Injection**: Enhanced BadUSB and Rubber Ducky integration.
- **Remote Cyber Deck Framework**: A lightweight framework running on Raspberry Pi Zero W, coordinating with Pico W and ESP32-S3 for a fully portable, remote-capable cyber deck, enabling synchronized attacks across devices.

## Legal Disclaimer

PWN0S is intended for educational purposes and authorized security testing only. Users must obtain explicit permission before using this toolkit against any systems or networks. The authors and contributors are not liable for any misuse, damage, or legal consequences resulting from the use of this tool. Always adhere to applicable laws and ethical guidelines.

## Contributing

Contributions are welcome to enhance PWN0S's capabilities. To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Implement and test your changes thoroughly.
4. Commit your changes (`git commit -m "Add your feature"`).
5. Push to your fork (`git push origin feature/your-feature`).
6. Submit a pull request with a detailed description of your changes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Links

- **Seeker (Integrated Phishing Toolkit)**: https://github.com/thewhiteh4t/seeker
- **GhostTrack (OSINT Tracking Tool)**: https://github.com/HunxByts/GhostTrack
- **Impulse (DDoS Toolkit)**: https://github.com/LimerBoy/Impulse
- **Metasploit Framework**: https://github.com/rapid7/metasploit-framework
- **Kali Linux**: https://www.kali.org/
- **Rust Programming Language**: https://www.rust-lang.org/
