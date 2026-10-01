# ============================================================
# X1CommandSentinel
# Command Database
# Created by X1
# ============================================================

COMMANDS = {
    "pwd": {
        "meaning": "Shows the current working directory.",
        "purpose": "Displays your current location in the filesystem.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "ls": {
        "meaning": "Lists files and directories.",
        "purpose": "Shows the contents of a directory.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "cd": {
        "meaning": "Changes the current working directory.",
        "purpose": "Moves the current shell session to another directory.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "mkdir": {
        "meaning": "Creates a new directory.",
        "purpose": "Creates a new folder.",
        "risk": "LOW",
        "files": True,
        "delete": False,
        "network": False,
        "root": False,
    },

    "touch": {
        "meaning": "Creates an empty file or updates a file timestamp.",
        "purpose": "Creates a file if it does not already exist.",
        "risk": "LOW",
        "files": True,
        "delete": False,
        "network": False,
        "root": False,
    },

    "cp": {
        "meaning": "Copies files or directories.",
        "purpose": "Creates a copy of specified data.",
        "risk": "LOW",
        "files": True,
        "delete": False,
        "network": False,
        "root": False,
    },

    "mv": {
        "meaning": "Moves or renames files and directories.",
        "purpose": "Moves data or changes its name.",
        "risk": "LOW",
        "files": True,
        "delete": False,
        "network": False,
        "root": False,
    },

    "rm": {
        "meaning": "Removes files or directories.",
        "purpose": "Deletes specified filesystem objects.",
        "risk": "HIGH",
        "files": True,
        "delete": True,
        "network": False,
        "root": False,
    },

    "chmod": {
        "meaning": "Changes file permissions.",
        "purpose": "Modifies who can read, write, or execute a file.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": False,
        "root": False,
    },

    "chown": {
        "meaning": "Changes file ownership.",
        "purpose": "Changes the owner or group associated with a file.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": False,
        "root": True,
    },

    "cat": {
        "meaning": "Displays file contents.",
        "purpose": "Reads and prints text from files.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "grep": {
        "meaning": "Searches text using patterns.",
        "purpose": "Finds matching text inside files or command output.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "find": {
        "meaning": "Searches for files and directories.",
        "purpose": "Locates filesystem objects based on conditions.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "echo": {
        "meaning": "Prints text to the terminal.",
        "purpose": "Displays text or data.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "clear": {
        "meaning": "Clears the terminal screen.",
        "purpose": "Removes visible terminal output from the screen.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "whoami": {
        "meaning": "Shows the current user.",
        "purpose": "Identifies the user running the shell.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "uname": {
        "meaning": "Displays system information.",
        "purpose": "Shows information about the operating system and kernel.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "ps": {
        "meaning": "Displays running processes.",
        "purpose": "Shows currently running processes.",
        "risk": "SAFE",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "kill": {
        "meaning": "Sends a signal to a process.",
        "purpose": "Stops or signals a running process.",
        "risk": "MEDIUM",
        "files": False,
        "delete": False,
        "network": False,
        "root": False,
    },

    "ping": {
        "meaning": "Tests network connectivity.",
        "purpose": "Sends network packets to check whether a host responds.",
        "risk": "LOW",
        "files": False,
        "delete": False,
        "network": True,
        "root": False,
    },

    "curl": {
        "meaning": "Transfers data using network protocols.",
        "purpose": "Connects to remote URLs and transfers data.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": True,
        "root": False,
    },

    "wget": {
        "meaning": "Downloads data from remote locations.",
        "purpose": "Retrieves files or resources over a network.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": True,
        "root": False,
    },

    "ssh": {
        "meaning": "Connects to a remote system securely.",
        "purpose": "Starts a remote shell session.",
        "risk": "MEDIUM",
        "files": False,
        "delete": False,
        "network": True,
        "root": False,
    },

    "git": {
        "meaning": "Manages Git repositories.",
        "purpose": "Downloads, updates, or manages source-code repositories.",
        "risk": "LOW",
        "files": True,
        "delete": False,
        "network": True,
        "root": False,
    },

    "python": {
        "meaning": "Runs Python code.",
        "purpose": "Executes a Python interpreter or script.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": True,
        "root": False,
    },

    "python3": {
        "meaning": "Runs Python 3 code.",
        "purpose": "Executes a Python 3 interpreter or script.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": True,
        "root": False,
    },

    "bash": {
        "meaning": "Runs commands through the Bash shell.",
        "purpose": "Executes shell commands or scripts.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": True,
        "root": False,
    },

    "sh": {
        "meaning": "Runs commands through a shell.",
        "purpose": "Executes shell commands or scripts.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": True,
        "root": False,
    },

    "sudo": {
        "meaning": "Requests elevated privileges.",
        "purpose": "Runs another command with administrator privileges when permitted.",
        "risk": "HIGH",
        "files": True,
        "delete": True,
        "network": True,
        "root": True,
    },

    "su": {
        "meaning": "Switches user identity.",
        "purpose": "Attempts to switch to another user account.",
        "risk": "HIGH",
        "files": True,
        "delete": True,
        "network": True,
        "root": True,
    },

    "apt": {
        "meaning": "Manages packages on Debian-based Linux systems.",
        "purpose": "Installs, removes, updates, or upgrades system packages.",
        "risk": "MEDIUM",
        "files": True,
        "delete": True,
        "network": True,
        "root": True,
    },

    "pkg": {
        "meaning": "Manages packages in Termux.",
        "purpose": "Installs, removes, or updates Termux packages.",
        "risk": "MEDIUM",
        "files": True,
        "delete": True,
        "network": True,
        "root": False,
    },

    "nmap": {
        "meaning": "Scans hosts and network services.",
        "purpose": "Performs network discovery and service enumeration.",
        "risk": "MEDIUM",
        "files": False,
        "delete": False,
        "network": True,
        "root": False,
    },

    "dd": {
        "meaning": "Copies and converts raw data.",
        "purpose": "Performs low-level data copying between input and output sources.",
        "risk": "CRITICAL",
        "files": True,
        "delete": True,
        "network": False,
        "root": True,
    },

    "mkfs": {
        "meaning": "Creates a filesystem.",
        "purpose": "Formats a storage device or partition with a filesystem.",
        "risk": "CRITICAL",
        "files": True,
        "delete": True,
        "network": False,
        "root": True,
    },

    "mount": {
        "meaning": "Attaches a filesystem.",
        "purpose": "Makes a filesystem accessible at a directory.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": False,
        "root": True,
    },

    "umount": {
        "meaning": "Detaches a mounted filesystem.",
        "purpose": "Unmounts a filesystem from the directory tree.",
        "risk": "MEDIUM",
        "files": True,
        "delete": False,
        "network": False,
        "root": True,
    },
}


def get_command(command):
    """Return information about a known command."""
    return COMMANDS.get(command)
