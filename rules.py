# ============================================================
# X1CommandSentinel
# Risk Rules Engine
# Created by X1
# ============================================================

RISK_ORDER = {
    "SAFE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def higher_risk(current, new):
    """Return the higher of two risk levels."""
    if RISK_ORDER.get(new, 0) > RISK_ORDER.get(current, 0):
        return new
    return current


def analyze_rules(command, tokens, operators=None):
    """
    Analyze a parsed command without executing it.

    Returns:
        {
            "risk": str,
            "warnings": list[str],
            "flags": list[str],
        }
    """

    operators = operators or []

    risk = "SAFE"
    warnings = []
    flags = []

    token_set = set(tokens)
    command_line = " ".join(tokens)

    # --------------------------------------------------------
    # SUDO / ROOT PRIVILEGES
    # --------------------------------------------------------

    if "sudo" in token_set:
        risk = higher_risk(risk, "HIGH")
        flags.append("ELEVATED_PRIVILEGES")
        warnings.append(
            "The command requests elevated privileges."
        )

    if "su" in token_set:
        risk = higher_risk(risk, "HIGH")
        flags.append("USER_SWITCH")
        warnings.append(
            "The command attempts to switch user identity."
        )

    # --------------------------------------------------------
    # FILE DELETION
    # --------------------------------------------------------

    if command == "rm":
        risk = higher_risk(risk, "HIGH")
        flags.append("FILE_DELETION")

        warnings.append(
            "The command can permanently delete files or directories."
        )

        if "-r" in token_set or "-R" in token_set:
            risk = higher_risk(risk, "HIGH")
            flags.append("RECURSIVE_DELETE")
            warnings.append(
                "Recursive deletion is enabled."
            )

        if "-f" in token_set:
            risk = higher_risk(risk, "HIGH")
            flags.append("FORCE_MODE")
            warnings.append(
                "Force mode can suppress confirmation prompts."
            )

        if "-rf" in token_set or "-fr" in token_set:
            risk = higher_risk(risk, "HIGH")
            flags.append("FORCE_RECURSIVE_DELETE")

    # --------------------------------------------------------
    # DANGEROUS PATHS
    # --------------------------------------------------------

    dangerous_paths = {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/root",
        "/sbin",
        "/sys",
        "/usr",
        "/var",
    }

    for token in tokens:
        if token in dangerous_paths:
            risk = higher_risk(risk, "CRITICAL")
            flags.append("SYSTEM_PATH")
            warnings.append(
                f"The command references a sensitive system path: {token}"
            )

    # --------------------------------------------------------
    # CHMOD
    # --------------------------------------------------------

    if command == "chmod":
        flags.append("PERMISSION_CHANGE")

        if "777" in tokens:
            risk = higher_risk(risk, "HIGH")
            flags.append("WORLD_WRITABLE")
            warnings.append(
                "Permission mode 777 grants read, write, and execute access to everyone."
            )
        else:
            risk = higher_risk(risk, "MEDIUM")
            warnings.append(
                "The command changes filesystem permissions."
            )

    # --------------------------------------------------------
    # CHOWN
    # --------------------------------------------------------

    if command == "chown":
        risk = higher_risk(risk, "MEDIUM")
        flags.append("OWNERSHIP_CHANGE")
        warnings.append(
            "The command changes file ownership."
        )

    # --------------------------------------------------------
    # NETWORK COMMANDS
    # --------------------------------------------------------

    network_commands = {
        "curl",
        "wget",
        "ssh",
        "ping",
        "nmap",
        "git",
    }

    if command in network_commands:
        flags.append("NETWORK_ACCESS")

    # --------------------------------------------------------
    # DOWNLOAD + EXECUTION
    # --------------------------------------------------------

    if command in {"curl", "wget"}:
        risk = higher_risk(risk, "MEDIUM")

        if "|" in operators:
            risk = higher_risk(risk, "HIGH")
            flags.append("PIPE_EXECUTION")
            warnings.append(
                "Network data is being piped into another command."
            )

        if "bash" in token_set or "sh" in token_set:
            risk = higher_risk(risk, "HIGH")
            flags.append("REMOTE_SHELL_EXECUTION")
            warnings.append(
                "The command combines network retrieval with shell execution."
            )

    # --------------------------------------------------------
    # SHELL EXECUTION
    # --------------------------------------------------------

    if command in {"bash", "sh"}:
        risk = higher_risk(risk, "MEDIUM")
        flags.append("SHELL_EXECUTION")
        warnings.append(
            "The command executes shell instructions or a shell script."
        )

    # --------------------------------------------------------
    # PYTHON EXECUTION
    # --------------------------------------------------------

    if command in {"python", "python3"}:
        risk = higher_risk(risk, "MEDIUM")
        flags.append("CODE_EXECUTION")
        warnings.append(
            "The command executes Python code or a Python script."
        )

    # --------------------------------------------------------
    # PACKAGE MANAGEMENT
    # --------------------------------------------------------

    if command in {"apt", "pkg"}:
        risk = higher_risk(risk, "MEDIUM")
        flags.append("PACKAGE_MANAGEMENT")

        package_actions = {
            "install": "PACKAGE_INSTALL",
            "remove": "PACKAGE_REMOVAL",
            "purge": "PACKAGE_PURGE",
            "update": "PACKAGE_UPDATE",
            "upgrade": "PACKAGE_UPGRADE",
        }

        for action, flag in package_actions.items():
            if action in token_set:
                flags.append(flag)

                if action in {"remove", "purge"}:
                    risk = higher_risk(risk, "HIGH")
                    warnings.append(
                        f"The package manager may remove software: {action}"
                    )
                else:
                    warnings.append(
                        f"The package manager performs the '{action}' operation."
                    )

    # --------------------------------------------------------
    # NMAP
    # --------------------------------------------------------

    if command == "nmap":
        risk = higher_risk(risk, "MEDIUM")
        flags.append("NETWORK_SCANNING")

        warnings.append(
            "The command performs network scanning or service discovery."
        )

    # --------------------------------------------------------
    # DD
    # --------------------------------------------------------

    if command == "dd":
        risk = higher_risk(risk, "CRITICAL")
        flags.append("RAW_DISK_OPERATION")
        warnings.append(
            "The command can perform low-level raw data operations."
        )

    # --------------------------------------------------------
    # MKFS
    # --------------------------------------------------------

    if command == "mkfs":
        risk = higher_risk(risk, "CRITICAL")
        flags.append("FILESYSTEM_FORMAT")
        warnings.append(
            "The command can create a filesystem and may destroy existing data."
        )

    # --------------------------------------------------------
    # MOUNT / UMOUNT
    # --------------------------------------------------------

    if command in {"mount", "umount"}:
        risk = higher_risk(risk, "MEDIUM")
        flags.append("FILESYSTEM_MOUNT")
        warnings.append(
            "The command changes filesystem mount state."
        )

    # --------------------------------------------------------
    # PROCESS CONTROL
    # --------------------------------------------------------

    if command == "kill":
        risk = higher_risk(risk, "MEDIUM")
        flags.append("PROCESS_CONTROL")
        warnings.append(
            "The command sends a signal to a running process."
        )

    # --------------------------------------------------------
    # REDIRECTION
    # --------------------------------------------------------

    if ">" in operators:
        risk = higher_risk(risk, "MEDIUM")
        flags.append("OUTPUT_REDIRECTION")
        warnings.append(
            "Output is redirected and may overwrite a file."
        )

    if ">>" in operators:
        risk = higher_risk(risk, "LOW")
        flags.append("OUTPUT_APPEND")
        warnings.append(
            "Output is appended to a file."
        )

    # --------------------------------------------------------
    # COMMAND CHAINS
    # --------------------------------------------------------

    if "&&" in operators:
        flags.append("COMMAND_CHAIN")
        warnings.append(
            "Multiple commands are connected with &&."
        )

    if "||" in operators:
        flags.append("CONDITIONAL_CHAIN")
        warnings.append(
            "Commands are connected with ||."
        )

    if ";" in operators:
        risk = higher_risk(risk, "LOW")
        flags.append("COMMAND_CHAIN")
        warnings.append(
            "Multiple commands are separated by ';'."
        )

    # --------------------------------------------------------
    # DANGEROUS COMBINATIONS
    # --------------------------------------------------------

    if "sudo" in token_set and command == "rm":
        risk = higher_risk(risk, "CRITICAL")
        flags.append("SUDO_DELETE")
        warnings.append(
            "Elevated privileges are combined with file deletion."
        )

    if "sudo" in token_set and command in {"dd", "mkfs"}:
        risk = higher_risk(risk, "CRITICAL")
        flags.append("PRIVILEGED_DISK_OPERATION")
        warnings.append(
            "Elevated privileges are combined with a low-level storage operation."
        )

    if (
        command in {"curl", "wget"}
        and "|" in operators
        and ("bash" in token_set or "sh" in token_set)
    ):
        risk = higher_risk(risk, "CRITICAL")
        flags.append("REMOTE_CODE_EXECUTION")
        warnings.append(
            "Remote data is being piped directly into a shell."
        )

    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return {
        "risk": risk,
        "warnings": list(dict.fromkeys(warnings)),
        "flags": list(dict.fromkeys(flags)),
    }
