from commands import get_command
from rules import analyze_rules, higher_risk


# ============================================================
# X1CommandSentinel
# analyzer.py
# Command parsing and analysis engine
# ============================================================


OPERATORS = {
    "&&",
    "||",
    ";",
    "|",
    ">",
    ">>",
}


def tokenize(command_line):
    """
    Split a command line into tokens.

    This parser keeps shell operators as separate tokens.
    Commands are analyzed only and are NEVER executed.
    """

    tokens = []
    current = ""
    i = 0

    while i < len(command_line):

        char = command_line[i]

        # Handle whitespace
        if char.isspace():

            if current:
                tokens.append(current)
                current = ""

            i += 1
            continue

        # Two-character operators
        if i + 1 < len(command_line):

            two = command_line[i:i + 2]

            if two in {"&&", "||", ">>"}:

                if current:
                    tokens.append(current)
                    current = ""

                tokens.append(two)
                i += 2
                continue

        # One-character operators
        if char in {";", "|", ">"}:

            if current:
                tokens.append(current)
                current = ""

            tokens.append(char)
            i += 1
            continue

        # Normal character
        current += char
        i += 1

    if current:
        tokens.append(current)

    return tokens, None


def extract_operators(tokens):
    """
    Return all shell operators found in the token list.
    """

    return [
        token
        for token in tokens
        if token in OPERATORS
    ]


def remove_operators(tokens):
    """
    Remove shell operators from a token list.
    """

    return [
        token
        for token in tokens
        if token not in OPERATORS
    ]


def parse_structure(tokens):
    """
    Parse wrapper, command and arguments.

    Example:

        sudo apt install nmap

    becomes:

        wrapper = sudo
        command = apt
        args    = install nmap
    """

    clean = remove_operators(tokens)

    if not clean:

        return {
            "wrapper": None,
            "command": None,
            "args": [],
        }

    wrapper = None
    command_index = 0

    # Supported wrappers
    if clean[0] in {"sudo", "su"}:

        wrapper = clean[0]
        command_index = 1

    # No command after wrapper
    if command_index >= len(clean):

        return {
            "wrapper": wrapper,
            "command": None,
            "args": [],
        }

    command = clean[command_index]

    args = clean[command_index + 1:]

    return {
        "wrapper": wrapper,
        "command": command,
        "args": args,
    }


def split_command_chain(tokens):
    """
    Split a command line into individual command segments.

    Example:

        cd test && rm file.txt

    becomes:

        cd test
        rm file.txt

    The operator connecting each command is preserved.
    """

    segments = []

    current = []

    # Operator that connects the current segment
    next_operator = None

    for token in tokens:

        if token in OPERATORS:

            if current:

                segments.append({
                    "tokens": current,
                    "operator": next_operator,
                })

                current = []

            next_operator = token

        else:

            current.append(token)

    # Last segment
    if current:

        segments.append({
            "tokens": current,
            "operator": next_operator,
        })

    return segments


def analyze_single(tokens, operators=None):
    """
    Analyze one individual command.

    This function never executes the command.
    """

    if operators is None:
        operators = []

    structure = parse_structure(tokens)

    command = structure["command"]

    # Empty command
    if not command:

        return {
            "recognized": False,
            "structure": structure,
            "risk": "SAFE",
            "warnings": [],
            "flags": [],
            "impact": {
                "files": False,
                "delete": False,
                "network": False,
                "root": False,
            },
        }

    # Look up command database
    info = get_command(command)

    # Unknown command
    if info is None:

        rule_result = analyze_rules(
            command,
            tokens,
            operators
        )

        return {
            "recognized": False,
            "structure": structure,
            "risk": rule_result["risk"],
            "warnings": [
                "Command not found in the X1CommandSentinel database."
            ] + rule_result["warnings"],
            "flags": [
                "UNKNOWN_COMMAND"
            ] + rule_result["flags"],
            "impact": {
                "files": False,
                "delete": False,
                "network": False,
                "root": False,
            },
        }

    # Rule engine
    rule_result = analyze_rules(
        command,
        tokens,
        operators
    )

    risk = rule_result["risk"]

    # sudo / su automatically raises privilege risk
    if structure["wrapper"] in {"sudo", "su"}:

        risk = higher_risk(
            risk,
            "HIGH"
        )

    return {
        "recognized": True,
        "structure": structure,
        "risk": risk,
        "warnings": rule_result["warnings"],
        "flags": rule_result["flags"],
        "impact": {
            "files": info.get("files", False),
            "delete": info.get("delete", False),
            "network": info.get("network", False),
            "root": info.get("root", False),
        },
    }


def analyze(command_line):
    """
    Main X1CommandSentinel analysis function.

    IMPORTANT:
    The supplied command is NEVER executed.
    """

    # --------------------------------------------------------
    # Empty input
    # --------------------------------------------------------

    if not command_line or not command_line.strip():

        return {
            "valid": False,
            "raw": command_line,
            "tokens": [],
            "operators": [],
            "segments": [],
            "chain_risk": "SAFE",
            "chain_warnings": [],
            "chain_flags": [],
        }

    # --------------------------------------------------------
    # Tokenization
    # --------------------------------------------------------

    tokens, error = tokenize(command_line)

    if error:

        return {
            "valid": False,
            "raw": command_line,
            "tokens": [],
            "operators": [],
            "segments": [],
            "chain_risk": "SAFE",
            "chain_warnings": [
                f"Syntax error: {error}"
            ],
            "chain_flags": [
                "INVALID_SYNTAX"
            ],
        }

    # --------------------------------------------------------
    # Operators
    # --------------------------------------------------------

    operators = extract_operators(tokens)

    # --------------------------------------------------------
    # Split command chain
    # --------------------------------------------------------

    chain = split_command_chain(tokens)

    analyzed_segments = []

    chain_risk = "SAFE"

    chain_warnings = []

    chain_flags = []

    # --------------------------------------------------------
    # Analyze every segment
    # --------------------------------------------------------

    for index, segment in enumerate(chain):

        segment_tokens = segment["tokens"]

        connecting_operator = segment["operator"]

        # Operators that belong to this command.
        #
        # The operator connecting this command to the previous
        # command is preserved so rules can see the chain.
        segment_operators = []

        if connecting_operator:
            segment_operators.append(
                connecting_operator
            )

        # Also inspect the operator after this segment.
        if index + 1 < len(chain):

            next_operator = chain[index + 1]["operator"]

            if next_operator:
                segment_operators.append(
                    next_operator
                )

        result = analyze_single(
            segment_tokens,
            segment_operators
        )

        result["operator_after"] = connecting_operator

        analyzed_segments.append(result)

        # Update overall risk
        chain_risk = higher_risk(
            chain_risk,
            result["risk"]
        )

        # Collect warnings
        chain_warnings.extend(
            result["warnings"]
        )

        # Collect flags
        chain_flags.extend(
            result["flags"]
        )

    # --------------------------------------------------------
    # Complete-chain analysis
    # --------------------------------------------------------

    all_commands = []

    for segment in chain:

        structure = parse_structure(
            segment["tokens"]
        )

        command = structure["command"]

        if command:

            all_commands.append(command)

    # --------------------------------------------------------
    # Detect curl/wget | bash/sh
    # --------------------------------------------------------

    has_download = any(
        command in {"curl", "wget"}
        for command in all_commands
    )

    has_shell = any(
        command in {"bash", "sh"}
        for command in all_commands
    )

    has_pipe = "|" in operators

    if has_download and has_shell and has_pipe:

        chain_risk = higher_risk(
            chain_risk,
            "CRITICAL"
        )

        if "REMOTE_CODE_EXECUTION" not in chain_flags:

            chain_flags.append(
                "REMOTE_CODE_EXECUTION"
            )

        chain_warnings.append(
            "Remote data is being piped directly into a shell."
        )

    # --------------------------------------------------------
    # Detect sudo + rm
    # --------------------------------------------------------

    if (
        "sudo" in all_commands
        and "rm" in all_commands
    ):

        chain_risk = higher_risk(
            chain_risk,
            "CRITICAL"
        )

        if "PRIVILEGED_FILE_DELETION" not in chain_flags:

            chain_flags.append(
                "PRIVILEGED_FILE_DELETION"
            )

        chain_warnings.append(
            "A privileged command chain contains file deletion."
        )

    # --------------------------------------------------------
    # Detect sudo + dd/mkfs
    # --------------------------------------------------------

    dangerous_storage = {
        "dd",
        "mkfs",
    }

    has_storage_operation = any(
        command in dangerous_storage
        for command in all_commands
    )

    if (
        "sudo" in all_commands
        and has_storage_operation
    ):

        chain_risk = higher_risk(
            chain_risk,
            "CRITICAL"
        )

        if "PRIVILEGED_STORAGE_OPERATION" not in chain_flags:

            chain_flags.append(
                "PRIVILEGED_STORAGE_OPERATION"
            )

        chain_warnings.append(
            "A privileged chain contains a storage-level operation."
        )

    # --------------------------------------------------------
    # Build final result
    # --------------------------------------------------------

    result = {
        "valid": True,
        "raw": command_line,
        "tokens": tokens,
        "operators": operators,
        "segments": analyzed_segments,
        "chain_risk": chain_risk,
        "chain_warnings": list(
            dict.fromkeys(chain_warnings)
        ),
        "chain_flags": list(
            dict.fromkeys(chain_flags)
        ),
    }

    # --------------------------------------------------------
    # Compatibility fields for single-command UI
    # --------------------------------------------------------

    if len(analyzed_segments) == 1:

        single = analyzed_segments[0]

        result["recognized"] = single["recognized"]

        result["structure"] = single["structure"]

        result["risk"] = single["risk"]

        result["warnings"] = single["warnings"]

        result["flags"] = single["flags"]

        result["impact"] = single["impact"]

    return result
