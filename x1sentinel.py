import os

from analyzer import analyze


RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
WHITE = "\033[97m"
GRAY = "\033[90m"


WIDTH = 54


RISK_COLORS = {
    "SAFE": GREEN,
    "LOW": GREEN,
    "MEDIUM": YELLOW,
    "HIGH": RED,
    "CRITICAL": RED,
}


def color(text, color_code):
    return f"{color_code}{text}{RESET}"


def clear_screen():
    os.system("clear")


def header():
    print()
    print("╭" + "─" * WIDTH + "╮")
    print("│" + "X1 COMMAND SENTINEL".center(WIDTH) + "│")
    print("│" + "Command Analyzer  •  v1.0".center(WIDTH) + "│")
    print("╰" + "─" * WIDTH + "╯")
    print()


def box(title, lines):
    print(f"┌─ {title} " + "─" * max(1, WIDTH - len(title) - 5) + "┐")

    for line in lines:
        print("│ " + line[:WIDTH - 2].ljust(WIDTH - 2) + "│")

    print("└" + "─" * WIDTH + "┘")


def risk_text(risk):
    risk_color = RISK_COLORS.get(risk, WHITE)
    return color(risk, risk_color)


def yes_no(value):
    return color(
        "YES" if value else "NO",
        GREEN if not value else YELLOW
    )


def format_args(args):
    if not args:
        return ""

    return " ".join(args)


def show_single(result):
    structure = result["structure"]

    wrapper = structure["wrapper"]
    command = structure["command"]
    args = format_args(structure["args"])

    full_command = command

    if args:
        full_command += " " + args

    if wrapper:
        full_command = wrapper + " " + full_command

    info = [
        f"Command : {full_command}",
        f"Type    : {command}",
        f"Risk    : {risk_text(result['risk'])}",
    ]

    box("ANALYSIS", info)

    impact = result["impact"]

    print(
        "Impact: "
        f"Files {yes_no(impact['files'])}  •  "
        f"Delete {yes_no(impact['delete'])}  •  "
        f"Network {yes_no(impact['network'])}  •  "
        f"Root {yes_no(impact['root'])}"
    )

    if result["flags"]:
        print()
        print("Flags:")

        for flag in result["flags"]:
            print(f"  • {flag}")

    if result["warnings"]:
        print()
        print(color("Warnings:", YELLOW))

        for warning in result["warnings"]:
            print(f"  ! {warning}")

def show_chain(result):
    segments = result["segments"]

    lines = []

    for index, segment in enumerate(segments, start=1):

        structure = segment["structure"]

        command = structure["command"] or "?"

        args = format_args(
            structure["args"]
        )

        command_text = command

        if args:
            command_text += " " + args

        lines.append(
            f"{index}. {command_text}"
        )

        # Show the operator BETWEEN commands.
        if index < len(segments):

            operator = segments[index].get(
                "operator_after"
            )

            if operator:
                lines.append(
                    f"   {operator}"
                )

    lines.append("")

    lines.append(
        f"Risk : {risk_text(result['chain_risk'])}"
    )

    box(
        "COMMAND CHAIN",
        lines
    )

    # --------------------------------------------------------
    # Combined impact
    # --------------------------------------------------------

    files = False
    deleted = False
    network = False
    root = False

    for segment in segments:

        impact = segment["impact"]

        files = (
            files
            or impact["files"]
        )

        deleted = (
            deleted
            or impact["delete"]
        )

        network = (
            network
            or impact["network"]
        )

        root = (
            root
            or impact["root"]
        )

    print(
        "Impact: "
        f"Files {yes_no(files)}  •  "
        f"Delete {yes_no(deleted)}  •  "
        f"Network {yes_no(network)}  •  "
        f"Root {yes_no(root)}"
    )

    # --------------------------------------------------------
    # Flags
    # --------------------------------------------------------

    flags = list(
        result["chain_flags"]
    )

    for segment in segments:

        for flag in segment["flags"]:

            if flag not in flags:

                flags.append(flag)

    if flags:

        print()
        print("Flags:")

        for flag in flags:

            print(
                f"  • {flag}"
            )

    # --------------------------------------------------------
    # Warnings
    # --------------------------------------------------------

    warnings = list(
        result["chain_warnings"]
    )

    for segment in segments:

        for warning in segment["warnings"]:

            if warning not in warnings:

                warnings.append(
                    warning
                )

    if warnings:

        print()
        print("Warnings:")

        for warning in warnings:

            print(
                f"  ! {warning}"
            )

def show_result(result):
    print()

    if not result["valid"]:
        box(
            "INPUT ERROR",
            result["chain_warnings"]
        )
        return

    if len(result["segments"]) > 1:
        show_chain(result)
    else:
        show_single(result)


def footer():
    print()
    print(
        color(
            "─" * WIDTH,
            GRAY
        )
    )
    print(
        color(
            "X1CommandSentinel • Analysis only • Never executes commands",
            GRAY
        )
    )
    print()


def main():

    while True:

        clear_screen()
        header()

        print(
            color(
                "Enter a command to analyze.",
                WHITE
            )
        )

        print(
            color(
                "Type 'exit' or 'quit' to close.",
                GRAY
            )
        )

        print()

        try:
            command = input(
                color(
                    "X1CommandSentinel > ",
                    CYAN
                )
            ).strip()

        except (KeyboardInterrupt, EOFError):
            print()
            break

        if command.lower() in {"exit", "quit"}:
            print()
            print(color("X1CommandSentinel closed.", GRAY))
            break

        if not command:
            continue

        result = analyze(command)

        show_result(result)
        footer()

        input(
            color(
                "Press Enter to continue...",
                GRAY
            )
        )


if __name__ == "__main__":
    main()
