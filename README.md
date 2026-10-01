X1CommandSentinel

X1CommandSentinel is a lightweight command-line analyzer for Linux, Kali Linux, and Termux.

It analyzes shell commands without executing them and provides information about their structure, potential impact, and security risk.

«X1CommandSentinel does not execute commands. It only analyzes them.»

---

Features

- Linux / Kali Linux / Termux command analysis
- Command structure detection
- Command chain detection
- Supports:
  - "&&"
  - "||"
  - ";"
  - "|"
- Risk classification:
  - "SAFE"
  - "LOW"
  - "MEDIUM"
  - "HIGH"
  - "CRITICAL"
- File operation detection
- File deletion detection
- Network activity detection
- Root / elevated privilege detection
- Dangerous command combination detection
- Security warnings and analysis flags
- Clean terminal interface
- Modular architecture
- Built with Python

---

Requirements

- Python 3
- Git

Check your Python version:

python3 --version

---

Installation

1. Clone the repository

git clone https://github.com/X1-starr/X1CommandSentinel.git

2. Enter the project directory

cd X1CommandSentinel

3. Run X1CommandSentinel

python3 x1sentinel.py

No external Python packages are required for the current version.

---

Usage

After starting X1CommandSentinel, enter a Linux command at the prompt:

X1CommandSentinel > pwd

The analyzer will inspect the command without executing it.

To exit the program:

exit

or:

quit

---

Examples

Safe Command

Input:

pwd

Example result:

ANALYSIS

Command : pwd
Type    : pwd
Risk    : SAFE

Impact:
Files   NO
Delete  NO
Network NO
Root    NO

---

Command Chain

Input:

cd test && rm file.txt

Example result:

COMMAND CHAIN

1. cd test
   &&

2. rm file.txt

Risk : HIGH

Impact:
Files   YES
Delete  YES
Network NO
Root    NO

Flags:
• COMMAND_CHAIN
• FILE_DELETION

---

Network + Shell Execution

Input:

curl https://example.com | bash

Example result:

COMMAND CHAIN

1. curl https://example.com
   |

2. bash

Risk : CRITICAL

Impact:
Files   YES
Delete  NO
Network YES
Root    NO

Flags:
• NETWORK_ACCESS
• PIPE_EXECUTION
• SHELL_EXECUTION
• REMOTE_CODE_EXECUTION

Warnings:
! Network data is being piped into another command.
! The command executes shell instructions or a shell script.
! Remote data is being piped directly into a shell.

---

Risk Levels

Level| Description
"SAFE"| No significant risk detected
"LOW"| Minor or limited impact
"MEDIUM"| Potentially sensitive operation
"HIGH"| Dangerous operation detected
"CRITICAL"| Extremely dangerous operation or combination detected

Risk levels are based on the rules implemented in the current version and are not a guarantee that a command is safe.

---

Project Structure

X1CommandSentinel/
├── analyzer.py
├── commands.py
├── rules.py
├── x1sentinel.py
└── README.md

"x1sentinel.py"

Main terminal interface and application entry point.

"analyzer.py"

Parses commands, detects command chains, and performs the main analysis.

"commands.py"

Contains the command database and basic information about supported commands.

"rules.py"

Contains the security rules and risk-analysis engine.

"README.md"

Project documentation.

---

How It Works

X1CommandSentinel follows a simple analysis pipeline:

User Input
    │
    ▼
Command Parser
    │
    ▼
Structure Analysis
    │
    ▼
Security Rules
    │
    ▼
Risk Analysis
    │
    ▼
Warnings + Flags + Impact
    │
    ▼
Terminal Output

The command is analyzed as text and is not executed by the program.

---

Security Note

X1CommandSentinel is an educational and defensive security tool.

It is designed to help users understand Linux commands and identify potentially dangerous command combinations before execution.

Always review commands carefully before executing them on a real system.

---

Development

The project uses a modular architecture so new analysis capabilities can be added without rewriting the entire application.

Planned Improvements

Argument Analysis
Flag Detection
Target / Path Analysis
More Command Definitions
Improved Risk Detection
Additional Security Rules
UI Improvements
Bug Fixes

---

Version

v1.0.0

---

Author

X1

GitHub:

https://github.com/X1-starr

Repository:

https://github.com/X1-starr/X1CommandSentinel

---

License

This project is provided for educational and defensive security purposes.
