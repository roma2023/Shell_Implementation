# Tiny Shell (tsh)

## Overview
Tiny Shell (tsh) is a minimalistic Linux shell designed as part of the Shell Lab for 15-213/15-513, Summer 2023. This project helps students become familiar with process control and signaling through the implementation of a simple command-line interpreter. The shell supports job control, signal handling, and I/O redirection, providing a hands-on approach to understanding the operations of typical Unix shells.

## Features
- **Job Control**: Manage jobs in the foreground and background, allowing for continued interaction with the shell while processes run asynchronously.
- **Signal Handling**: Implements custom handlers for `SIGINT`, `SIGCHLD`, and `SIGTSTP`, enhancing control over process interruptions and completions.
- **I/O Redirection**: Redirect input and output streams for commands, facilitating advanced data management during command execution.
- **Built-in Commands**: Supports basic built-in commands such as `quit`, `jobs`, `bg`, and `fg`, allowing for direct manipulation of job execution.

## Getting Started

### Prerequisites
- **Linux environment**
- **GCC compiler**

### Installation
1. **Clone the repository** on a class shark machine:
    ```bash
    git clone https://github.com/cmu15213-m23/tshlab-m23-<USERNAME>.git
    ```
2. **Navigate to the project directory** and compile the shell:
    ```bash
    cd tshlab-m23-<USERNAME>
    make
    ```

### Running the Shell
- **Start the shell** by running:
    ```bash
    ./tsh
    ```
- You can now enter commands at the `tsh>` prompt.

## Usage
- **Execute commands** like any other shell:
    ```bash
    tsh> /bin/ls
    ```
- **Run jobs in the background**:
    ```bash
    tsh> /usr/bin/sleep 5 &
    ```
- **Use job control commands**:
    ```bash
    tsh> jobs
    tsh> bg %1
    tsh> fg %1
    ```

## Development and Testing
- **To test the shell**, use the provided trace files with the `runtrace` tool as described in the lab documentation.

## Contributions
- **Feedback and Suggestions**: While this is an individual project for educational purposes, feedback and suggestions for improvements are welcome.

## License
- **Distributed under the MIT License.** See `LICENSE` file for more information.

## Acknowledgements
- **Carnegie Mellon University** instructors and teaching staff for providing the educational resources and support for this project.
