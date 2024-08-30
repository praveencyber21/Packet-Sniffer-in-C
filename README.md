# Packet Sniffer in C

## Overview

This project is a simple packet sniffer written in C. It captures and analyzes network packets transmitted over an Ethernet network interface. The sniffer can identify and process various types of packets, including TCP, UDP, ICMP, and more.

## Features

- **Capture Packets**: The sniffer captures all incoming and outgoing packets on a specified network interface.
- **Protocol Analysis**: The sniffer identifies the protocol type (TCP, UDP, ICMP) and processes the packet accordingly.
- **Packet Details**: Extracts and displays detailed information about the captured packets, including IP headers, TCP/UDP headers, and data payloads.
- **Real-Time Monitoring**: Continuously captures and analyzes packets in real-time until the program is terminated.

## Requirements

- **Operating System**: Linux (The code uses raw sockets which are specific to Unix-like operating systems)
- **Compiler**: GCC (GNU Compiler Collection)
- **Privileges**: Root privileges (required for creating raw sockets)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/praveencyber21/Packet-Sniffer-in-C
   cd Packet-Sniffer-in-C
   ```

2. **Compile the code**:
   ```bash
   gcc -o sniffer sniffer.c
   ```

3. **Run the program**:
   ```bash
   sudo ./sniffer
   ```

## Usage

1. **Capture and Analyze Packets**:
   - The program will start capturing packets as soon as it is run. It will continuously display information about the captured packets until you manually stop it.

2. **Viewing Packet Details**:
   - Packet details are printed to the console in real-time, including the source and destination IP addresses, protocol type, and payload information.

## Code Structure

- `sniffer.c`: The main source code file that contains all the logic for capturing and analyzing network packets.

## Example Output


## Disclaimer

This tool is for educational purposes only. Use it responsibly and only on networks where you have permission to monitor traffic.

## Contributing

If you have any improvements or suggestions, feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.





