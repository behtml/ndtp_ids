"""
Example usage of the NDTP IDS packet collector

This example demonstrates how to use the packet collector module
to capture and process network traffic.
"""

import sys
import os

# Add src to path for imports when running standalone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ndtp_ids.packet_collector import start_collector


def main():
    """
    Main function to start the packet collector
    """
    # Check if interface is provided as command line argument
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        # Default interface
        interface = "eth0"
        print(f"Usage: {sys.argv[0]} <interface>")
        print(f"Using default interface: {interface}")
        print()
        print("Common interfaces:")
        print("  Linux: eth0, wlan0, enp0s3")
        print("  Windows: 'Ethernet', 'Wi-Fi'")
        print("  macOS: en0, en1")
        print()
    
    try:
        # Start collecting packets
        start_collector(interface=interface)
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo/administrator privileges:")
        print(f"  sudo python3 {sys.argv[0]} {interface}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet collector...")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
