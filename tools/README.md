# FPC 10a5:a920 Reverse Engineering Tools

This folder contains the Python analysis and reverse engineering scripts developed to reverse-engineer and verify the USB protocol for the FPC Disum 10a5:a920 fingerprint sensor found in Honor/Huawei laptops.

## Tools Overview

* **`derive_enclave_key.py`**: Extracts the obfuscated key tables from `fpc_enclave.dll`, simulates the rotation and XOR loop to reconstruct the PBKDF2 password, and derives the root sealing key.
* **`extract_tls_records.py`**: Extracts raw TLS records and handshake messages from Wireshark USB capture logs.
* **`analyze_pcap.py`**: Inspects USB control transfers and bulk packets using `tshark` to trace command sequence, endpoints, and data payloads.
* **`reassemble_flow.py`**: Reassembles complete USB bulk event framing and maps the full init, arm, capture, and handshake sequence.
* **`parse_all_pcaps.py`**: Batch processes Wireshark recordings (`.pcapng`) to verify repeatability of command patterns.
* **`test_tls_psk.py`**: Prototype TLS 1.2 PSK client in Python validating cipher selection and key handshake against captured sensor flows.
