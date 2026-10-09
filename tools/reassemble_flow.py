import subprocess
import json
import glob
import os

pcaps = sorted(glob.glob("recordings/*.pcapng"))

def reassemble_events(pcap):
    print("\n" + "="*80)
    print(f"REASSEMBLED PROTOCOL FLOW: {pcap}")
    print("="*80)
    
    cmd = [
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "usb.device_address",
        "-e", "usb.endpoint_address",
        "-e", "usb.transfer_type",
        "-e", "usb.urb_type",
        "-e", "usb.bmRequestType",
        "-e", "usb.setup.bRequest",
        "-e", "usb.setup.wValue",
        "-e", "usb.setup.wIndex",
        "-e", "usb.setup.wLength",
        "-e", "usb.capdata",
        "-e", "usb.data_fragment",
        "-e", "usb.control.Response",
        "-E", "separator=\t"
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate()
    
    lines = [l for l in out.strip().split("\n") if l]
    
    bulk_buffer = bytearray()
    expected_event_len = 0
    cur_event_code = 0
    cur_event_unk = 0
    cur_event_frame = ""
    cur_event_time = 0.0

    for l in lines:
        parts = l.split("\t")
        def get_p(idx):
            return parts[idx] if len(parts) > idx else ""
        
        frame = get_p(0)
        t = float(get_p(1)) if get_p(1) else 0.0
        xfer = get_p(4)
        urb_type = get_p(5)
        req_type = get_p(6)
        bReq = get_p(7)
        wVal = get_p(8)
        wIdx = get_p(9)
        wLen = get_p(10)
        capdata = get_p(11)
        frag = get_p(12)
        resp = get_p(13)
        data = capdata or frag or resp
        
        # Skip USB hub/standard requests
        if req_type in ("0x00", "0x80") and bReq in ("0", "6", "9"):
            continue
        if req_type in ("0x23", "0xa3"): # hub requests
            continue
        if xfer == "1":
            continue

        if xfer == "0x02": # Control
            if urb_type == "'S'":
                # Print control request
                raw = bytes.fromhex(data.replace(':', '')) if data else b""
                print(f"[{frame:5s}] t={t:7.3f} CTRL-REQ  bReq=0x{int(bReq):02x}({bReq:2s}) wVal={wVal:6s} wLen={wLen:4s} payload({len(raw)})={raw.hex()[:50]}")
            elif urb_type == "'C'":
                raw = bytes.fromhex(data.replace(':', '')) if data else b""
                if raw:
                    print(f"[{frame:5s}] t={t:7.3f} CTRL-RSP  len={len(raw):4d} data={raw.hex()[:50]}")
        elif xfer == "0x03" and urb_type == "'C'": # Bulk IN completion
            raw = bytes.fromhex(data.replace(':', '')) if data else b""
            if not raw:
                continue
            if len(bulk_buffer) == 0:
                cur_event_frame = frame
                cur_event_time = t
                if len(raw) >= 12:
                    cur_event_code = int.from_bytes(raw[0:4], "little")
                    expected_event_len = int.from_bytes(raw[4:8], "little")
                    cur_event_unk = int.from_bytes(raw[8:12], "little")
                    bulk_buffer.extend(raw)
                else:
                    print(f"[{frame:5s}] t={t:7.3f} BULK-IN  raw small: {raw.hex()}")
                    continue
            else:
                bulk_buffer.extend(raw)
            
            # Check if event is complete (expected_event_len is usually the total event size including header 12 bytes)
            if len(bulk_buffer) >= expected_event_len:
                event_payload = bulk_buffer[12:expected_event_len]
                print(f"[{cur_event_frame:5s}] t={cur_event_time:7.3f} EVT 0x{cur_event_code:02x} len={expected_event_len:5d} unk={cur_event_unk:08x} payload({len(event_payload)})={event_payload[:32].hex()}...")
                leftover = bulk_buffer[expected_event_len:]
                bulk_buffer = bytearray(leftover)

for p in pcaps:
    reassemble_events(p)
