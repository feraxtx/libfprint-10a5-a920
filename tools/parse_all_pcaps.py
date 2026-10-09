import subprocess
import json
import glob
import os

pcaps = sorted(glob.glob("recordings/*.pcapng"))

for pcap in pcaps:
    print("\n" + "="*80)
    print(f"ANALYZING: {pcap}")
    print("="*80)
    
    # We query all packets with usbmon
    cmd = [
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "usb.device_address",
        "-e", "usb.endpoint_address",
        "-e", "usb.endpoint_address.direction",
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
    print(f"Total packets in pcap: {len(lines)}")
    
    for l in lines:
        parts = l.split("\t")
        def get_p(idx):
            return parts[idx] if len(parts) > idx else ""
        
        frame = get_p(0)
        t = float(get_p(1)) if get_p(1) else 0.0
        dev_addr = get_p(2)
        ep = get_p(3)
        ep_dir = get_p(4)
        xfer = get_p(5)
        urb_type = get_p(6) # 'S' (submit) or 'C' (complete)
        req_type = get_p(7)
        bReq = get_p(8)
        wVal = get_p(9)
        wIdx = get_p(10)
        wLen = get_p(11)
        capdata = get_p(12)
        frag = get_p(13)
        resp = get_p(14)
        
        data = capdata or frag or resp
        
        # Skip standard enumeration
        if req_type in ("0x00", "0x80") and bReq in ("0", "6", "9"):
            continue
        if xfer == "1":
            continue
            
        # If it's a control transfer submit
        if xfer == "0x02": # Control
            if urb_type == "'S'":
                print(f"[{frame:5s}] t={t:7.3f} CTRL-REQ dir={req_type} bReq={bReq:2s} wVal={wVal:6s} wIdx={wIdx:2s} wLen={wLen:4s} payload={data[:40]}{'...' if len(data)>40 else ''}")
            elif urb_type == "'C'":
                if data:
                    print(f"[{frame:5s}] t={t:7.3f} CTRL-RSP len={len(bytes.fromhex(data.replace(':','')))} data={data[:40]}{'...' if len(data)>40 else ''}")
        elif xfer == "0x03": # Bulk
            if urb_type == "'C'" and data:
                raw_bytes = bytes.fromhex(data.replace(':', ''))
                if len(raw_bytes) >= 12:
                    code = int.from_bytes(raw_bytes[0:4], "little")
                    ev_len = int.from_bytes(raw_bytes[4:8], "little")
                    unk = int.from_bytes(raw_bytes[8:12], "little")
                    print(f"[{frame:5s}] t={t:7.3f} BULK-IN  code=0x{code:02x} len={ev_len:5d} unk={unk:08x} total={len(raw_bytes):5d} data={raw_bytes[12:32].hex()}...")
                else:
                    print(f"[{frame:5s}] t={t:7.3f} BULK-IN  len={len(raw_bytes)} data={data[:40]}...")
