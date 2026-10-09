import sys
import subprocess
import json

def analyze_pcap(filename):
    print(f"=== ANALYZING {filename} ===")
    cmd = [
        "tshark", "-r", filename,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "usb.endpoint_address",
        "-e", "usb.endpoint_address.direction",
        "-e", "usb.transfer_type",
        "-e", "usb.bmRequestType",
        "-e", "usb.setup.bRequest",
        "-e", "usb.setup.wValue",
        "-e", "usb.setup.wIndex",
        "-e", "usb.setup.wLength",
        "-e", "usb.capdata",
        "-e", "usb.data_fragment",
        "-E", "separator=\t"
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    lines = out.strip().split("\n")
    print(f"Total lines: {len(lines)}")
    for line in lines:
        if not line:
            continue
        parts = line.split("\t")
        frame_num = parts[0]
        time_rel = parts[1]
        ep = parts[2] if len(parts) > 2 else ""
        direction = parts[3] if len(parts) > 3 else ""
        xfer_type = parts[4] if len(parts) > 4 else ""
        req_type = parts[5] if len(parts) > 5 else ""
        bReq = parts[6] if len(parts) > 6 else ""
        wVal = parts[7] if len(parts) > 7 else ""
        wIdx = parts[8] if len(parts) > 8 else ""
        wLen = parts[9] if len(parts) > 9 else ""
        capdata = parts[10] if len(parts) > 10 else ""
        data_frag = parts[11] if len(parts) > 11 else ""
        data = capdata or data_frag

        # Filter out standard device enumeration (GET_DESCRIPTOR etc if standard)
        # Standard device requests have req_type == 0x00 or 0x80 and bReq in [0, 6, 9]
        if req_type in ("0x00", "0x80") and bReq in ("0", "6", "9"):
            continue
        if xfer_type == "1": # isoc
            continue

        print(f"[{frame_num:5s}] t={float(time_rel):.3f} ep={ep} xfer={xfer_type} reqType={req_type} bReq={bReq} wVal={wVal} wLen={wLen} data={data[:60]}{'...' if len(data)>60 else ''}")

if __name__ == "__main__":
    analyze_pcap(sys.argv[1])
