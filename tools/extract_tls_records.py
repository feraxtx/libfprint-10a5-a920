import subprocess

def get_data(fn):
    out = subprocess.check_output(["tshark", "-r", "recordings/01_init.pcapng", "-Y", f"frame.number == {fn}", "-T", "fields", "-e", "usb.data_fragment", "-e", "usb.capdata"]).decode().strip()
    return bytes.fromhex(out.replace(":", "").replace("\t", ""))

# Frame 132 + 134: ClientHello
ch_rec = get_data(132) + get_data(134)
# Frame 136 + 138: ServerHello (starts after 12 byte event header)
sh_rec = (get_data(136) + get_data(138))[12:]
# Frame 140: ServerHelloDone (starts after 12 byte event header)
shd_rec = get_data(140)[12:]
# Frame 142: ClientKeyExchange
cke_rec = get_data(142)
# Frame 144: ChangeCipherSpec
ccs_rec = get_data(144)
# Frame 146: Client Finished
fin_rec = get_data(146)

print("ClientHello record:    ", ch_rec.hex())
print("ServerHello record:    ", sh_rec.hex())
print("ServerHelloDone record:", shd_rec.hex())
print("ClientKeyExchange rec: ", cke_rec.hex())
print("ChangeCipherSpec rec:  ", ccs_rec.hex())
print("Client Finished rec:   ", fin_rec.hex())
