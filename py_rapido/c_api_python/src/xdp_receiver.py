from xdp_wrapper import xdp_open, xdp_recv, xdp_close
import sys

if xdp_open(sys.argv[1]):
    print("Socket abierto. Esperando paquetes...")
    while True:
        pkt = xdp_recv()
        if pkt:
            print(f"Paquete recibido ({len(pkt)} bytes): {pkt[:32].hex()}")
            ip_header = pkt[14:34]  # Asumiendo Ethernet (14 bytes) + IP (20 bytes)
            src_ip = ".".join(str(b) for b in ip_header[12:16])
            dst_ip = ".".join(str(b) for b in ip_header[16:20])
            print(f"IP origen: {src_ip}")
            print(f"IP destino: {dst_ip}")
        
    xdp_close()
else:
    print("Error abriendo socket XDP")
