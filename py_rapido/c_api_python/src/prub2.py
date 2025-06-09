import queue
import pcap_wrapper
import time
import sys
import multiprocessing
import math
import sys
import threading
from collections import deque, defaultdict
from struct import unpack, unpack_from
#import cProfile
import os
#from line_profiler import LineProfiler
import re
import pstats
import ctypes
import xdp
import sys

stop_event = threading.Event()
class Paquete(ctypes.Structure):
    _fields_ = [("timestamp", ctypes.c_uint64),
                ("src_ip", ctypes.c_uint32),
                ("dst_ip", ctypes.c_uint32),
                ("src_port", ctypes.c_uint16),
                ("dst_port", ctypes.c_uint16),
                ("packet_size", ctypes.c_uint16),
                ("protocol", ctypes.c_char * 20),
                ("call_id", ctypes.c_char * 256),
                ("rtp_seq", ctypes.c_uint16),
                ("rtp_timestamp", ctypes.c_uint32),
                ("metodo", ctypes.c_char * 30),
                ("transporte_proto", ctypes.c_uint8),
                ("from_", ctypes.c_char * 50),
                ("to", ctypes.c_char * 50),
                ("vlan1", ctypes.c_uint16),
                ("vlan2", ctypes.c_uint16),
                ("user_agent", ctypes.c_char * 256),
                ("to_200", ctypes.c_char * 50),
                ("pai", ctypes.c_char * 128),
                ("sip_uri", ctypes.c_char * 100),
                ("pcv", ctypes.c_char * 128),
                ('es_trying_o_ringing', ctypes.c_int),
                ("sdp_ip_a", ctypes.c_char * 64),
                ("sdp_port_a", ctypes.c_uint16),
                ("sdp_codecs_a", ctypes.c_char * 256),
                ("sdp_ip_b", ctypes.c_char * 64),
                ("sdp_port_b", ctypes.c_uint16),
                ("sdp_codecs_b", ctypes.c_char * 256),]



def capturar_paquetes(interfaz):
    print(f"Iniciando captura de tráfico en la interfaz {interfaz}...")

    pcap_wrapper.open_live(interfaz)
    total_bytes = 0
    total_paquetes = 0
    start_time = time.time()
    last_report = start_time  # para control por segundo

    try:
        while not stop_event.is_set():
            paquetes = pcap_wrapper.read_live()
            if not paquetes:
                continue

            for packet in paquetes:
                PyCapsule_GetPointer = ctypes.pythonapi.PyCapsule_GetPointer
                PyCapsule_GetPointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
                PyCapsule_GetPointer.restype = ctypes.c_void_p

                ptr = PyCapsule_GetPointer(packet, b"Paquete")
                paq_struct = ctypes.cast(ptr, ctypes.POINTER(Paquete)).contents

                total_bytes += paq_struct.packet_size
                total_paquetes += 1

                now = time.time()
                # Mostrar tasa cada segundo
                if now - last_report >= 1:
                    elapsed = now - start_time
                    bitrate = (total_bytes * 8) / elapsed  # bps
                    print(f"[{int(elapsed)}s] Tasa: {bitrate:.2f} bps ({bitrate/1e6:.2f} Mbps), paquetes: {total_paquetes}")
                    last_report = now
    except KeyboardInterrupt:
        print("\n[!] Captura interrumpida por el usuario.")
    except Exception as e:
        print(f"[ERROR] durante la captura: {e}")
    finally:
        pcap_wrapper.close_pcap()
        elapsed_time = time.time() - start_time
        bitrate = (total_bytes * 8) / elapsed_time if elapsed_time > 0 else 0

        print(f"\nTiempo total: {elapsed_time:.2f} segundos")
        print(f"Tasa promedio: {bitrate:.2f} bps ({bitrate / 1e6:.2f} Mbps)")
        print(f"Total paquetes: {total_paquetes}")

# Configuración de hilos
def iniciar_capturas(tipo, interfaz, filtros):
    """
    Inicia procesos para capturar tráfico, procesar paquetes y monitorear actividad.
    Maneja excepciones y señales correctamente.
    """
    procesos = []  # Lista para gestionar los procesos
    try:
        proc_captura = threading.Thread(target=capturar_paquetes, args=(interfaz,))
        

        # Agregar procesos a la lista para gestionarlos
        procesos.extend([proc_captura])

        # Iniciar procesos
        for proc in procesos:
            proc.start()

        # Esperar a que terminen
        while any(proc.is_alive() for proc in procesos):
            time.sleep(0.1)  # Pequeño delay para evitar consumo excesivo de CPU

    except KeyboardInterrupt:
        print("\n[!] Control+C detectado. Terminando procesos...")
        stop_event.set()
    except Exception as e:
        print(f"[ERROR] Problema al iniciar las capturas: {e}")
    finally:
        # Finalizar todos los procesos correctamente
        #for proc in procesos:
            #if proc.is_alive():
                #proc.terminate()
        for proc in procesos:
            proc.join()

        print("[✔] Todos los procesos se han detenido correctamente.")



# Configuración principal
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python capturar_trafico.py tipo(0 si interfaz y 1 si pcap) <interfaz o pcap> filtros...")
        sys.exit(1)


    tipo = sys.argv[1]
    interfaz = sys.argv[2]
    filtros = sys.argv[3:]
    iniciar_capturas(tipo, interfaz,filtros)
