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
# Variables globales compartidas
num_paquete = 0
total_bytes = 0
cola_paquetes = multiprocessing.Queue()
lock_cola = threading.Lock()  # Bloqueo para acceso seguro a la cola
lock_llamadas = threading.Lock()  # Bloqueo para acceso seguro a las llamadas
TIEMPO_INACTIVIDAD = 60  # Tiempo de inactividad en segundos para considerar una llamada inactiva
# Rango de puertos RTP (ajusta estos valores según lo necesites)
PUERTOS_RTP = range(16384, 32768)
stop_event = threading.Event()
llamadas = defaultdict(lambda: {
    "num_paquetes_rtp_llamante": 0,
    "num_paquetes_rtp_llamado": 0,
    "bytes_rtp_llamante": 0,
    "bytes_rtp_llamado": 0,
    "num_paquetes_sip": 0,
    "inicio_llamada": 0,
    "source_ip": None,
    "dst_ip": None,
    "source_port": None,
    "dst_port": None,
    "transporte_proto": None,
    "from": None,
    "to": None,
    "time_inicio_llamante": 0,
    "time_inicio_llamado": 0,
    "time_final_llamante": 0,
    "time_final_llamado": 0,
    "vlan1": None,
    "vlan2": None,
    "user_agent_llamante": 0,
    "user_agent_llamado": 0,
    "to_200": None,
    "p_asserted_id": None,
    "sip_uri": None,
    "pcv": None,
    "tiempo_t_r": 0,
    "inactividad": 0,
    "sdp_ip_llamante": None,
    "sdp_port_llamante": None,
    "sdp_codecs_llamante": None,
    "sdp_ip_llamado": None,
    "sdp_port_llamado": None,
    "sdp_codecs_llamado": None,
    "tiempo_bye": 0,
    "rtp_llamante_seq_min": None,
    "rtp_llamante_seq_max": None,
    "rtp_llamado_seq_min": None,
    "rtp_llamado_seq_max": None,
    "loss_ratio_llamante": -1,
    "loss_ratio_llamado": -1,
    "rtp_tiempos_llamante": [],
    "rtp_tiempos_llamado": [],
    "rtp_inter_avg_llamante": -1,
    "rtp_inter_min_llamante": -1,
    "rtp_inter_max_llamante": -1,
    "rtp_inter_avg_llamado": -1,
    "rtp_inter_min_llamado": -1,
    "rtp_inter_max_llamado": -1,
    "llamada_finalizada": False
})


def calcular_inter_arrivals_call(call_id):
    global llamadas
    llamada = llamadas[call_id]
    
    # LLAMANTE
    tiempos = sorted(llamada["rtp_tiempos_llamante"])
    if len(tiempos) >= 2:
        inters = [t2 - t1 for t1, t2 in zip(tiempos[:-1], tiempos[1:])]
        llamada["rtp_inter_avg_llamante"] = round(sum(inters) / len(inters))
        llamada["rtp_inter_min_llamante"] = min(inters)
        llamada["rtp_inter_max_llamante"] = max(inters)

    # LLAMADO
    tiempos = sorted(llamada["rtp_tiempos_llamado"])
    if len(tiempos) >= 2:
        inters = [t2 - t1 for t1, t2 in zip(tiempos[:-1], tiempos[1:])]
        llamada["rtp_inter_avg_llamado"] = round(sum(inters) / len(inters))
        llamada["rtp_inter_min_llamado"] = min(inters)
        llamada["rtp_inter_max_llamado"] = max(inters)

def calcular_loss_ratios_call(call_id):
    global llamadas
    llamada = llamadas[call_id]
    
    # LLAMANTE
    min_seq = llamada["rtp_llamante_seq_min"]
    max_seq = llamada["rtp_llamante_seq_max"]
    recibidos = llamada["num_paquetes_rtp_llamante"]

    if min_seq is not None and max_seq is not None and max_seq >= min_seq:
        esperados = max_seq - min_seq + 1
        if esperados > 0:
            perdida = (esperados - recibidos) / esperados
            llamada["loss_ratio_llamante"] = round(perdida, 4)
        else:
            llamada["loss_ratio_llamante"] = -1

    # LLAMADO
    min_seq = llamada["rtp_llamado_seq_min"]
    max_seq = llamada["rtp_llamado_seq_max"]
    recibidos = llamada["num_paquetes_rtp_llamado"]

    if min_seq is not None and max_seq is not None and max_seq >= min_seq:
        esperados = max_seq - min_seq + 1
        if esperados > 0:
            perdida = (esperados - recibidos) / esperados
            llamada["loss_ratio_llamado"] = round(perdida, 4)
        else:
            llamada["loss_ratio_llamado"] = -1

def ip_a_string(ip_uint32):
    b1 = (ip_uint32 >> 0) & 0xFF
    b2 = (ip_uint32 >> 8) & 0xFF
    b3 = (ip_uint32 >> 16) & 0xFF
    b4 = (ip_uint32 >> 24) & 0xFF
    return f"{b1}.{b2}.{b3}.{b4}"


def monitorear_inactividad(filtros, interfaz):
    global llamadas
    while not stop_event.is_set():
        try:
            with lock_llamadas:
                for call_id, data in list(llamadas.items()):
                    if data.get("llamada_finalizada", False):
                        continue

                    if data["inactividad"] >= TIEMPO_INACTIVIDAD:
                        imprimir_llamada(call_id, "Inactividad general", filtros, interfaz)
                        llamadas[call_id]["llamada_finalizada"] = True

                    elif data["tiempo_bye"] != 0:
                        time.sleep(2)
                        imprimir_llamada(call_id, "BYE", filtros, interfaz)
                        llamadas[call_id]["llamada_finalizada"] = True

                    else:
                        llamadas[call_id]["inactividad"] += 1

        except KeyboardInterrupt:
            print("Proceso interrumpido por el usuario.")
            break
        except Exception as e:
            print(f"Error inesperado: {e}")
        
        time.sleep(1)


def imprimir_llamada(call_id, motivo, filtros, interfaz):
    global llamadas
    data = llamadas[call_id]
    calcular_inter_arrivals_call(call_id)
    calcular_loss_ratios_call(call_id)
    tiempo_final = max(data["time_final_llamante"], data["time_final_llamado"])
    diferencia_ns = data['time_final_llamante'] - data['time_inicio_llamante']  # nanosegundos
    diferencia_s = diferencia_ns / 1_000_000_000  # segundos
    duracion_llamada_llamante = diferencia_s / 60  # minutos
    diferencia_ns = data['time_final_llamado'] - data['time_inicio_llamado']  # nanosegundos
    diferencia_s = diferencia_ns / 1_000_000_000  # segundos
    duracion_llamada_llamado = diferencia_s / 60  # minutos
    diferencia_ns = data['tiempo_bye'] - data['time_inicio_llamado']  # nanosegundos
    diferencia_s = diferencia_ns / 1_000_000_000  # segundos
    duracion_facturable = diferencia_s / 60  # minutos
    diferencia_ns = data['tiempo_t_r'] - data['time_inicio_llamante']  # nanosegundos
    pdd = diferencia_ns / 1_000_000_000  # segundos
    duracion_rtp_llamante = 0
    duracion_rtp_llamado = 0

    # Duración RTP llamante
    if data["rtp_tiempos_llamante"] and len(data["rtp_tiempos_llamante"]) >= 2:
        diferencia_ns = data["rtp_tiempos_llamante"][-1] - data["rtp_tiempos_llamante"][0]
        diferencia_s = diferencia_ns / 1_000_000_000  # segundos
        duracion_rtp_llamante = diferencia_s / 60  # minutos

    # Duración RTP llamado
    if data["rtp_tiempos_llamado"] and len(data["rtp_tiempos_llamado"]) >= 2:
        diferencia_ns = data["rtp_tiempos_llamado"][-1] - data["rtp_tiempos_llamado"][0]
        diferencia_s = diferencia_ns / 1_000_000_000  # segundos
        duracion_rtp_llamado = diferencia_s / 60  # minutos

    print(f"Call-ID: {call_id}")
    print(f"  Paquetes SIP: {data['num_paquetes_sip']}")
    print(f"  Paquetes RTP: {data['num_paquetes_rtp_llamante'] + data['num_paquetes_rtp_llamado'] }")
    print(f"Begin: {data['time_inicio_llamante']}")
    print(f"End: {tiempo_final}")
    print(f"Source port: {data['source_port']}")
    print(f"Destination port: {data['dst_port']}")
    print(f"Source IP: {data['source_ip']}")
    print(f"Destination IP: {data['dst_ip']}")
    print(f"Transport protocol: {data['transporte_proto']}")
    print(f"From: {data['from']}")
    print(f"To: {data['to']}")
    print(f"Caller duration: {duracion_llamada_llamante} minutos")
    print(f"Callee duration: {duracion_llamada_llamado} minutos")  # Esto puede variar si calculas individualmente llamante y llamado
    #print(f"Caller last message: {info_sip_final}")
    #print(f"Callee last message: {info_sip_final}")
    print(f"PCAP file (interfaz): {interfaz}")
    print(f"VLAN1: {data['vlan1']}")
    print(f"VLAN2: {data['vlan2']}")
    print(f"Caller User Agent: {data['user_agent_llamante']}")
    print(f"Callee User Agent: {data['user_agent_llamado']}")  # Esto se extraería de un 200 OK o último mensaje SIP
    print(f"To200: {data['to_200']}")  # Esto también depende del 200 OK
    print(f"Passerted: {data['p_asserted_id']}")
    print(f"Sipuri: {data['sip_uri']}")
    print(f"P_Charging_Vector: {data['pcv']}")
    print(f"PDD: {pdd} segundos")
    print(f"Duracion Factuable: {duracion_facturable} minutos")  # Depende de la diferencia entre 200 OK y BYE
    print(f"Motivo cierre: {motivo}")  # BYE, CANCEL o TIMEOUT
    print(f"RTP caller port: {data['sdp_port_llamante']}")
    print(f"RTP callee port: {data['sdp_port_llamado']}")
    print(f"RTP IP caller: {data['sdp_ip_llamante']}")
    print(f"RTP IP callee: {data['sdp_ip_llamado']}")
    print(f"Caller mediatype: {data['sdp_codecs_llamante']}")
    print(f"Callee mediatype: {data['sdp_codecs_llamado']}")
    print(f"RTP Npack caller: {data['num_paquetes_rtp_llamante']}")  # Esto requeriría contar los paquetes RTP
    print(f"RTP Npack callee: {data['num_paquetes_rtp_llamado']}")
    print(f"RTP bytes caller: {data['bytes_rtp_llamante']}")  # Se puede calcular el total de bytes RTP
    print(f"RTP bytes callee: {data['bytes_rtp_llamado']}")
    print(f"Ratio loss caller: {data['loss_ratio_llamante']}")
    print(f"Ratio loss callee: {data['loss_ratio_llamado']}")
    print(f"RTP inter caller: {data['rtp_inter_avg_llamante']} µs")
    print(f"RTP inter callee: {data['rtp_inter_avg_llamado']} µs")
    print(f"RTP max inter caller: {data['rtp_inter_max_llamante']} µs")
    print(f"RTP max inter callee: {data['rtp_inter_max_llamado']} µs")
    print(f"RTP min inter caller: {data['rtp_inter_min_llamante']} µs")
    print(f"RTP min inter callee: {data['rtp_inter_min_llamado']} µs")
    print(f"RTP dur caller: {duracion_rtp_llamante} minutos")
    print(f"RTP dur callee: {duracion_rtp_llamado} minutos")
    print("-" * 50)
    del llamadas[call_id]




def procesa_paquete(timestamp, data):
    """Procesa cada paquete capturado desde el archivo PCAP."""
    global num_paquete, total_bytes
    num_paquete += 1
    total_bytes += len(data)

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

class Paquete2(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
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

        

def adjuntar_llamada(paquete):
    global llamadas
    src_ip = ip_a_string(paquete.src_ip)
    dst_ip = ip_a_string(paquete.dst_ip)
    src_port = paquete.src_port
    dst_port = paquete.dst_port

    if paquete.protocol.decode() == "SIP":
        call_id = bytes(paquete.call_id).decode(errors='ignore').strip('\x00')
        llamadas[call_id]["num_paquetes_sip"] += 1
        if llamadas[call_id]["transporte_proto"] is None:
            llamadas[call_id]["transporte_proto"]= paquete.transporte_proto
        # Registrar IPs y puertos al principio si no están seteados
        if llamadas[call_id]["source_ip"] is None:
            llamadas[call_id]["source_ip"] = src_ip
        if llamadas[call_id]["dst_ip"] is None:
            llamadas[call_id]["dst_ip"] = dst_ip
        if llamadas[call_id]["source_port"] is None:
            llamadas[call_id]["source_port"] = src_port
        if llamadas[call_id]["dst_port"] is None:
            llamadas[call_id]["dst_port"] = dst_port

        metodo = paquete.metodo.decode('utf-8', errors='ignore').strip('\x00')
        if metodo == "BYE":
            llamadas[call_id]["tiempo_bye"]= paquete.timestamp
        # Detectar inicio llamada caller (quien envía INVITE)
        if llamadas[call_id]["time_inicio_llamante"] == 0 and metodo == "INVITE" and src_ip == llamadas[call_id]["source_ip"] and\
        src_port == llamadas[call_id]["source_port"] and \
        dst_ip == llamadas[call_id]["dst_ip"] and \
        dst_port == llamadas[call_id]["dst_port"]:
            llamadas[call_id]["time_inicio_llamante"] = paquete.timestamp
            llamadas[call_id]["from"] = paquete.from_.decode('utf-8', errors='ignore').strip('\x00')
            llamadas[call_id]["to"] = paquete.to.decode('utf-8', errors='ignore').strip('\x00')
            llamadas[call_id]["user_agent_llamante"] = paquete.user_agent.decode('utf-8', errors='ignore').strip('\x00')
            llamadas[call_id]["sip_uri"] = paquete.sip_uri
            llamadas[call_id]["sdp_ip_llamante"] = paquete.sdp_ip_a.decode('utf-8', errors='ignore').strip('\x00')
            llamadas[call_id]["sdp_port_llamante"] = paquete.sdp_port_a
            llamadas[call_id]["sdp_codecs_llamante"] = paquete.sdp_codecs_a.decode('utf-8', errors='ignore').strip('\x00')

            # Guardar VLANs si es el primer INVITE
            if llamadas[call_id].get("vlan1") is None:
                llamadas[call_id]["vlan1"] = paquete.vlan1
            if llamadas[call_id].get("vlan2") is None:
                llamadas[call_id]["vlan2"] = paquete.vlan2

        # Detectar inicio llamada callee (primer paquete SIP que viene del callee)
        if llamadas[call_id]["time_inicio_llamado"] == 0 and \
        src_ip == llamadas[call_id]["dst_ip"] and \
        src_port == llamadas[call_id]["dst_port"] and \
        dst_ip == llamadas[call_id]["source_ip"] and \
        dst_port == llamadas[call_id]["source_port"] and \
        llamadas[call_id]["user_agent_llamado"] == 0:
            llamadas[call_id]["time_inicio_llamado"] = paquete.timestamp
            llamadas[call_id]["user_agent_llamado"] = paquete.user_agent.decode('utf-8', errors='ignore').strip('\x00')

        # Actualizar fin de llamada caller (último paquete enviado por caller)
        if src_ip == llamadas[call_id]["source_ip"] and dst_ip == llamadas[call_id]["dst_ip"] and src_port == llamadas[call_id]["source_port"] and dst_port == llamadas[call_id]["dst_port"]:
            llamadas[call_id]["time_final_llamante"] = paquete.timestamp

        # Actualizar fin de llamada callee (último paquete enviado por callee)
        if src_ip == llamadas[call_id]["dst_ip"] and dst_ip == llamadas[call_id]["source_ip"] and src_port == llamadas[call_id]["dst_port"] and dst_port == llamadas[call_id]["source_port"]:
            llamadas[call_id]["time_final_llamado"] = paquete.timestamp

        to_200_val = paquete.to_200.decode('utf-8', errors='ignore').strip('\x00')
        if to_200_val != "N/A" and to_200_val != "" and llamadas[call_id]["to_200"] is None:
            llamadas[call_id]["to_200"] = to_200_val
            llamadas[call_id]["time_inicio_llamado"] = paquete.timestamp
            llamadas[call_id]["sdp_ip_llamado"] = paquete.sdp_ip_b.decode('utf-8', errors='ignore').strip('\x00')
            llamadas[call_id]["sdp_port_llamado"] = paquete.sdp_port_b
            llamadas[call_id]["sdp_codecs_llamado"] = paquete.sdp_codecs_b.decode('utf-8', errors='ignore').strip('\x00')
        pai = paquete.pai.decode('utf-8', errors='ignore').strip('\x00')
        if pai not in ("", "N/A"):
            llamadas[call_id]["p_asserted_id"] = pai
        pcv = paquete.pcv.decode('utf-8', errors='ignore').strip('\x00')
        if pcv not in ("", "N/A"):
            llamadas[call_id]["pcv"] = pcv
        if paquete.es_trying_o_ringing == 1 and llamadas[call_id]["tiempo_t_r"] == 0:
            llamadas[call_id]["tiempo_t_r"] = paquete.timestamp
        return
    if paquete.protocol.decode() == "RTP":
        seq = paquete.rtp_seq
        ts = paquete.timestamp
        for call_id in list(llamadas.keys()):
            llamada = llamadas[call_id]
            # Verificar si coincide con IP/puerto del llamante
            if (src_ip == llamada["sdp_ip_llamante"] and src_port == llamada["sdp_port_llamante"]):
                llamadas[call_id]["bytes_rtp_llamante"] += paquete.packet_size
                llamadas[call_id]["num_paquetes_rtp_llamante"] += 1
                llamada["rtp_tiempos_llamante"].append(ts)
                llamada["time_final_llamante"] =  paquete.timestamp
                if llamada["rtp_llamante_seq_min"] is None or seq < llamada["rtp_llamante_seq_min"]:
                    llamada["rtp_llamante_seq_min"] = seq
                if llamada["rtp_llamante_seq_max"] is None or seq > llamada["rtp_llamante_seq_max"]:
                    llamada["rtp_llamante_seq_max"] = seq
            # Verificar si coincide con IP/puerto del llamado
            elif (src_ip == llamada["sdp_ip_llamado"] and src_port == llamada["sdp_port_llamado"]):
                llamadas[call_id]["bytes_rtp_llamado"] += paquete.packet_size
                llamadas[call_id]["num_paquetes_rtp_llamado"] += 1
                llamada["rtp_tiempos_llamado"].append(ts)
                llamada["time_final_llamado"] = paquete.timestamp
                if llamada["rtp_llamado_seq_min"] is None or seq < llamada["rtp_llamado_seq_min"]:
                    llamada["rtp_llamado_seq_min"] = seq
                if llamada["rtp_llamado_seq_max"] is None or seq > llamada["rtp_llamado_seq_max"]:
                    llamada["rtp_llamado_seq_max"] = seq
        return


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

                adjuntar_llamada(paq_struct)

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

def xdp_captura(interfaz):
    if xdp.xdp_open(interfaz):
        print("Socket abierto. Esperando paquetes (XDP)...")
        total_bytes = 0
        total_paquetes = 0
        start_time = time.time()
        last_report = start_time  # para control por segundo

        PyCapsule_GetPointer = ctypes.pythonapi.PyCapsule_GetPointer
        PyCapsule_GetPointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
        PyCapsule_GetPointer.restype = ctypes.c_void_p

        try:
            while not stop_event.is_set():
                pkt = xdp.xdp_recv()
                now = time.time()
                if pkt:
                    ptr = PyCapsule_GetPointer(pkt, b"Paquete2")
                    paq_struct = ctypes.cast(ptr, ctypes.POINTER(Paquete2)).contents
                    adjuntar_llamada(paq_struct)
                    total_bytes += paq_struct.packet_size
                    total_paquetes += 1
                # Mostrar tasa cada segundo
                if now - last_report >= 1:
                    elapsed = now - start_time
                    bitrate = (total_bytes * 8) / elapsed  # bps
                    print(f"[{int(elapsed)}s] Tasa: {bitrate:.2f} bps ({bitrate/1e6:.2f} Mbps), paquetes: {total_paquetes}")
                    last_report = now
        except KeyboardInterrupt:
            print("\n[!] Captura interrumpida por el usuario.")
        except Exception as e:
            print(f"[ERROR] durante la captura con XDP: {e}")
        finally:
            xdp.xdp_close()
            elapsed_time = time.time() - start_time
            bitrate = (total_bytes * 8) / elapsed_time if elapsed_time > 0 else 0

            print(f"\nTiempo total: {elapsed_time:.2f} segundos")
            print(f"Tasa promedio: {bitrate:.2f} bps ({bitrate / 1e6:.2f} Mbps)")
            print(f"Total paquetes: {total_paquetes}")
    else:
        print("Error abriendo socket XDP")


def leer_paquetes_de_pcap(archivo_pcap):
    """
    Lee paquetes desde un archivo PCAP y mide el rendimiento en tiempo real.

    :param archivo_pcap: Ruta al archivo PCAP que contiene los paquetes a procesar.
    """
    
    print(f"Iniciando lectura de tráfico desde el archivo {archivo_pcap}...")
    # Leer un archivo PCAP
    #profiler = cProfile.Profile()
    #profiler.enable()  # Inicia el profiling
    pcap_wrapper.open_pcap(archivo_pcap)
    total_bytes=0
    total_paquetes = 0
    start_time=time.time()

    vacios_consecutivos = 0
    max_vacios = 5  # ajustable: cuántos intentos vacíos hasta salir
    while not stop_event.is_set():
        paquetes = pcap_wrapper.read_pcap()  # Ahora devuelve una lista de paquetes
        if paquetes is None or len(paquetes) == 0:
            print("No hay más paquetes")
            break  # No hay más paquetes

        for packet in paquetes:  # Procesar cada paquete en la lista
            # Extraer el puntero desde la capsule
            PyCapsule_GetPointer = ctypes.pythonapi.PyCapsule_GetPointer
            PyCapsule_GetPointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
            PyCapsule_GetPointer.restype = ctypes.c_void_p

            ptr = PyCapsule_GetPointer(packet, b"Paquete")
            paq_struct = ctypes.cast(ptr, ctypes.POINTER(Paquete)).contents
            adjuntar_llamada(paq_struct)

            total_bytes += paq_struct.packet_size
            total_paquetes += 1
    
    global llamadas
    pcap_wrapper.close_pcap()

    #
    # Mostrar los paquetes leídos
    #for i, (length, data) in enumerate(packets):
    #    total_bytes+=length
    end_time=time.time()

    elapsed_time = end_time - start_time

    bitrate = (total_bytes * 8) / elapsed_time if elapsed_time > 0 else 0

    print(f"\nTiempo total: {elapsed_time:.6f} segundos")
    print(f"Tasa promedio: {bitrate:.2f} bps ({bitrate / 1e6:.2f} Mbps)")
    print(f"Total paquetes: {total_paquetes}")
    #profiler.disable()  # Detiene el profiling
    #stats = pstats.Stats(profiler)
    #stats.strip_dirs().sort_stats("cumulative").print_stats(10)  # Muestra las 10 funciones más lentas



# Configuración de hilos
def iniciar_capturas(tipo, interfaz, filtros):
    """
    Inicia procesos para capturar tráfico, procesar paquetes y monitorear actividad.
    Maneja excepciones y señales correctamente.
    """
    procesos = []  # Lista para gestionar los procesos

    try:
        if str(tipo) == '0':
            proc_captura = threading.Thread(target=capturar_paquetes, args=(interfaz,))
        elif str(tipo) == '1':
            print("Archivo")
            proc_captura = threading.Thread(target=leer_paquetes_de_pcap, args=(interfaz,))
        else:
            proc_captura = threading.Thread(target=xdp_captura, args=(interfaz,))
        
        proc_monitoreo = threading.Thread(target=monitorear_inactividad, args=(filtros, interfaz,))

        # Agregar procesos a la lista para gestionarlos
        procesos.extend([proc_captura, proc_monitoreo])

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
