import math
import sys
import threading
from scapy.all import sniff, IP, UDP, TCP, PcapReader
import time
from collections import deque, defaultdict
import signal
import pyshark

# Variables globales para detener la captura
stop_sniffing_event= threading.Event()

# Variables globales
cola_paquetes = deque()  # Cola centralizada para paquetes en orden de llegada
llamadas = defaultdict(lambda: {
    "sip": [],  # Paquetes SIP asociados a la llamada
    "rtp": [],  # Paquetes RTP asociados a la llamada
    "num_paquetes": 0,
    "inactividad": 0,
    "sdp": {
        "llamante": {
            "ip": None,        # IP inicializada como None
            "port": None,      # Puerto inicializado como None
            "codecs": []       # Lista de códecs vacía
        },
        "llamado": {
            "ip": None,        # IP inicializada como None
            "port": None,      # Puerto inicializado como None
            "codecs": []       # Lista de códecs vacía
        }
    },
    "procesado": False,  # Marca si la llamada ha sido procesada
    "ultima_actividad_sip": None,  # Última actividad SIP entrante
    "ultima_actividad_rtp": None,  # Última actividad RTP entrante
    "bye_detected": False,  # Indica si se detectó un mensaje BYE
    "bye_time": None,  # Timestamp del mensaje BYE
    "bye_responded": False,  # Indica si el mensaje BYE recibió respuesta (200 OK)
    "ok_time": None,  # Timestamp del último 200 OK recibido
})



lock_cola = threading.Lock()  # Bloqueo para acceso seguro a la cola
lock_llamadas = threading.Lock()  # Bloqueo para acceso seguro a las llamadas
TIEMPO_INACTIVIDAD = 5  # Tiempo de inactividad en segundos para considerar una llamada inactiva


# Calcular estadísticas RTP: número de paquetes, bytes, jitter y pérdida de paquetes
def analizar_rtp(paquetes_rtp):
    num_paquetes = len(paquetes_rtp)
    total_bytes = sum(len(pkt) for pkt in paquetes_rtp)
    jitter_total = 0
    perdida_paquetes = 0
    ultimo_num_seq = None
    ultimo_tiempo = None
    jitter_max=0
    jitter_min= math.inf

    for pkt in paquetes_rtp:
        rtp_payload = pkt[UDP].load
        num_seq = int.from_bytes(rtp_payload[2:4], byteorder='big')  # Convertir número de secuencia a entero
        tiempo_marca = pkt.time
        if ultimo_num_seq is not None:
            if num_seq != ultimo_num_seq + 1:
                perdida_paquetes += (num_seq - ultimo_num_seq - 1)  # Estimar la pérdida de paquetes
            if ultimo_tiempo is not None:
                jitter_total += abs(tiempo_marca - ultimo_tiempo)  # Calcular el jitter
                if abs(tiempo_marca - ultimo_tiempo) > jitter_max:
                    jitter_max= abs(tiempo_marca - ultimo_tiempo)
                if abs(tiempo_marca - ultimo_tiempo) < jitter_min:
                    jitter_min= abs(tiempo_marca - ultimo_tiempo)    

        ultimo_num_seq = num_seq
        ultimo_tiempo = tiempo_marca
    
    if jitter_min ==math.inf:
        jitter_min=0
    if len(paquetes_rtp) == 0:
        duracion = 0
    else:
        duracion = paquetes_rtp[-1].time - paquetes_rtp[0].time
    jitter_promedio = jitter_total / num_paquetes if num_paquetes > 0 else 0
    return num_paquetes, total_bytes, perdida_paquetes, jitter_promedio, jitter_max, jitter_min, duracion

# Filtrar paquetes RTP correspondientes a un flujo basado en IP y puerto
def filtrar_paquetes_rtp(paquetes, ip_rtp, puerto_rtp):
    paquetes_rtp = []
    for pkt in paquetes:
        if UDP in pkt and pkt[UDP].sport == puerto_rtp and pkt[IP].src == ip_rtp:
            paquetes_rtp.append(pkt)
    return paquetes_rtp

def calcular_duracion_facturable(paquetes_sip):
    tiempo_ok = None
    tiempo_bye = None
    duracion_facturable = None

    for pkt in paquetes_sip:
        # Obtener el contenido del paquete
        if UDP in pkt:
            payload = pkt[UDP].load.decode("utf-8", errors="ignore")
        elif TCP in pkt:
            payload = pkt[TCP].payload.load.decode("utf-8", errors="ignore")

        # Buscar el 200 OK
        if "200 OK" in payload:
            tiempo_ok = pkt.time

        es_req, metodo_sip, uri_sip = es_request(payload)
        # Buscar el BYE
        if es_req and "BYE" in metodo_sip:
            tiempo_bye = pkt.time

        # Si ambos tiempos se han capturado, calcular la duración
        if tiempo_ok and tiempo_bye:
            duracion_facturable = tiempo_bye - tiempo_ok
            break  # Salir después de calcular la duración facturable

    # Retornar la duración en segundos y microsegundos
    if duracion_facturable is not None:
        return duracion_facturable  # Ejemplo: 12.345678 segundos
    else:
        return None  # Si no se encontraron los mensajes 200 OK o BYE

def calcular_pdd(paquetes_sip):
    pdd = None
    tiempo_invite = None
    tiempo_trying = None
    tiempo_ringing = None

    for pkt in paquetes_sip:
        # Obtener el tiempo de la llamada INVITE
        if UDP in pkt:
            payload = pkt[UDP].load.decode("utf-8", errors="ignore")
        elif TCP in pkt:
            payload = pkt[TCP].payload.load.decode("utf-8", errors="ignore")

        es_req, metodo_sip, uri_sip = es_request(payload)
        # Buscar el BYE
        if es_req and "INVITE" in metodo_sip:
            tiempo_invite = pkt.time
        
        # Comprobar si el paquete es una respuesta 100 TRYING
        if "SIP/2.0 100 Trying" in payload:
            tiempo_trying = pkt.time
        
        # Comprobar si el paquete es una respuesta 180 RINGING
        if "SIP/2.0 180 Ringing" in payload:
            tiempo_ringing = pkt.time

        # Calcular PDD usando el primer tiempo de respuesta válido
        if tiempo_invite is not None:
            if tiempo_trying is not None:
                pdd = tiempo_trying - tiempo_invite
                break  # Salir después de calcular
            elif tiempo_ringing is not None:
                pdd = tiempo_ringing - tiempo_invite
                break  # Salir después de calcular
    return pdd

def extraer_user_agent(paquetes_sip):
    llamante = None
    llamado = None
    mensaje_to = None
    p_asserted = None
    uri_sip = None
    p_charging_vector = None
    for pkt in paquetes_sip:
        if UDP in pkt:
            payload = pkt[UDP].load.decode("utf-8", errors="ignore")
        elif TCP in pkt:
            payload = pkt[TCP].payload.load.decode("utf-8", errors="ignore")
        es_req, metodo_sip, uri_sip = es_request(payload)
        if es_req and str(metodo_sip) == 'INVITE':
            if "User-Agent" in pkt[UDP].load.decode('utf-8', errors='ignore'):
                # Extrae el User-Agent
                llamante = pkt[UDP].load.decode('utf-8', errors='ignore').split("User-Agent: ")[1].split("\r\n")[0]
            uri_sip = uri_sip
        es_res, codigo_sip, estado = es_response(payload)
        if es_res and codigo_sip == "200" and estado == "OK":
            if "User-Agent" in pkt[UDP].load.decode('utf-8', errors='ignore'):
                # Extrae el User-Agent
                llamado = pkt[UDP].load.decode('utf-8', errors='ignore').split("User-Agent: ")[1].split("\r\n")[0]
                if "To:" in payload:
                    mensaje_to = payload.split("To: ")[1].split("\r\n")[0]
                    if ";" in mensaje_to:
                        mensaje_to = mensaje_to.split(";")[0]
        if "P-Asserted-Identity:" in payload:
            p_asserted = payload.split("P-Asserted-Identity: ")[1].split("\r\n")[0]
        if "P-Charging-Vector" in payload:
            # Extrae el P-Charging-Vector
            p_charging_vector = payload.split("P-Charging-Vector: ")[1].split("\r\n")[0]
    return llamante, llamado, mensaje_to, p_asserted, uri_sip, p_charging_vector

# Función para extraer los campos SIP relevantes del payload
def extraer_campos_sip(payload, filtros):
    info_sip = {}
    lineas = payload.splitlines()
    for linea in lineas:
        for filtro in filtros:
            if filtro.lower() in linea.lower():
                info_sip[filtro] = linea
    return info_sip

def obtener_metodo_sip(payload):
    try:
        # Dividir el contenido en líneas
        lineas = payload.splitlines()
        
        # La primera línea contiene el método y otros datos
        primera_linea = lineas[0]
        
        # Dividir la línea en palabras
        partes = primera_linea.split()
        
        # Verificar si la primera palabra es un método SIP conocido
        metodos_sip = {"INVITE", "REGISTER", "ACK", "BYE", "CANCEL", "OPTIONS", "INFO", "PRACK", "UPDATE", "MESSAGE", "SUBSCRIBE", "NOTIFY", "PUBLISH", "REFER"}
        
        if partes and partes[0] in metodos_sip:
            return partes[0]  # Retorna el método SIP
    except Exception as e:
        print(f"Error al analizar el payload SIP: {e}")
    
    return None  # Si no se encuentra un método válido
# Función para determinar si el payload es un request SIP
def es_request(payload):
    metodos_sip = ["INVITE", "REGISTER", "ACK", "CANCEL", "BYE", "OPTIONS"]
    lineas = payload.splitlines()
    if lineas:
        primera_linea = lineas[0]
        for metodo in metodos_sip:
            if metodo in primera_linea:
                partes = primera_linea.split()
                if len(partes) >= 2:
                    metodo_sip = partes[0]
                    uri_sip = partes[1]
                    return (True, metodo_sip, uri_sip)
    return (False, None, None)

# Función para determinar si el payload es un response SIP
def es_response(payload):
    lineas = payload.splitlines()
    if lineas:
        primera_linea = lineas[0]
        if primera_linea.startswith("SIP/2.0"):
            partes = primera_linea.split()
            if len(partes) >= 3:
                codigo_sip = partes[1]
                estado = " ".join(partes[2:])
                return (True, codigo_sip, estado)
    return (False, None, None)

# Función para extraer el Call-ID de los paquetes SIP
def extraer_call_id(payload):
    lineas = payload.splitlines()
    for linea in lineas:
        if "Call-ID:" in linea or "call-id:" in linea:
            return linea.split(":", 1)[1].strip()
    return None

# Función para extraer información SDP
def extraer_info_sdp(sdp_text):
    """
    Extrae IP, puerto y códecs del cuerpo SDP de un paquete SIP.
    """
    lines = sdp_text.splitlines()
    ip = None
    port = None
    codecs = []

    for line in lines:
        if line.startswith("c="):  # Línea con la IP de escucha
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "c=IN" and parts[1].startswith("IP4"):
                ip = parts[2]  # Obtener solo la IP

        if line.startswith("m=audio"):  # Línea con el puerto de escucha RTP
            parts = line.split()
            if len(parts) >= 2:
                port = parts[1]  # Puerto está en la segunda parte

        if line.startswith("a=rtpmap"):  # Línea con los codecs ofertados
            parts = line.split()
            if len(parts) >= 2:
                codecs.append(parts[1])  # El códec está en la segunda parte

    return ip, port, codecs


# Función para procesar paquetes
def procesar_paquetes():
    """
    Procesa los paquetes en la cola en orden de llegada y agrupa llamadas inactivas.
    """
    global cola_paquetes, llamadas

    while True:
        time.sleep(1)  # Ajusta el intervalo según sea necesario
        # Procesar paquetes en la cola
        with lock_cola:
            while cola_paquetes:
                paquete = cola_paquetes.popleft()  # Extraer paquete de la cola
                if paquete.haslayer(UDP):  # Verificar que el paquete tenga capa UDP
                    if paquete[UDP].sport == 5060 or paquete[UDP].dport == 5060:  # SIP
                        procesar_sip(paquete)
                    else:  # RTP
                        procesar_rtp(paquete)

        # Agrupar llamadas inactivas


def procesar_sip(paquete):
    """
    Procesa paquetes SIP y extrae información SDP.
    """
    global llamadas
    if paquete.haslayer("Raw"):
        payload = paquete[UDP].load.decode("utf-8", errors="ignore")
        call_id = extraer_call_id(payload)

        if call_id:
            with lock_llamadas:
                # Actualizar información de la llamada
                llamadas[call_id]["sip"].append(paquete)
                sip_origen = paquete[IP].src
                sip_destino = paquete[IP].dst

                # Identificar mensajes BYE y 200 OK
                es_req, metodo_sip, _ = es_request(payload)
                es_res, codigo_sip, _ = es_response(payload)
                
                if es_req and metodo_sip == "BYE":
                    llamadas[call_id]["bye_time"] = paquete.time
                    llamadas[call_id]["bye_detected"] = True

                if es_res and codigo_sip == "200":
                    llamadas[call_id]["ok_time"] = paquete.time
                    if "bye_detected" in llamadas[call_id] and llamadas[call_id]["bye_detected"]:
                        llamadas[call_id]["bye_responded"] = True

                # Actualizar última actividad SIP
                llamadas[call_id]["ultima_actividad_sip"] = paquete.time

                # Extraer información SDP si está presente
                if "Content-Type: application/sdp" in payload:
                    sdp_ip, sdp_port, sdp_codecs = extraer_info_sdp(payload)
                    es_req, metodo_sip, uri_sip = es_request(payload)
                    if sdp_ip and sdp_port:
                        if es_req and metodo_sip == "INVITE":
                            llamadas[call_id]["sdp"]['llamante'] = {
                                    "ip": sdp_ip,
                                    "port": int(sdp_port),
                                    "codecs": sdp_codecs,
                                }
                        else:
                            llamadas[call_id]["sdp"]['llamado'] = {
                                    "ip": sdp_ip,
                                    "port": int(sdp_port),
                                    "codecs": sdp_codecs,
                                }


paquetes_rtp_no_asociados = []

def procesar_rtp(paquete):
    global llamadas, paquetes_rtp_no_asociados
    ip_origen = paquete[IP].src
    puerto_origen = paquete[UDP].sport

    asociado = False

    with lock_llamadas:
        for call_id, data in llamadas.items():
            if "sdp" in data and data["sdp"]:
                sdp_info1 = data["sdp"]['llamante']
                sdp_info2 = data["sdp"]['llamado']
                if sdp_info1["ip"] == ip_origen and sdp_info1["port"] == puerto_origen:
                    # RTP entrante
                    llamadas[call_id]["rtp"].append(paquete)
                    # Actualizar última actividad SIP
                    llamadas[call_id]["ultima_actividad_rtp"] = paquete.time
                    asociado = True
                    break
                elif sdp_info2["ip"] == ip_origen and sdp_info2["port"] == puerto_origen:
                    # RTP saliente
                    llamadas[call_id]["rtp"].append(paquete)
                    
                    # Actualizar última actividad SIP
                    llamadas[call_id]["ultima_actividad_rtp"] = paquete.time
                    asociado = True
                    break


def monitorear_inactividad(filtros,interfaz):
    """
    Monitorea las llamadas basándose en los timestamps y tiempo de inactividad.
    Detecta:
    1. BYE con respuesta.
    2. BYE sin respuesta.
    3. Inactividad general.
    """
    global llamadas

    while True:
        time.sleep(1)  # Intervalo para revisar
        with lock_llamadas:
            for call_id, data in list(llamadas.items()):

                if llamadas[call_id]["num_paquetes"] == len(llamadas[call_id]["sip"]) + len(llamadas[call_id]["rtp"]):
                    llamadas[call_id]["inactividad"] += 1
                else:
                    llamadas[call_id]["inactividad"] = 0
                    llamadas[call_id]["num_paquetes"] = len(llamadas[call_id]["sip"]) + len(llamadas[call_id]["rtp"])

                # Caso 2: Verificar inactividad general (sin BYE)
                if  llamadas[call_id]["inactividad"] >= TIEMPO_INACTIVIDAD:
                    imprimir_llamada(call_id, "Inactividad general",filtros,interfaz)
                    #del llamadas[call_id]
                
                if llamadas[call_id]["bye_detected"] == True and llamadas[call_id]["bye_responded"] == True:
                    imprimir_llamada(call_id, "BYE",filtros,interfaz)

def imprimir_llamada(call_id, motivo, filtros, interfaz):
    global llamadas
    data = llamadas.get(call_id, {})
    if len(data['rtp']) == 0:
        #print("No hay paquetes rtp")
        del llamadas[call_id]
        #print(len(llamadas))
        return
    pkt_inicial = data['rtp'][0]
    pkt_final = data['rtp'][-1]
    sip_inicial = data['sip'][0]
    sip_final = data['sip'][-1]
    protocolo_transporte = ""
    if UDP in sip_inicial:
        payload = sip_inicial[UDP].load.decode("utf-8", errors="ignore")
        ip_origen = sip_inicial[IP].src
        ip_destino = sip_inicial[IP].dst
        puerto_origen = sip_inicial[UDP].sport
        puerto_destino = sip_inicial[UDP].dport
        protocolo_transporte = "UDP"
    elif TCP in sip_inicial:
        payload = sip_inicial[TCP].payload.load.decode("utf-8", errors="ignore")
        ip_origen = sip_inicial[IP].src
        ip_destino = sip_inicial[IP].dst
        puerto_origen = sip_inicial[TCP].sport
        puerto_destino = sip_inicial[TCP].dport
        protocolo_transporte = "TCP"
    payload_inicial = sip_inicial[UDP].load.decode("utf-8", errors="ignore")
    # Extraer información adicional SIP y SDP del primer paquete INVITE
    info_sip_inicial = extraer_campos_sip(payload_inicial, filtros)
    tiempo_inicial = pkt_inicial.time
    tiempo_final = pkt_final.time
    duracion_llamada = tiempo_final - tiempo_inicial
    # Extraer información del último paquete
    payload_final = sip_final[UDP].load.decode("utf-8", errors="ignore") if UDP in sip_final else sip_final[TCP].payload.load.decode("utf-8", errors="ignore")
    info_sip_final = extraer_campos_sip(payload_final, filtros)
    user_a_llamante, user_a_llamado, mensaje_to, p_asserted, uri_sip, p_charging_vector = extraer_user_agent(data['sip'])
    pdd = calcular_pdd(data['sip'])
    duracion_facturable = calcular_duracion_facturable(data['sip'])


    ip_rtp_llamante = data['sdp']['llamante']['ip']
    puerto_rtp_llamante = data['sdp']['llamante']['port']
    rtp_codecs_llamante = data['sdp']['llamante']['codecs']
    ip_rtp_llamado = data['sdp']['llamado']['ip']
    puerto_rtp_llamado = data['sdp']['llamado']['port']
    rtp_codecs_llamado = data['sdp']['llamado']['codecs']
    # Filtrar paquetes RTP de acuerdo a IP y puerto
    paquetes_rtp_llamante = filtrar_paquetes_rtp(data['rtp'], ip_rtp_llamante, puerto_rtp_llamante)
    paquetes_rtp_llamado = filtrar_paquetes_rtp(data['rtp'], ip_rtp_llamado, puerto_rtp_llamado)

    # Análisis RTP para ambas direcciones
    num_paquetes_llamante, bytes_llamante, perdida_llamante, jitter_llamante,jitter_max_llamante,jitter_min_llamante,duracion_llamante = analizar_rtp(paquetes_rtp_llamante)
    num_paquetes_llamado, bytes_llamado, perdida_llamado, jitter_llamado,jitter_max_llamado,jitter_min_llamado,duracion_llamado = analizar_rtp(paquetes_rtp_llamado)
    '''
    if data["bye_detected"] == True and data["bye_responded"] == True:
        motivo = "BYE"
    else:
        motivo = "TIMEOUT"
        '''
    print(f"Call-ID: {call_id}")
    print(f"  Paquetes SIP: {len(data['sip'])}")
    print(f"  Paquetes RTP: {len(data['rtp'])}")
    print(f"Begin: {tiempo_inicial:.6f}")
    print(f"End: {tiempo_final:.6f}")
    print(f"Source port: {puerto_origen}")
    print(f"Destination port: {puerto_destino}")
    print(f"Source IP: {ip_origen}")
    print(f"Destination IP: {ip_destino}")
    print(f"Transport protocol: {protocolo_transporte}")
    if info_sip_inicial:
        for campo, valor in info_sip_inicial.items():
            print(f"{valor}")
    print(f"Caller duration: {duracion_llamada:.6f}")
    print(f"Callee duration: {duracion_llamada:.6f}")  # Esto puede variar si calculas individualmente llamante y llamado
    print(f"Caller last message: {info_sip_final}")
    print(f"Callee last message: {info_sip_final}")
    print(f"PCAP file (interfaz): {interfaz}")
    print(f"VLAN1: N/A")
    print(f"VLAN2: N/A")
    print(f"Caller User Agent: {user_a_llamante}")
    print(f"Callee User Agent: {user_a_llamado}")  # Esto se extraería de un 200 OK o último mensaje SIP
    print(f"To200: {mensaje_to}")  # Esto también depende del 200 OK
    print(f"Passerted: {p_asserted}")
    print(f"Sipuri: {uri_sip}")
    print(f"P_Charging_Vector: {p_charging_vector}")
    print(f"PDD: {pdd}")
    print(f"Duracion Factuable: {duracion_facturable}")  # Depende de la diferencia entre 200 OK y BYE
    print(f"Motivo cierre: {motivo}")  # BYE, CANCEL o TIMEOUT
    print(f"Reason: N/A")  # Extraído del campo REASON
    print(f"RTP caller port: {puerto_rtp_llamante}")
    print(f"RTP callee port: {puerto_rtp_llamado}")
    print(f"RTP IP caller: {ip_rtp_llamante}")
    print(f"RTP IP callee: {ip_rtp_llamado}")
    print(f"Caller mediatype: {rtp_codecs_llamante}")
    print(f"Callee mediatype: {rtp_codecs_llamado}")
    print(f"RTP Npack caller: {num_paquetes_llamante}")  # Esto requeriría contar los paquetes RTP
    print(f"RTP Npack callee: {num_paquetes_llamado}")
    print(f"RTP bytes caller: {bytes_llamante}")  # Se puede calcular el total de bytes RTP
    print(f"RTP bytes callee: {bytes_llamado}")
    print(f"Ratio loss caller: {perdida_llamante}")
    print(f"Ratio loss callee: {perdida_llamado}")
    print(f"RTP inter caller: {jitter_llamante}")
    print(f"RTP inter callee: {jitter_llamado}")
    print(f"RTP max inter caller: {jitter_max_llamante}")
    print(f"RTP max inter callee: {jitter_max_llamado}")
    print(f"RTP min inter caller: {jitter_min_llamante}")
    print(f"RTP min inter callee: {jitter_min_llamado}")
    print(f"RTP dur caller: {duracion_llamante}")
    print(f"RTP dur callee: {duracion_llamado}")
    print("-" * 50)
    del llamadas[call_id]




def capturar_paquetes(interfaz):
    """
    Captura paquetes SIP y RTP desde una interfaz y mide el rendimiento en tiempo real.

    :param interfaz: Nombre de la interfaz de red desde la cual capturar los paquetes.
    """
    print(f"Iniciando captura de tráfico en la interfaz {interfaz}...")

    total_paquetes = 0
    total_bytes = 0
    start_time = time.time()

    def manejar_paquete(paquete):
        nonlocal total_paquetes, total_bytes
        with lock_cola:
            cola_paquetes.append(paquete)  # Añade cada paquete a la cola
        total_paquetes += 1
        total_bytes += len(paquete)

    try:
        while not stop_sniffing_event.is_set():
            sniff(iface=interfaz, prn=manejar_paquete, store=False, timeout=1)
    except Exception as e:
        print(f"Ocurrió un error al capturar tráfico en la interfaz {interfaz}: {e}")
    finally:
        elapsed_time = time.time() - start_time

        if elapsed_time > 0:
            tasa_paquetes = total_paquetes / elapsed_time
            tasa_bits = (total_bytes * 8) / elapsed_time

            print(f"Rendimiento:")
            print(f" - Tasa de paquetes: {tasa_paquetes:.2f} paquetes/s")
            print(f" - Tasa de bits: {tasa_bits:.2f} bits/s")

        print(f"Finalizada la captura de tráfico en la interfaz {interfaz}.")



def leer_paquetes_de_pcap(archivo_pcap):
    """
    Lee paquetes SIP y RTP desde un archivo PCAP y mide el rendimiento en tiempo real.

    :param archivo_pcap: Ruta al archivo PCAP que contiene los paquetes a procesar.
    """
    print(f"Iniciando lectura de tráfico desde el archivo {archivo_pcap}...")

    total_paquetes = 0
    total_bytes = 0
    start_time = time.time()

    try:
        # Usamos pyshark para procesar el archivo PCAP
        captura = pyshark.FileCapture(archivo_pcap)

        for paquete in captura:
            with lock_cola:
                cola_paquetes.append(paquete)  # Añade cada paquete a la cola

            total_paquetes += 1

            # Calculamos el tamaño del paquete (si tiene capa raw, usamos eso)
            if hasattr(paquete, 'length'):
                total_bytes += int(paquete.length)
            elif hasattr(paquete, 'frame_info'):
                total_bytes += int(paquete.frame_info.len)
            else:
                total_bytes += len(str(paquete))

        elapsed_time = time.time() - start_time

        if elapsed_time > 0:
            tasa_paquetes = total_paquetes / elapsed_time
            tasa_bits = (total_bytes * 8) / elapsed_time

            print(f"Rendimiento:")
            print(f" - Tasa de paquetes: {tasa_paquetes:.2f} paquetes/s")
            print(f" - Tasa de bits: {tasa_bits:.2f} bits/s")

        print(f"Finalizada la lectura de paquetes desde {archivo_pcap}.")
    except FileNotFoundError:
        print(f"El archivo {archivo_pcap} no existe.")
    except Exception as e:
        print(f"Ocurrió un error al procesar el archivo {archivo_pcap}: {e}")

def signal_handler(sig, frame):
    """Manejador de señal para Ctrl+C."""
    print("\nDetección de Ctrl+C. Deteniendo captura...")
    stop_sniffing_event.set()

    # Deshabilitar el manejador de señales para evitar que se siga imprimiendo después
    signal.signal(signal.SIGINT, signal.SIG_DFL)

# Configuración de hilos
def iniciar_capturas(tipo, interfaz, filtros):
    """
    Inicia hilos para capturar tráfico, procesar paquetes y mostrar las llamadas periódicamente.
    """
    try:
        if str(tipo) == '0':
            hilo_captura = threading.Thread(target=capturar_paquetes, args=(interfaz,))
        else:
            print("Archivo")
            hilo_captura = threading.Thread(target=leer_paquetes_de_pcap, args=(interfaz,))

        hilo_procesamiento = threading.Thread(target=procesar_paquetes)
        hilo_imprimir = threading.Thread(target=monitorear_inactividad, args=(filtros, interfaz,))

        # Iniciar hilos
        hilo_captura.start()
        hilo_procesamiento.start()
        hilo_imprimir.start()

        # Monitorear los hilos y procesar señales
        while hilo_captura.is_alive() or hilo_procesamiento.is_alive() or hilo_imprimir.is_alive():
            time.sleep(0.1)  # Evitar consumo excesivo de CPU

    except Exception as e:
        print(f"Error al iniciar las capturas: {e}")

    finally:
        stop_sniffing_event.set()
        # Esperar que todos los hilos terminen
        hilo_captura.join()
        hilo_procesamiento.join()
        hilo_imprimir.join()
        print("Todos los hilos se han detenido correctamente.")




# Configuración principal
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python capturar_trafico.py tipo(0 si interfaz y 1 si pcap) <interfaz o pcap> filtros...")
        sys.exit(1)


    # Registrar el manejador de señales para Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    tipo = sys.argv[1]
    interfaz = sys.argv[2]
    filtros = sys.argv[3:]
    iniciar_capturas(tipo, interfaz,filtros)
