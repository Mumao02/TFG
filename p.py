import math
import sys
import threading
from scapy.all import sniff, IP, UDP, TCP, PcapReader
import time
from collections import deque, defaultdict
import signal
import pcapy
from struct import unpack
import multiprocessing

# Variable global para detener los hilos
detener = False

# Variables globales
cola_paquetes = deque()  # Cola centralizada para paquetes en orden de llegada
llamadas = defaultdict(lambda: {
    "sip": [],  # Paquetes SIP asociados a la llamada
    "sip_headers":[],
    "rtp": [],  # Paquetes RTP asociados a la llamada
    "rtp_headers":[],
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
TIEMPO_INACTIVIDAD = 60  # Tiempo de inactividad en segundos para considerar una llamada inactiva
# Rango de puertos RTP (ajusta estos valores según lo necesites)
PUERTOS_RTP = range(16384, 32768)


# Calcular estadísticas RTP: número de paquetes, bytes, jitter y pérdida de paquetes
def analizar_rtp(paquetes_rtp,time):
    num_paquetes = len(paquetes_rtp)
    total_bytes = sum(len(pkt) for pkt in paquetes_rtp)
    jitter_total = 0
    perdida_paquetes = 0
    ultimo_num_seq = None
    ultimo_tiempo = None
    jitter_max=0
    jitter_min= math.inf

    for indice, pkt in enumerate(paquetes_rtp):
        rtp_payload = pkt[42:]  # Todo lo que queda después de la cabecera Ethernet (14) + IP (20) + UDP (8)
        num_seq = (rtp_payload[2] << 8) | rtp_payload[3]  # Combinar los bytes alto y bajo
        tiempo_inicial_tuple = time[indice].getts()  # (segundos, microsegundos)
        # Convertir a un único valor en segundos
        tiempo_inicial = tiempo_inicial_tuple[0] + tiempo_inicial_tuple[1] / 1000000
        tiempo_marca = tiempo_inicial
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
        tiempo_inicial_tuple = time[0].getts()  # (segundos, microsegundos)
        # Convertir a un único valor en segundos
        tiempo_inicial = tiempo_inicial_tuple[0] + tiempo_inicial_tuple[1] / 1000000
        tiempo_final_tuple = time[indice].getts()  # (segundos, microsegundos)
        # Convertir a un único valor en segundos
        tiempo_final = tiempo_final_tuple[0] + tiempo_final_tuple[1] / 1000000
        duracion = tiempo_final - tiempo_inicial
    jitter_promedio = jitter_total / num_paquetes if num_paquetes > 0 else 0
    return num_paquetes, total_bytes, perdida_paquetes, jitter_promedio, jitter_max, jitter_min, duracion

# Filtrar paquetes RTP correspondientes a un flujo basado en IP y puerto
def filtrar_paquetes_rtp(paquetes, ip_rtp, puerto_rtp,headers):
    paquetes_rtp = []
    headers_rtp = []
    for indice, pkt in enumerate(paquetes):
        ip_header = pkt[14:34]  # Cabecera IP
        udp_header = pkt[34:42]  # Cabecera UDP
        ip_src = unpack('!4B', ip_header[12:16])  # IP origen
        ip_dst = unpack('!4B', ip_header[16:20])  # IP destino
        ip_origen = '.'.join(map(str, ip_src))
        ip_destino = '.'.join(map(str, ip_dst))

        udp_hdr = unpack('!HHHH', udp_header)  # Desempaquetar la cabecera UDP
        puerto_origen = udp_hdr[0]  # Puerto origen
        puerto_destino = udp_hdr[1]  # Puerto destino
        if puerto_origen == puerto_rtp and ip_origen == ip_rtp:
            paquetes_rtp.append(pkt)
            headers_rtp.append(headers[indice])
    return paquetes_rtp, headers_rtp

def calcular_duracion_facturable(paquetes_sip,time):
    tiempo_ok = None
    tiempo_bye = None
    duracion_facturable = None

    for indice, pkt in enumerate(paquetes_sip):
        # Obtener el contenido del paquete
        payload = pkt[42:]  # Todo lo que queda después de la cabecera Ethernet (14) + IP (20) + UDP (8)
        payload = payload.decode("utf-8", errors="ignore")

        # Buscar el 200 OK
        if "200 OK" in payload:
            tiempo_inicial_tuple = time[indice].getts()  # (segundos, microsegundos)
            # Convertir a un único valor en segundos
            tiempo_inicial = tiempo_inicial_tuple[0] + tiempo_inicial_tuple[1] / 1000000
            tiempo_ok = tiempo_inicial

        es_req, metodo_sip, uri_sip = es_request(payload)
        # Buscar el BYE
        if es_req and "BYE" in metodo_sip:
            tiempo_inicial_tuple = time[indice].getts()  # (segundos, microsegundos)
            # Convertir a un único valor en segundos
            tiempo_inicial = tiempo_inicial_tuple[0] + tiempo_inicial_tuple[1] / 1000000
            tiempo_bye = tiempo_inicial

        # Si ambos tiempos se han capturado, calcular la duración
        if tiempo_ok and tiempo_bye:
            duracion_facturable = tiempo_bye - tiempo_ok
            break  # Salir después de calcular la duración facturable

    # Retornar la duración en segundos y microsegundos
    if duracion_facturable is not None:
        return duracion_facturable  # Ejemplo: 12.345678 segundos
    else:
        return None  # Si no se encontraron los mensajes 200 OK o BYE

def calcular_pdd(paquetes_sip, time):
    pdd = None
    tiempo_invite = None
    tiempo_trying = None
    tiempo_ringing = None

    for indice, pkt in enumerate(paquetes_sip):
        # Obtener el tiempo de la llamada INVITE
        payload = pkt[42:]  # Todo lo que queda después de la cabecera Ethernet (14) + IP (20) + UDP (8)
        payload = payload.decode("utf-8", errors="ignore")
        es_req, metodo_sip, uri_sip = es_request(payload)
        # Buscar el BYE
        if es_req and "INVITE" in metodo_sip:
            tiempo_inicial_tuple = time[indice].getts()  # (segundos, microsegundos)
            # Convertir a un único valor en segundos
            tiempo_inicial = tiempo_inicial_tuple[0] + tiempo_inicial_tuple[1] / 1000000
            tiempo_invite = tiempo_inicial
        
        # Comprobar si el paquete es una respuesta 100 TRYING
        if "SIP/2.0 100 Trying" in payload:
            tiempo_inicial_tuple = time[indice].getts()  # (segundos, microsegundos)
            # Convertir a un único valor en segundos
            tiempo_inicial = tiempo_inicial_tuple[0] + tiempo_inicial_tuple[1] / 1000000
            tiempo_trying = tiempo_inicial
        
        # Comprobar si el paquete es una respuesta 180 RINGING
        if "SIP/2.0 180 Ringing" in payload:
            tiempo_inicial_tuple = time[indice].getts()  # (segundos, microsegundos)
            # Convertir a un único valor en segundos
            tiempo_inicial = tiempo_inicial_tuple[0] + tiempo_inicial_tuple[1] / 1000000
            tiempo_ringing = tiempo_inicial

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
        payload = pkt[42:]  # Todo lo que queda después de la cabecera Ethernet (14) + IP (20) + UDP (8)
        payload = payload.decode("utf-8", errors="ignore")
        es_req, metodo_sip, uri_sip = es_request(payload)
        if es_req and str(metodo_sip) == 'INVITE':
            if "User-Agent" in payload:
                # Extrae el User-Agent
                llamante = payload.split("User-Agent: ")[1].split("\r\n")[0]
            uri_sip = uri_sip
        es_res, codigo_sip, estado = es_response(payload)
        if es_res and codigo_sip == "200" and estado == "OK":
            if "User-Agent" in payload:
                # Extrae el User-Agent
                llamado = payload.split("User-Agent: ")[1].split("\r\n")[0]
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

def es_paquete_sip(paquete):
    """
    Verifica si un paquete es SIP. Asumimos que SIP usa el puerto 5060.
    """
    try:
        # La IP comienza en el byte 14 (después de la cabecera Ethernet)
        ip_header = paquete[14:34]
        ip_hdr = unpack('!BBHHHBBH4s4s', ip_header)

        # Extraer puertos UDP (comienzan después de la cabecera IP)
        udp_header = paquete[34:42]  # Los primeros 8 bytes después de la cabecera IP
        udp_hdr = unpack('!HHHH', udp_header)

        sport = udp_hdr[0]
        dport = udp_hdr[1]
        if sport == 5060 or dport == 5060:
            return True
    except Exception:
        return False
    return False


def es_paquete_rtp(paquete):
    """
    Verifica si un paquete es RTP. Usamos el rango de puertos UDP.
    """
    try:
        # La IP comienza en el byte 14 (después de la cabecera Ethernet)
        ip_header = paquete[14:34]
        ip_hdr = unpack('!BBHHHBBH4s4s', ip_header)

        # Extraer puertos UDP (comienzan después de la cabecera IP)
        udp_header = paquete[34:42]  # Los primeros 8 bytes después de la cabecera IP
        udp_hdr = unpack('!HHHH', udp_header)
        sport, dport = udp_hdr[0], udp_hdr[1]

        # Comprobar si el paquete está en el rango de puertos RTP
        if sport in PUERTOS_RTP or dport in PUERTOS_RTP:
            return True
    except Exception:
        return False
    return False

# Función para procesar paquetes
def procesar_paquetes():
    """
    Procesa los paquetes en la cola en orden de llegada y agrupa llamadas inactivas.
    """
    global cola_paquetes,detener

    while detener != True:
        time.sleep(1)  # Ajusta el intervalo según sea necesario
        # Procesar paquetes en la cola
        with lock_cola:
            while cola_paquetes:
                header, paquete = cola_paquetes.popleft()  # Extraer paquete de la cola
                # Asegúrate de que el paquete sea de longitud suficiente
                if es_paquete_sip(paquete):
                    #print("Paquete SIP detectado.")
                    procesar_sip(header,paquete)
                    # Aquí puedes agregar código para procesar SIP (si es necesario)
                elif es_paquete_rtp(paquete):
                    #print("Paquete RTP detectado.")
                    procesar_rtp(header,paquete)
                    # Aquí puedes agregar código para procesar RTP (si es necesario)


def procesar_sip(header,paquete):
    """
    Procesa paquetes SIP y extrae información SDP.
    """
    global llamadas

    try:
        # Extraemos la cabecera Ethernet (14 bytes)
        ethernet_header = paquete[0:14]  # La cabecera Ethernet es siempre de 14 bytes

        # Extraemos la cabecera IP (20 bytes estándar sin opciones)
        ip_header = paquete[14:34]  # Después de la cabecera Ethernet, comienza la IP (14 bytes + 20 bytes)
        
        # Extraemos la cabecera UDP (8 bytes)
        udp_header = paquete[34:42]  # Después de la cabecera IP (14 + 20 bytes = 34), comienza la UDP (8 bytes)
        udp_hdr = unpack('!HHHH', udp_header)  # Desempaquetamos cabecera UDP
        sport, dport = udp_hdr[0], udp_hdr[1]

        # Verificar si es un paquete SIP (usualmente usa el puerto 5060)
        if sport == 5060 or dport == 5060:
            # Extraemos la carga útil (todo después de la cabecera UDP)
            carga_util = paquete[42:]  # Todo lo que queda después de la cabecera Ethernet (14) + IP (20) + UDP (8)

            try:
                # Decodificamos la carga útil en formato UTF-8
                payload = carga_util.decode("utf-8", errors="ignore")
                timestamp_paquete = header.getts()  # Esto te da el tiempo de captura del paquete
                # Extraer el Call-ID de la carga útil (ejemplo de función para extraerlo)
                call_id = extraer_call_id(payload)
                if call_id:
                    with lock_llamadas:
                        # Verificar si el call_id ya existe
                        if call_id not in llamadas:
                            llamadas[call_id] = {"sip": [],"sip_headers":[], "rtp": [],"rtp_headers":[], "sdp": {}, "ultima_actividad_sip": None, "ultima_actividad_rtp": None}

                        # Actualizar la información de la llamada
                        llamadas[call_id]["sip"].append(paquete)
                        llamadas[call_id]["sip_headers"].append(header)
                        if "num_paquetes" not in llamadas[call_id]:
                            llamadas[call_id]["num_paquetes"] = 0
                        llamadas[call_id]["num_paquetes"] += 1

                        # Identificar mensajes BYE y 200 OK
                        es_req, metodo_sip, _ = es_request(payload)
                        es_res, codigo_sip, _ = es_response(payload)

                        if es_req and metodo_sip == "BYE":
                            llamadas[call_id]["bye_time"] = timestamp_paquete
                            llamadas[call_id]["bye_detected"] = True

                        if es_res and codigo_sip == "200":
                            llamadas[call_id]["ok_time"] = timestamp_paquete
                            if "bye_detected" in llamadas[call_id] and llamadas[call_id]["bye_detected"]:
                                llamadas[call_id]["bye_responded"] = True

                        # Actualizar última actividad SIP
                        llamadas[call_id]["ultima_actividad_sip"] = timestamp_paquete

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
            except Exception as e:
                print(f"Error al procesar carga útil SIP: {e}")
    except Exception as e:
        print(f"Error al procesar paquete SIP: {e}")


paquetes_rtp_no_asociados = []

def procesar_rtp(header,paquete):
    global llamadas, paquetes_rtp_no_asociados

    # Desempaquetar la cabecera IP (20 bytes) y UDP (8 bytes) para obtener la IP y los puertos
    ip_header = paquete[14:34]  # Cabecera IP
    udp_header = paquete[34:42]  # Cabecera UDP
    ip_src = unpack('!4B', ip_header[12:16])  # IP origen
    ip_dst = unpack('!4B', ip_header[16:20])  # IP destino
    ip_origen = '.'.join(map(str, ip_src))
    ip_destino = '.'.join(map(str, ip_dst))

    udp_hdr = unpack('!HHHH', udp_header)  # Desempaquetar la cabecera UDP
    puerto_origen = udp_hdr[0]  # Puerto origen
    puerto_destino = udp_hdr[1]  # Puerto destino

    asociado = False
    timestamp_paquete = header.getts()  # Esto te da el tiempo de captura del paquete
    # Procesar las llamadas y asociar el paquete RTP
    with lock_llamadas:
        for call_id, data in llamadas.items():
            if "sdp" in data and data["sdp"]:
                sdp_info1 = data["sdp"].get('llamante', {})
                sdp_info2 = data["sdp"].get('llamado', {})
                if sdp_info1 and sdp_info1["ip"] == ip_origen and sdp_info1["port"] == puerto_origen:
                    # RTP entrante
                    llamadas[call_id]["rtp"].append(paquete)
                    llamadas[call_id]["rtp_headers"].append(header)
                    # Actualizar última actividad RTP
                    llamadas[call_id]["ultima_actividad_rtp"] = timestamp_paquete
                    if "num_paquetes" not in llamadas[call_id]:
                        llamadas[call_id]["num_paquetes"] = 0
                    llamadas[call_id]["num_paquetes"] += 1
                    asociado = True
                    break
                elif sdp_info2 and sdp_info2["ip"] == ip_origen and sdp_info2["port"] == puerto_origen:
                    # RTP saliente
                    llamadas[call_id]["rtp"].append(paquete)
                    llamadas[call_id]["rtp_headers"].append(header)
                    # Actualizar última actividad RTP
                    llamadas[call_id]["ultima_actividad_rtp"] = timestamp_paquete
                    if "num_paquetes" not in llamadas[call_id]:
                        llamadas[call_id]["num_paquetes"] = 0
                    llamadas[call_id]["num_paquetes"] += 1
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
    global llamadas,detener

    while detener != True:
        time.sleep(1)  # Intervalo para revisar
        with lock_llamadas:
            for call_id, data in list(llamadas.items()):
                if "inactividad" not in llamadas[call_id]:
                        llamadas[call_id]["inactividad"] = 0
                if llamadas[call_id]["num_paquetes"] == len(llamadas[call_id]["sip"]) + len(llamadas[call_id]["rtp"]):
                    llamadas[call_id]["inactividad"] += 1
                else:
                    llamadas[call_id]["inactividad"] = 0
                    llamadas[call_id]["num_paquetes"] = len(llamadas[call_id]["sip"]) + len(llamadas[call_id]["rtp"])

                # Caso 2: Verificar inactividad general (sin BYE)
                if  llamadas[call_id]["inactividad"] >= TIEMPO_INACTIVIDAD:
                    imprimir_llamada(call_id, "Inactividad general",filtros,interfaz)
                    #del llamadas[call_id]
                if "bye_detected" not in llamadas[call_id]:
                        llamadas[call_id]["bye_detected"] = False
                if "bye_responded" not in llamadas[call_id]:
                        llamadas[call_id]["bye_responded"] = False
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

    ip_header = sip_inicial[14:34]
    ip_hdr = unpack('!BBHHHBBH4s4s', ip_header)  # Desempaquetar la cabecera IP
    ip_version_ihl = ip_hdr[0]
    ip_length = (ip_version_ihl & 0x0F) * 4  # Longitud de la cabecera IP en bytes

    if len(sip_inicial) < 14 + ip_length:  # Validar longitud total del paquete
        return {"error": "Paquete incompleto para analizar IP"}

    # Extraer campos de la cabecera IP
    protocolo = ip_hdr[6]  # Campo de protocolo
    ip_origen = ".".join(map(str, ip_hdr[8]))  # Dirección IP origen
    ip_destino = ".".join(map(str, ip_hdr[9]))  # Dirección IP destino

    # Determinar el inicio de la cabecera de transporte (UDP/TCP)
    transport_header_start = 14 + ip_length

    # Verificar longitud suficiente para la cabecera de transporte (8 bytes mínimo)
    if len(sip_inicial) < transport_header_start + 8:
        return {"error": "Paquete demasiado corto para analizar cabecera de transporte"}

    # Extraer cabecera UDP o TCP y los puertos
    transport_header = sip_inicial[transport_header_start:transport_header_start + 8]
    puerto_origen, puerto_destino = unpack('!HH', transport_header[:4])
    if protocolo == 6:  # TCP
        protocolo_transporte = "TCP"
    elif protocolo == 17:  # UDP
        protocolo_transporte = "UDP"
    else:
        protocolo_transporte = "Desconocido"
    payload_inicial = sip_inicial[42:]  # Todo lo que queda después de la cabecera Ethernet (14) + IP (20) + UDP (8)
    payload_inicial = payload_inicial.decode("utf-8", errors="ignore")
    # Extraer información adicional SIP y SDP del primer paquete INVITE
    info_sip_inicial = extraer_campos_sip(payload_inicial, filtros)
    tiempo_inicial_tuple = data['rtp_headers'][0].getts()  # (segundos, microsegundos)
    tiempo_final_tuple = data['rtp_headers'][-1].getts()  # (segundos, microsegundos)

    # Convertir a un único valor en segundos
    tiempo_inicial = tiempo_inicial_tuple[0] + tiempo_inicial_tuple[1] / 1000000
    tiempo_final = tiempo_final_tuple[0] + tiempo_final_tuple[1] / 1000000
    duracion_llamada = tiempo_final - tiempo_inicial
    # Extraer información del último paquete
    payload_final = sip_final[42:]  # Todo lo que queda después de la cabecera Ethernet (14) + IP (20) + UDP (8)
    payload_final = payload_final.decode("utf-8", errors="ignore")
    info_sip_final = extraer_campos_sip(payload_final, filtros)
    user_a_llamante, user_a_llamado, mensaje_to, p_asserted, uri_sip, p_charging_vector = extraer_user_agent(data['sip'])
    pdd = calcular_pdd(data['sip'],data['sip_headers'])
    duracion_facturable = calcular_duracion_facturable(data['sip'],data['sip_headers'])


    ip_rtp_llamante = data['sdp']['llamante']['ip']
    puerto_rtp_llamante = data['sdp']['llamante']['port']
    rtp_codecs_llamante = data['sdp']['llamante']['codecs']
    ip_rtp_llamado = data['sdp']['llamado']['ip']
    puerto_rtp_llamado = data['sdp']['llamado']['port']
    rtp_codecs_llamado = data['sdp']['llamado']['codecs']
    # Filtrar paquetes RTP de acuerdo a IP y puerto
    paquetes_rtp_llamante, header_llamante = filtrar_paquetes_rtp(data['rtp'], ip_rtp_llamante, puerto_rtp_llamante,data['rtp_headers'])
    paquetes_rtp_llamado, header_llamado = filtrar_paquetes_rtp(data['rtp'], ip_rtp_llamado, puerto_rtp_llamado,data['rtp_headers'])

    # Análisis RTP para ambas direcciones
    num_paquetes_llamante, bytes_llamante, perdida_llamante, jitter_llamante,jitter_max_llamante,jitter_min_llamante,duracion_llamante = analizar_rtp(paquetes_rtp_llamante,header_llamante)
    num_paquetes_llamado, bytes_llamado, perdida_llamado, jitter_llamado,jitter_max_llamado,jitter_min_llamado,duracion_llamado = analizar_rtp(paquetes_rtp_llamado,header_llamado)
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

def capturar_paquetes(interfaz,tiempo_maximo):
    """
    Captura paquetes SIP y RTP desde una interfaz y mide el rendimiento en tiempo real.

    :param interfaz: Nombre de la interfaz de red desde la cual capturar los paquetes.
    """
    print(f"Iniciando captura de tráfico en la interfaz {interfaz}...")

    global detener
    start_time = time.time()
    total_paquetes = 0
    total_bytes = 0
    def manejar_paquete(header, data):
        nonlocal total_paquetes, total_bytes
        with lock_cola:
            cola_paquetes.append((header, data))  # Añade el paquete a la cola
        total_paquetes += 1
        total_bytes += header.getlen()
    try:
        cap = pcapy.open_live(interfaz, 0, 1, 0)  # Buffer infinito, modo promiscuo, timeout 1s
        while time.time() - start_time < tiempo_maximo and detener != True:
            # Leer el siguiente paquete
            try:
                header, packet = cap.next()
                if header is not None:
                    manejar_paquete(header, packet)
            except pcapy.PcapError:
                # Si no se captura nada en este intervalo, continuar
                continue
        elapsed_time = time.time() - start_time

        if elapsed_time > 0:
            tasa_paquetes = total_paquetes / elapsed_time
            tasa_bits = (total_bytes * 8) / elapsed_time

            print(f"Rendimiento:")
            print(f" - Tasa de paquetes: {tasa_paquetes:.2f} paquetes/s")
            print(f" - Tasa de bits: {tasa_bits:.2f} bits/s")

        print(f"Finalizada la captura de tráfico en la interfaz {interfaz}.")
    except Exception as e:
        print(f"Ocurrió un error al capturar tráfico en la interfaz {interfaz}: {e}")



def leer_paquetes_de_pcap(archivo_pcap):
    """
    Lee paquetes SIP y RTP desde un archivo PCAP y mide el rendimiento en tiempo real.

    :param archivo_pcap: Ruta al archivo PCAP que contiene los paquetes a procesar.
    """
    print(f"Iniciando lectura de tráfico desde el archivo {archivo_pcap}...")
    global detener
    total_bytes = 0
    start_time = time.time()
    paquetes_procesados = 0

    try:
        # Abrir el archivo PCAP en modo offline
        capturador = pcapy.open_offline(archivo_pcap)
        print("Archivo cargado exitosamente.")

        while detener != True:
            # Leer el siguiente paquete
            header, paquete = capturador.next()
            if not header:
                break  # No hay más paquetes

            with lock_cola:
                cola_paquetes.append((header, paquete))  # Añadir paquete a la cola
                paquetes_procesados += 1  # Incrementar contador global

            total_bytes += header.getlen()

        elapsed_time = time.time() - start_time

        # Calcular tasas de rendimiento
        if elapsed_time > 0:
            tasa_paquetes = paquetes_procesados / elapsed_time
            tasa_bits = (total_bytes * 8) / elapsed_time

            print("\nRendimiento:")
            print(f" - Tasa de paquetes: {tasa_paquetes:.2f} paquetes/s")
            print(f" - Tasa de bits: {tasa_bits:.2f} bits/s")

        print(f"Lectura finalizada. Total de paquetes procesados: {paquetes_procesados}")
    except FileNotFoundError:
        print(f"El archivo {archivo_pcap} no existe.")
    except pcapy.PcapError as e:
        print(f"Error al procesar el archivo {archivo_pcap}: {e}")
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}")


# Configuración de hilos
def iniciar_capturas(tipo, interfaz, filtros):
    """
    Inicia hilos para capturar tráfico, procesar paquetes y mostrar las llamadas periódicamente.
    """
    global detener
    try:
        if str(tipo) == '0':
            tiempo_maximo = 0
            while tiempo_maximo < 1:
                tiempo_maximo = int(input("Introduce el tiempo máximo para la captura (en segundos y > 1 segundo): "))
            hilo_captura = threading.Thread(target=capturar_paquetes, args=(interfaz,tiempo_maximo,))
        else:
            print("Archivo")
            hilo_captura = threading.Thread(target=leer_paquetes_de_pcap, args=(interfaz,))

        hilo_procesamiento = threading.Thread(target=procesar_paquetes)
        hilo_imprimir = threading.Thread(target=monitorear_inactividad, args=(filtros, interfaz,))

        # Iniciar hilos
        hilo_captura.start()
        hilo_procesamiento.start()
        hilo_imprimir.start()

        while hilo_captura.is_alive() or hilo_procesamiento.is_alive() or hilo_imprimir.is_alive():
            time.sleep(0.1)  # Reduce el consumo de CPU
    except KeyboardInterrupt:
        print("\nControl+C detectado. Deteniendo todos los hilos...")
        detener = True  # Indicar a los hilos que deben detenerse
    except Exception as e:
        print(f"Error al iniciar las capturas: {e}")
    finally:
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


    tipo = sys.argv[1]
    interfaz = sys.argv[2]
    filtros = sys.argv[3:]
    iniciar_capturas(tipo, interfaz,filtros)