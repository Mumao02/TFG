import sys
import time
import math
from scapy.all import rdpcap, UDP, TCP
from scapy.layers.inet import IP

# Parámetros de temporización
tiempo_expirar = 60
tiempo_espera = 1
tiempo_inactividad = 10
grupos = {}

def filtrar_paquetes_por_tiempo(paquetes):
    if len(paquetes) < 2:
        return paquetes  # Si hay menos de 2 paquetes, no es necesario filtrar.

    # Inicializar la lista filtrada con el primer paquete.
    paquetes_filtrados = [paquetes[0]]

    for i in range(1, len(paquetes)):
        tiempo_anterior = paquetes[i-1].time
        tiempo_actual = paquetes[i].time

        # Calcular la diferencia de tiempo entre el paquete actual y el anterior.
        diferencia_tiempo = tiempo_actual - tiempo_anterior

        if diferencia_tiempo <= tiempo_expirar:
            # Si la diferencia es menor o igual a `tiempo_maximo`, añadir el paquete a la lista filtrada.
            paquetes_filtrados.append(paquetes[i])
        else:
            # Si la diferencia es mayor, detener el filtrado y retornar la lista filtrada.
            break

    return paquetes_filtrados

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
            print(tiempo_ok)

        es_req, metodo_sip, uri_sip = es_request(payload)
        # Buscar el BYE
        if es_req and "BYE" in metodo_sip:
            tiempo_bye = pkt.time
            print(tiempo_bye)

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
            uri_sip =uri_sip
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
    

# Filtrar paquetes RTP correspondientes a un flujo basado en IP y puerto
def filtrar_paquetes_rtp(paquetes, ip_rtp, puerto_rtp):
    paquetes_rtp = []
    for pkt in paquetes:
        if UDP in pkt and pkt[UDP].sport == puerto_rtp and pkt[IP].src == ip_rtp:
            paquetes_rtp.append(pkt)
    return paquetes_rtp

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


# Función para determinar si el paquete es probablemente RTP
def es_paquete_rtp(payload):
    if len(payload) < 12:  # Tamaño mínimo del encabezado RTP es 12 bytes
        return False, None, None  # Devuelve None para secuencia y timestamp

    # Verificar la versión RTP (los dos primeros bits del primer byte deben ser 10, lo que corresponde a la versión 2)
    version = (payload[0] >> 6) & 0x03
    if version != 2:
        return False, None, None  # Devuelve None para secuencia y timestamp

    # Verificar el Payload Type (entre 0 y 127)
    payload_type = payload[1] & 0x7F
    if not (0 <= payload_type <= 127):
        return False, None, None  # Devuelve None para secuencia y timestamp

    return True

# Cargar el archivo pcap
def detectar_rtp(archivo_pcap):
    paquetes = rdpcap(archivo_pcap)
    paquetes_rtp = []

    # Filtrar paquetes UDP y verificar si son RTP
    for pkt in paquetes:
        if UDP in pkt:
            payload = bytes(pkt[UDP].payload)
            resultado= es_paquete_rtp(payload)

            if resultado:
                paquetes_rtp.append(pkt)

    return paquetes_rtp
# Función para extraer el Call-ID de los paquetes SIP
def extraer_callid(payload):
    lineas = payload.splitlines()
    for linea in lineas:
        if "Call-ID:" in linea or "call-id:" in linea:
            return linea.split(":", 1)[1].strip()
    return None

# Función para crear una clave única que represente el par origen <-> destino
def crear_clave_origen_destino(ip_origen, ip_destino):
    return tuple(sorted([ip_origen, ip_destino]))

# Función para extraer los campos SIP relevantes del payload
def extraer_campos_sip(payload, filtros):
    info_sip = {}
    lineas = payload.splitlines()
    for linea in lineas:
        for filtro in filtros:
            if filtro.lower() in linea.lower():
                info_sip[filtro] = linea
    return info_sip

# Función para extraer información SDP
def extraer_info_sdp(sdp_text):
    lines = sdp_text.splitlines()
    ip = None
    port = None
    codecs = []

    for line in lines:
        if line.startswith("c="):  # IP de escucha
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "c=IN" and parts[1].startswith("IP4"):
                ip = parts[2]  # Obtener solo la IP

        if line.startswith("m=audio"):  # Puerto de escucha RTP
            parts = line.split()
            if len(parts) >= 2:
                port = parts[1]  # Puerto está en la segunda parte

        if line.startswith("a=rtpmap"):  # Códigos ofertados
            parts = line.split()
            if len(parts) >= 2:
                codecs.append(parts[1])  # El códec está en la segunda parte

    return ip, port, codecs

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

# Función para agrupar paquetes por Call-ID y origen <-> destino
def agrupar_paquetes(paquetes_filtrados, paquetes_rtp):
    grupos_no_printeados = {}

    # Procesar los paquetes SIP primero y agrupar por Call-ID y origen/destino
    for pkt, callid, ip_origen, ip_destino, es_llamante in paquetes_filtrados:
        clave = (callid, crear_clave_origen_destino(ip_origen, ip_destino))
        if clave not in grupos:
            grupos[clave] = {
                'paquetes': [],
                'paquetes_rtp': [],
                'causa': None,
                'primer_tiempo': pkt.time,
                'ultimo_tiempo': pkt.time,
                'num_paquetes': 0,
                'num_bytes': 0,
                'tiempo_expiracion': 0,
                'tiempo_inactividad': 0,
                'llamada_abierta': 1,
                'intentos': 0,
                'sdp_info': {
                    'llamante': None,
                    'llamado': None
                }
            }

        grupo = grupos[clave]
        grupo['ultimo_tiempo'] = pkt.time
        grupo['num_paquetes'] += 1
        grupo['num_bytes'] += len(pkt)
        grupo['paquetes'].append(pkt)

        # Extraer información SDP si es un mensaje con Content-Type: application/sdp
        if "Content-Type: application/sdp" in pkt[UDP].load.decode("utf-8", errors="ignore"):
            sdp_start = pkt[UDP].load.decode("utf-8", errors="ignore").find("\r\n\r\n") + 4
            sdp_text = pkt[UDP].load.decode("utf-8", errors="ignore")[sdp_start:]
            ip_rtp, port_rtp, codecs = extraer_info_sdp(sdp_text)

            # Almacenar información de la negociación SDP
            if es_llamante:
                grupo['sdp_info']['llamante'] = {'ip': ip_rtp, 'port': int(port_rtp), 'codecs': codecs}
            else:
                grupo['sdp_info']['llamado'] = {'ip': ip_rtp, 'port': int(port_rtp), 'codecs': codecs}


    for clave, grupo in grupos.items():
        sdp_llamante = grupo['sdp_info']['llamante']
        sdp_llamado = grupo['sdp_info']['llamado']
        for pkt_rtp in paquetes_rtp:
            if UDP in pkt_rtp:
                ip_origen_rtp = pkt_rtp[IP].src
                ip_destino_rtp = pkt_rtp[IP].dst
                puerto_origen_rtp = pkt_rtp[UDP].sport
                puerto_destino_rtp = pkt_rtp[UDP].dport
            # Verificar si el paquete RTP pertenece al llamante o al llamado
            if (
                ((ip_origen_rtp == sdp_llamante['ip'] and puerto_origen_rtp == sdp_llamante['port']) and (ip_destino_rtp == sdp_llamado['ip'] and puerto_destino_rtp == sdp_llamado['port'])) or
                ((ip_origen_rtp == sdp_llamado['ip'] and puerto_origen_rtp == sdp_llamado['port']) and (ip_destino_rtp == sdp_llamante['ip'] and puerto_destino_rtp == sdp_llamante['port']))):
                grupos[clave]['paquetes_rtp'].append(pkt_rtp)

    # Control de expiración de los grupos
    for g in list(grupos.keys()):
        if grupos[g]['llamada_abierta'] == 0:
            continue
        paquetes_nuevos = filtrar_paquetes_por_tiempo(grupos[g]['paquetes'])
        if paquetes_nuevos != grupos[g]['paquetes']:
            grupos[g]['tiempo_expiracion'] = 1
            grupos[g]['paquetes'] = paquetes_nuevos
        grupos_no_printeados[g] = grupos[g]
    for g in list(grupos.keys()):
        if grupos[g]['llamada_abierta'] == 1 and grupos[g]['tiempo_expiracion'] != 1:
            grupos[g] = {
                'paquetes': [],
                'paquetes_rtp': [],
                'causa': None,
                'primer_tiempo': grupos[g]['primer_tiempo'],
                'ultimo_tiempo': grupos[g]['ultimo_tiempo'],
                'num_paquetes': 0,
                'num_bytes': 0,
                'llamada_abierta': 1,
                'tiempo_expiracion': grupos[g]['tiempo_expiracion'],
                'tiempo_inactividad': grupos[g]['tiempo_inactividad'],
                'intentos': grupos[g]['intentos'],
                'sdp_info': grupos[g]['sdp_info']
            }
    return grupos_no_printeados



# Función para imprimir la llamada con información ampliada
def printear_llamada(filtros, datos_grupo, archivo_pcap):
    pkt_inicial = datos_grupo['paquetes'][0]
    pkt_final = datos_grupo['paquetes'][-1]
    
    user_a_llamante, user_a_llamado, mensaje_to, p_asserted, uri_sip, p_charging_vector = extraer_user_agent(datos_grupo['paquetes'])
    pdd = calcular_pdd(datos_grupo['paquetes'])
    duracion_facturable = calcular_duracion_facturable(datos_grupo['paquetes'])
    # Generalmente las llamadas son por UDP
    if UDP in pkt_inicial:
        payload_inicial = pkt_inicial[UDP].load.decode("utf-8", errors="ignore")
        ip_origen = pkt_inicial[IP].src
        ip_destino = pkt_inicial[IP].dst
        puerto_origen = pkt_inicial[UDP].sport
        puerto_destino = pkt_inicial[UDP].dport
        protocolo_transporte = "UDP"
    elif TCP in pkt_inicial:
        payload_inicial = pkt_inicial[TCP].payload.load.decode("utf-8", errors="ignore")
        ip_origen = pkt_inicial[IP].src
        ip_destino = pkt_inicial[IP].dst
        puerto_origen = pkt_inicial[TCP].sport
        puerto_destino = pkt_inicial[TCP].dport
        protocolo_transporte = "TCP"
    
    # Extraer información del primer y último paquete
    tiempo_inicial = pkt_inicial.time
    tiempo_final = pkt_final.time
    duracion_llamada = tiempo_final - tiempo_inicial
    
    # Extraer información adicional SIP y SDP del primer paquete INVITE
    info_sip_inicial = extraer_campos_sip(payload_inicial, filtros)
    
    # Extraer información del último paquete
    payload_final = pkt_final[UDP].load.decode("utf-8", errors="ignore") if UDP in pkt_final else pkt_final[TCP].payload.load.decode("utf-8", errors="ignore")
    info_sip_final = extraer_campos_sip(payload_final, filtros)
    
    ip_rtp_llamante = datos_grupo['sdp_info']['llamante']['ip']
    puerto_rtp_llamante = datos_grupo['sdp_info']['llamante']['port']
    ip_rtp_llamado = datos_grupo['sdp_info']['llamado']['ip']
    puerto_rtp_llamado = datos_grupo['sdp_info']['llamado']['port']
    rtp_codecs_llamante = datos_grupo['sdp_info']['llamante']['codecs']
    rtp_codecs_llamado = datos_grupo['sdp_info']['llamado']['codecs']

    # Filtrar paquetes RTP de acuerdo a IP y puerto
    paquetes_rtp_llamante = filtrar_paquetes_rtp(datos_grupo['paquetes_rtp'], ip_rtp_llamante, puerto_rtp_llamante)
    paquetes_rtp_llamado = filtrar_paquetes_rtp(datos_grupo['paquetes_rtp'], ip_rtp_llamado, puerto_rtp_llamado)

    # Análisis RTP para ambas direcciones
    num_paquetes_llamante, bytes_llamante, perdida_llamante, jitter_llamante,jitter_max_llamante,jitter_min_llamante,duracion_llamante = analizar_rtp(paquetes_rtp_llamante)
    num_paquetes_llamado, bytes_llamado, perdida_llamado, jitter_llamado,jitter_max_llamado,jitter_min_llamado,duracion_llamado = analizar_rtp(paquetes_rtp_llamado)
    


    # Imprimir información detallada
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
    print(f"PCAP file: {archivo_pcap}")
    print(f"VLAN1: N/A")  # Asumiendo que esta información se extrae de otro modo, actualmente no disponible
    print(f"VLAN2: N/A")
    print(f"Caller User Agent: {user_a_llamante}")
    print(f"Callee User Agent: {user_a_llamado}")  # Esto se extraería de un 200 OK o último mensaje SIP
    print(f"To200: {mensaje_to}")  # Esto también depende del 200 OK
    print(f"Passerted: {p_asserted}")
    print(f"Sipuri: {uri_sip}")
    print(f"P_Charging_Vector: {p_charging_vector}")
    print(f"PDD: {pdd}")
    print(f"Duracion Factuable: {duracion_facturable}")  # Depende de la diferencia entre 200 OK y BYE
    print(f"Motivo cierre: {datos_grupo['causa']}")  # BYE, CANCEL o TIMEOUT
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

# Función principal para procesar el archivo pcap
def procesar_pcap(archivo_pcap, filtros):
    paquetes = rdpcap(archivo_pcap)
    paquetes_agrupar = []
    paquetes_rtp= detectar_rtp(archivo_pcap)

    for pkt in paquetes:
        if (UDP in pkt and pkt[UDP].dport == 5060) or (TCP in pkt and pkt[TCP].dport == 5060):
            try:
                if UDP in pkt:
                    payload = pkt[UDP].load.decode("utf-8", errors="ignore")
                    ip_origen = pkt[IP].src
                    ip_destino = pkt[IP].dst
                elif TCP in pkt:
                    payload = pkt[TCP].payload.load.decode("utf-8", errors="ignore")
                    ip_origen = pkt[IP].src
                    ip_destino = pkt[IP].dst

                callid = extraer_callid(payload)
                if not callid:
                    continue

                es_llamante = False
                es_req, metodo_sip, uri_sip = es_request(payload)
                if es_req and metodo_sip == "INVITE":
                    es_llamante = True

                paquetes_agrupar.append((pkt, callid, ip_origen, ip_destino, es_llamante))

            except AttributeError:
                continue

    grupos_no_printeados = agrupar_paquetes(paquetes_agrupar,paquetes_rtp)
    
    # Imprimir los grupos de paquetes
    for clave, datos_grupo in grupos_no_printeados.items():
        callid, ips = clave
        # Iterar sobre los paquetes dentro del agrupado
        for pkt in datos_grupo['paquetes']:
            if UDP in pkt:
                payload = pkt[UDP].load.decode("utf-8", errors="ignore")
            elif TCP in pkt:
                payload = pkt[TCP].payload.load.decode("utf-8", errors="ignore")

            # Verificar si es una request o response
            es_req, metodo_sip, uri_sip = es_request(payload)
            es_res, codigo_sip, estado = es_response(payload)

            if grupos_no_printeados[clave]['tiempo_expiracion'] == 1 and grupos_no_printeados[clave]['llamada_abierta'] == 1:
                grupos_no_printeados[clave]['llamada_abierta'] = 0
                grupos[clave]['causa'] = "TIMEOUT"
                printear_llamada(filtros,datos_grupo,archivo_pcap)

            # Imprimir información sobre request o response
            elif es_req and ((str(metodo_sip) == 'CANCEL') or (str(metodo_sip) == 'BYE')):
                if ((datos_grupo['paquetes'].index(pkt)) == (len(datos_grupo['paquetes'])-2)) or (grupos[clave]['intentos'] > 1):
                    grupos[clave]['llamada_abierta'] = 0
                    grupos[clave]['causa'] = str(metodo_sip)
                    datos_grupo['causa'] = str(metodo_sip)
                    printear_llamada(filtros,datos_grupo,archivo_pcap)
                else:
                    grupos[clave]['intentos'] += 1
        
        grupos[clave]['tiempo_inactividad'] += 1
        grupos_no_printeados[clave]['tiempo_inactividad'] += 1
        if grupos[clave]['tiempo_inactividad'] == tiempo_inactividad and grupos[clave]['llamada_abierta'] == 1:
                grupos_no_printeados[clave]['llamada_abierta'] = 0
                datos_grupo['causa'] = "TIMEOUT"
                printear_llamada(filtros,datos_grupo,archivo_pcap)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usar: python3 capturar_trafico.py archivo.pcap filtro1 filtro2 ...")
        sys.exit(1)

    archivo_pcap = sys.argv[1]
    filtros = sys.argv[2:]
    while True:
        procesar_pcap(archivo_pcap, filtros)
        time.sleep(tiempo_espera)
