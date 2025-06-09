#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

pcap_t *handle;

typedef struct
{
    char media_ip[64];
    uint16_t media_port;
    char codecs[256]; // Lista de codecs rtpmap separados por coma
} SdpInfo;

SdpInfo extraer_sdp_info(const char *payload)
{
    SdpInfo info;
    memset(&info, 0, sizeof(SdpInfo));

    const char *c_line = strstr(payload, "\nc=");
    if (c_line)
    {
        sscanf(c_line, "\nc=IN IP4 %63s", info.media_ip);
    }

    const char *m_line = strstr(payload, "\nm=audio ");
    if (m_line)
    {
        sscanf(m_line, "\nm=audio %hu RTP", &info.media_port);
    }

    // Extraer líneas a=rtpmap y concatenar
    const char *p = payload;
    char *codec_ptr = info.codecs;
    size_t remaining = sizeof(info.codecs);

    while ((p = strstr(p, "\na=rtpmap:")) != NULL)
    {
        const char *line_end = strchr(p + 1, '\n');
        if (!line_end)
            break;
        size_t len = line_end - p - 1; // quitar el salto de línea
        if (len < remaining - 1)
        {
            strncat(codec_ptr, p + 1, len); // quitar el salto de línea inicial
            strncat(codec_ptr, ",", 1);
            codec_ptr += len + 1;
            remaining -= len + 1;
        }
        p = line_end;
    }

    // Quitar la coma final si hay
    size_t clen = strlen(info.codecs);
    if (clen > 0 && info.codecs[clen - 1] == ',')
    {
        info.codecs[clen - 1] = '\0';
    }

    return info;
}
/* Función para abrir un archivo PCAP */
static PyObject *open_pcap(PyObject *self, PyObject *args)
{
    const char *filename;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!PyArg_ParseTuple(args, "s", &filename))
        return NULL;

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }
    return PyLong_FromLong(0);
}

/* Función para abrir una interfaz en vivo */
static PyObject *open_live(PyObject *self, PyObject *args)
{
    const char *device;
    int snaplen = 65535;
    int promisc = 1;
    int to_ms = 100; // Timeout en milisegundos -> 0 es indefinido
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!PyArg_ParseTuple(args, "s|iii", &device, &snaplen, &promisc, &to_ms))
        return NULL;

    handle = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
    if (handle == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }
    pcap_setnonblock(handle, 1, errbuf);

    return PyLong_FromLong(0);
}
bool es_100_trying_o_180_ringing(const char *payload)
{
    if (payload == NULL)
        return false;

    regex_t regex;
    const char *pattern = "^SIP/2.0[ \t]+(100[ \t]+Trying|180[ \t]+Ringing)";
    bool resultado = false;

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE | REG_NEWLINE) != 0)
        return false;

    if (regexec(&regex, payload, 0, NULL, 0) == 0)
        resultado = true;

    regfree(&regex);
    return resultado;
}
/* Función para extraer el campo From de un mensaje SIP */
char *extraer_from(const char *payload)
{
    if (payload == NULL)
        return NULL;

    regex_t regex;
    regmatch_t matches[2];

    // Compilar la expresión regular: captura todo lo que sigue a "From: " hasta el salto de línea
    if (regcomp(&regex, "From: ([^\r\n]+)", REG_EXTENDED | REG_ICASE) != 0)
        return NULL;

    char *result = NULL;
    if (regexec(&regex, payload, 2, matches, 0) == 0)
    {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + matches[1].rm_so, len);
            result[len] = '\0';
        }
    }

    regfree(&regex);
    return result; // NULL si no se encontró
}
char *extraer_to(const char *payload)
{
    regex_t regex;
    regmatch_t matches[2];

    // Regex: busca una línea que comience con "To:", seguida de cualquier cosa hasta el fin de línea
    const char *pattern = "To:[ \t]*([^\\r\\n]+)";

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE) != 0)
        return NULL;

    if (regexec(&regex, payload, 2, matches, 0) == 0)
    {
        size_t start = matches[1].rm_so;
        size_t end = matches[1].rm_eo;
        size_t len = end - start;

        char *result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + start, len);
            result[len] = '\0';
        }

        regfree(&regex);
        return result;
    }

    regfree(&regex);
    return NULL;
}
/* Función para extraer Call-ID de SIP */
char *extraer_call_id(const char *payload)
{
    if (payload == NULL)
        return NULL;

    regex_t regex;
    regmatch_t matches[2];

    // Compilar la regex, ignorando mayúsculas/minúsculas
    if (regcomp(&regex, "Call-ID: ([^\r\n]+)", REG_EXTENDED | REG_ICASE) != 0)
        return NULL;

    char *result = NULL;
    if (regexec(&regex, payload, 2, matches, 0) == 0)
    {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + matches[1].rm_so, len);
            result[len] = '\0';
        }
    }

    regfree(&regex);
    return result; // NULL si no se encontró
}

/* Función para extraer el método SIP (INVITE, BYE, etc.) */
char *extraer_metodo_sip(const char *payload)
{
    if (payload == NULL)
        return NULL;

    regex_t regex;
    regmatch_t matches[2];

    // Coincide con métodos al comienzo del payload
    // Ejemplo: "INVITE sip:... SIP/2.0"
    if (regcomp(&regex, "^([A-Z]+)[[:space:]]+sip:", REG_EXTENDED | REG_ICASE | REG_NEWLINE) != 0)
        return NULL;

    char *result = NULL;
    if (regexec(&regex, payload, 2, matches, 0) == 0)
    {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + matches[1].rm_so, len);
            result[len] = '\0';
        }
    }

    regfree(&regex);
    return result; // NULL si no se encontró
}
int es_sip_200_ok(const char *payload)
{
    if (payload == NULL)
        return 0;

    // Verifica si el payload comienza con "SIP/2.0 200 OK"
    return strncmp(payload, "SIP/2.0 200 OK", 13) == 0;
}
char *extraer_estado_sip(const char *payload)
{
    if (payload == NULL)
        return NULL;

    regex_t regex_response;
    regmatch_t matches[2];
    char *result = NULL;

    // Regex para response SIP: "SIP/2.0 " seguido de código y estado
    // Captura el código y el texto del estado (ej: "200 OK", "404 Not Found")
    if (regcomp(&regex_response, "^SIP/2\\.0[[:space:]]+([0-9]{3}[[:space:]][^\\r\\n]+)", REG_EXTENDED | REG_ICASE | REG_NEWLINE) != 0)
    {
        return NULL;
    }

    if (regexec(&regex_response, payload, 2, matches, 0) == 0)
    {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + matches[1].rm_so, len);
            result[len] = '\0';
        }
    }

    regfree(&regex_response);

    return result; // NULL si no es response o no se encontró
}
char *extraer_user_agent(const char *payload)
{
    regex_t regex;
    regmatch_t pmatch[2]; // Para capturar grupo (User-Agent: valor)
    const char *pattern = "^User-Agent:[ \t]*([^\r\n]+)";
    int ret;

    // Compilamos regex con flag REG_ICASE (insensible a mayúsculas) y REG_NEWLINE (para ^ y $ en líneas)
    ret = regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE | REG_NEWLINE);
    if (ret)
        return NULL;

    // Buscamos coincidencia
    ret = regexec(&regex, payload, 2, pmatch, 0);
    if (ret == 0)
    {
        size_t len = pmatch[1].rm_eo - pmatch[1].rm_so;
        char *result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + pmatch[1].rm_so, len);
            result[len] = '\0';

            // Opcional: limpiar espacios al final
            while (len > 0 && (result[len - 1] == ' ' || result[len - 1] == '\t'))
            {
                result[len - 1] = '\0';
                len--;
            }
        }
        regfree(&regex);
        return result;
    }

    regfree(&regex);
    return NULL;
}
char *extraer_p_asserted_id(const char *payload)
{
    if (payload == NULL)
        return NULL;

    regex_t regex;
    regmatch_t matches[2];

    // Regex para capturar el valor del campo "P-Asserted-Identity"
    const char *pattern = "P-Asserted-Identity:[ \t]*([^\\r\\n]+)";

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE | REG_NEWLINE) != 0)
        return NULL;

    char *result = NULL;
    if (regexec(&regex, payload, 2, matches, 0) == 0)
    {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + matches[1].rm_so, len);
            result[len] = '\0';
        }
    }

    regfree(&regex);
    return result; // NULL si no se encontró
}

char *extraer_p_charging_vector(const char *payload)
{
    if (payload == NULL)
        return NULL;

    regex_t regex;
    regmatch_t matches[2];

    // Regex para capturar el valor del campo "P-Charging-Vector"
    const char *pattern = "P-Charging-Vector:[ \t]*([^\\r\\n]+)";

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE | REG_NEWLINE) != 0)
        return NULL;

    char *result = NULL;
    if (regexec(&regex, payload, 2, matches, 0) == 0)
    {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + matches[1].rm_so, len);
            result[len] = '\0';
        }
    }

    regfree(&regex);
    return result; // NULL si no se encontró
}
char *extraer_sip_uri(const char *payload)
{
    if (payload == NULL)
        return NULL;

    regex_t regex;
    regmatch_t matches[2];

    // Busca en la primera línea el patrón INVITE sip:... SIP/2.0
    const char *pattern = "^INVITE[[:space:]]+(sip:[^[:space:]]+)";

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE | REG_NEWLINE) != 0)
        return NULL;

    char *result = NULL;
    if (regexec(&regex, payload, 2, matches, 0) == 0)
    {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        result = malloc(len + 1);
        if (result)
        {
            strncpy(result, payload + matches[1].rm_so, len);
            result[len] = '\0';
        }
    }

    regfree(&regex);
    return result; // NULL si no se encontró
}

/* Función para procesar un paquete y extraer información */
static PyObject *procesar_paquete(PyObject *self, PyObject *args)
{
    PyObject *timestamp_obj;
    const char *packet;
    Py_ssize_t packet_len;

    if (!PyArg_ParseTuple(args, "Oy#", &timestamp_obj, &packet, &packet_len))
        return NULL;

    PyObject *pkt_info = PyDict_New();
    if (!pkt_info)
        return NULL;

    struct ether_header *eth = (struct ether_header *)packet;
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4));
    const char *payload = packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr);

    PyDict_SetItemString(pkt_info, "timestamp", timestamp_obj);
    PyDict_SetItemString(pkt_info, "src_ip", PyUnicode_FromString(inet_ntoa(ip_hdr->ip_src)));
    PyDict_SetItemString(pkt_info, "dst_ip", PyUnicode_FromString(inet_ntoa(ip_hdr->ip_dst)));
    PyDict_SetItemString(pkt_info, "src_port", PyLong_FromLong(ntohs(udp_hdr->uh_sport)));
    PyDict_SetItemString(pkt_info, "dst_port", PyLong_FromLong(ntohs(udp_hdr->uh_dport)));
    PyDict_SetItemString(pkt_info, "packet_size", PyLong_FromSsize_t(packet_len));

    if (ntohs(udp_hdr->uh_sport) == 5060 || ntohs(udp_hdr->uh_dport) == 5060)
    {
        PyDict_SetItemString(pkt_info, "protocol", PyUnicode_FromString("SIP"));
        PyDict_SetItemString(pkt_info, "call_id", PyUnicode_FromString(extraer_call_id(payload)));
    }
    else if (ntohs(udp_hdr->uh_sport) >= 16384 && ntohs(udp_hdr->uh_sport) <= 32768)
    {
        PyDict_SetItemString(pkt_info, "protocol", PyUnicode_FromString("RTP"));
        PyDict_SetItemString(pkt_info, "rtp_seq", PyLong_FromLong((payload[2] << 8) | payload[3]));
        PyDict_SetItemString(pkt_info, "rtp_timestamp", PyLong_FromLong((payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]));
    }
    else
    {
        PyDict_SetItemString(pkt_info, "protocol", PyUnicode_FromString("UNKNOWN"));
    }

    return pkt_info;
}

typedef struct
{
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t packet_size;
    char protocol[20];
    char call_id[256];
    uint16_t rtp_seq;
    uint32_t rtp_timestamp;
    char metodo[30];
    uint8_t transporte_proto;
    char fro[50];
    char to[50];
    uint16_t vlan1; // S-VLAN
    uint16_t vlan2; // C-VLAN
    char user_agent[256];
    char to_200[50];
    char p_asserted_id[128];
    char sip_uri[100];
    char pcv[128];
    int es_trying_o_ringing; // 0 = no, 1 = sí
    char sdp_ip_a[64];
    uint16_t sdp_port_a;
    char sdp_codecs_a[256];
    char sdp_ip_b[64];
    uint16_t sdp_port_b;
    char sdp_codecs_b[256];

} Paquete;

static void destroy_capsule(PyObject *capsule)
{
    Paquete *p = PyCapsule_GetPointer(capsule, "Paquete");
    // free(p->call_id);
    free(p);
}

/* Función para leer paquetes sin procesar (evitando memoryview) */
static PyObject *read_pcap(PyObject *self, PyObject *args)
{
    PyObject *pkt_list = PyList_New(0); // Lista para almacenar los paquetes
    struct pcap_pkthdr *header;
    const u_char *packet;
    int count = 0;

    while (count < 10 && pcap_next_ex(handle, &header, &packet) == 1)
    {
        Paquete *p = malloc(sizeof(Paquete));

        struct ether_header *eth = (struct ether_header *)packet;
        const u_char *ptr = packet + sizeof(struct ether_header);

        // VLAN parsing
        uint16_t vlan_tpid = ntohs(*(uint16_t *)(packet + 12));
        if (vlan_tpid == 0x8100 || vlan_tpid == 0x88A8)
        {
            uint16_t vlan1_tci = ntohs(*(uint16_t *)(packet + 14));
            p->vlan1 = vlan1_tci & 0x0FFF;

            uint16_t next_type = ntohs(*(uint16_t *)(packet + 16));
            if (next_type == 0x8100)
            {
                uint16_t vlan2_tci = ntohs(*(uint16_t *)(packet + 18));
                p->vlan2 = vlan2_tci & 0x0FFF;
                ptr += 8; // Avanza después de dos etiquetas VLAN
            }
            else
            {
                p->vlan2 = 0;
                ptr += 4; // Avanza después de una etiqueta VLAN
            }
        }
        else
        {
            p->vlan1 = 0;
            p->vlan2 = 0;
        }
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
        struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4));
        const char *payload = packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr);

        p->timestamp = (header->ts.tv_sec * 1000000) + header->ts.tv_usec;
        p->src_ip = (ip_hdr->ip_src.s_addr);
        p->dst_ip = (ip_hdr->ip_dst.s_addr);
        p->src_port = ntohs(udp_hdr->uh_sport);
        p->dst_port = ntohs(udp_hdr->uh_dport);
        p->packet_size = header->len;
        p->transporte_proto = ip_hdr->ip_p;

        if (ntohs(udp_hdr->uh_sport) == 5060 || ntohs(udp_hdr->uh_dport) == 5060)
        {
            sprintf(p->protocol, "SIP");

            int ip_header_len = ip_hdr->ip_hl * 4;
            int udp_header_len = sizeof(struct udphdr);
            int l2_header_len = sizeof(struct ether_header);
            int headers_len = l2_header_len + ip_header_len + udp_header_len;

            int payload_len = header->caplen - headers_len;
            if (payload_len <= 0 || (header->caplen < headers_len))
            {
                strncpy(p->call_id, "EMPTY", 255);
                p->call_id[255] = '\0';
                strncpy(p->metodo, "EMPTY", 29);
                p->metodo[29] = '\0';
                strncpy(p->fro, "EMPTY", 49);
                p->fro[49] = '\0';
                strncpy(p->to, "EMPTY", 49);
                p->to[49] = '\0';
                strncpy(p->user_agent, "EMPTY", 255);
                p->user_agent[255] = '\0';
                strncpy(p->to_200, "EMPTY", 49);
                p->to_200[49] = '\0';
                strncpy(p->p_asserted_id, "EMPTY", 127);
                p->p_asserted_id[127] = '\0';
                strncpy(p->sip_uri, "EMPTY", 99);
                p->sip_uri[99] = '\0';
                strncpy(p->pcv, "EMPTY", 127);
                p->pcv[127] = '\0';
                strncpy(p->sdp_ip_a, "EMPTY", 63);
                p->sdp_ip_a[63] = '\0';
                strncpy(p->sdp_codecs_a, "EMPTY", 255);
                p->sdp_codecs_a[255] = '\0';
                p->sdp_port_a = 0;
                strncpy(p->sdp_ip_b, "EMPTY", 63);
                p->sdp_ip_b[63] = '\0';
                strncpy(p->sdp_codecs_b, "EMPTY", 255);
                p->sdp_codecs_b[255] = '\0';
                p->sdp_port_b = 0;
            }
            else
            {
                const char *payload = packet + headers_len;

                char *payload_copy = malloc(payload_len + 1);
                if (payload_copy)
                {
                    memcpy(payload_copy, payload, payload_len);
                    payload_copy[payload_len] = '\0';

                    // Extraer Call-ID
                    char *cid = extraer_call_id(payload_copy);
                    strncpy(p->call_id, cid ? cid : "N/A", 255);
                    p->call_id[255] = '\0';

                    if (cid)
                        free(cid);

                    // Extraer método SIP
                    char *metodo = extraer_metodo_sip(payload_copy);
                    strncpy(p->metodo, metodo ? metodo : "N/A", 29);
                    p->metodo[29] = '\0';
                    if (metodo)
                        free(metodo);

                    // Extraer from
                    char *fro = extraer_from(payload_copy);
                    strncpy(p->fro, fro ? fro : "N/A", 49);
                    p->fro[49] = '\0';
                    if (fro)
                        free(fro);

                    // Extraer to
                    char *to = extraer_to(payload_copy);
                    strncpy(p->to, to ? to : "N/A", 49);
                    p->to[49] = '\0';
                    if (to)
                        free(to);
                    
                    //Extraer user agent
                    char *user_agent = extraer_user_agent(payload_copy);
                    strncpy(p->user_agent, user_agent ? user_agent: "N/A", 255);
                    p->user_agent[255] = '\0';
                    if (user_agent)
                        free(user_agent);
                    // Aquí se agrega la lógica de 200 OK
                    if (es_sip_200_ok(payload_copy))
                    {
                        strncpy(p->to_200, p->to, 49);
                        p->to_200[49] = '\0';

                        // Extraer IP de línea c=
                        const char *c_line = strstr(payload_copy, "\nc=IN IP4 ");
                        if (c_line)
                        {
                            sscanf(c_line, "\nc=IN IP4 %63s", p->sdp_ip_b);
                            p->sdp_ip_b[63] = '\0';
                        }

                        // Extraer puerto de línea m=
                        const char *m_line = strstr(payload_copy, "\nm=audio ");
                        if (m_line)
                        {
                            sscanf(m_line, "\nm=audio %hu", &p->sdp_port_b);
                        }

                        // Extraer codecs (a=rtpmap)
                        const char *a_line = payload_copy;
                        char *codecs_ptr = p->sdp_codecs_b;
                        size_t remaining = sizeof(p->sdp_codecs_b);
                        codecs_ptr[0] = '\0'; // Inicializar
                        const char *prefix = "\na=rtpmap:";
                        size_t prefix_len = strlen(prefix);

                        while ((a_line = strstr(a_line, prefix)) != NULL)
                        {
                            const char *start = a_line + prefix_len;

                            // Buscar el espacio después del payload number
                            const char *space_pos = strchr(start, ' ');
                            if (!space_pos)
                                break; // formato incorrecto, salir

                            const char *codec_start = space_pos + 1;

                            // Buscar fin de línea
                            const char *end = strchr(codec_start, '\n');
                            if (!end)
                                break;

                            size_t len = end - codec_start;

                            // Copiar solo si la longitud es positiva y quepa
                            if (len > 0 && len < remaining - 1)
                            {
                                // Evitar espacios al inicio o fin
                                while (len > 0 && (codec_start[0] == ' ' || codec_start[0] == '\r'))
                                {
                                    codec_start++;
                                    len--;
                                }
                                while (len > 0 && (codec_start[len - 1] == ' ' || codec_start[len - 1] == '\r'))
                                {
                                    len--;
                                }
                                if (len > 0)
                                {
                                    strncat(codecs_ptr, codec_start, len);
                                    strncat(codecs_ptr, ",", 1);
                                    codecs_ptr += len + 1;
                                    remaining -= len + 1;
                                }
                            }
                            a_line = end;
                        }

                        // Quitar coma final
                        size_t clen = strlen(p->sdp_codecs_b);
                        if (clen > 0 && p->sdp_codecs_b[clen - 1] == ',')
                        {
                            p->sdp_codecs_b[clen - 1] = '\0';
                        }
                    }
                    else
                    {
                        strncpy(p->to_200, "N/A", 49);
                        p->to_200[49] = '\0';
                        strncpy(p->sdp_ip_b, "N/A", 63);
                        p->sdp_port_b = 0;
                        strncpy(p->sdp_codecs_b, "N/A", 255);
                    }
                    //PAI
                    char *pai = extraer_p_asserted_id(payload_copy);
                    strncpy(p->p_asserted_id, pai ? pai : "N/A", 127);
                    p->p_asserted_id[127] = '\0';
                    if (pai)
                        free(pai);
                    // SIP URI
                    //  Solo si es INVITE
                    if (strcmp(p->metodo, "INVITE") == 0)
                    {

                        // Extraer IP de línea c=
                        const char *c_line = strstr(payload_copy, "\nc=IN IP4 ");
                        if (c_line)
                        {
                            sscanf(c_line, "\nc=IN IP4 %63s", p->sdp_ip_a);
                            p->sdp_ip_a[63] = '\0';
                        }

                        // Extraer puerto de línea m=
                        const char *a_line = payload_copy;
                        char *codecs_ptr = p->sdp_codecs_a;
                        size_t remaining = sizeof(p->sdp_codecs_a);
                        codecs_ptr[0] = '\0'; // Inicializar
                        const char *prefix = "\na=rtpmap:";
                        size_t prefix_len = strlen(prefix);

                        while ((a_line = strstr(a_line, prefix)) != NULL)
                        {
                            const char *start = a_line + prefix_len;

                            // Buscar el espacio después del payload number
                            const char *space_pos = strchr(start, ' ');
                            if (!space_pos)
                                break; // formato incorrecto, salir

                            const char *codec_start = space_pos + 1;

                            // Buscar fin de línea
                            const char *end = strchr(codec_start, '\n');
                            if (!end)
                                break;

                            size_t len = end - codec_start;

                            // Copiar solo si la longitud es positiva y quepa
                            if (len > 0 && len < remaining - 1)
                            {
                                // Evitar espacios al inicio o fin
                                while (len > 0 && (codec_start[0] == ' ' || codec_start[0] == '\r'))
                                {
                                    codec_start++;
                                    len--;
                                }
                                while (len > 0 && (codec_start[len - 1] == ' ' || codec_start[len - 1] == '\r'))
                                {
                                    len--;
                                }
                                if (len > 0)
                                {
                                    strncat(codecs_ptr, codec_start, len);
                                    strncat(codecs_ptr, ",", 1);
                                    codecs_ptr += len + 1;
                                    remaining -= len + 1;
                                }
                            }
                            a_line = end;
                        }

                        // Quitar coma final
                        size_t clen = strlen(p->sdp_codecs_a);
                        if (clen > 0 && p->sdp_codecs_a[clen - 1] == ',')
                        {
                            p->sdp_codecs_a[clen - 1] = '\0';
                        }
                    
                        char *uri = extraer_sip_uri(payload_copy);
                        strncpy(p->sip_uri, uri ? uri : "N/A", 99);
                        p->sip_uri[99] = '\0';
                        if (uri)
                            free(uri);
                    }
                    // PCV
                    char *pcv = extraer_p_charging_vector(payload_copy);
                    strncpy(p->pcv, pcv ? pcv : "N/A", 127);
                    p->pcv[127] = '\0';
                    if (pcv)
                        free(pcv);
                    // Ver si es 100 Trying o 180 Ringing
                    p->es_trying_o_ringing = es_100_trying_o_180_ringing(payload_copy) ? 1 : 0;
                    //
                    free(payload_copy);
                }
                else
                {
                    strncpy(p->call_id, "ERR", 255);
                    p->call_id[255] = '\0';
                    strncpy(p->metodo, "EMPTY", 29);
                    p->metodo[29] = '\0';
                    strncpy(p->fro, "EMPTY", 49);
                    p->fro[49] = '\0';
                    strncpy(p->to, "EMPTY", 49);
                    p->to[49] = '\0';
                    strncpy(p->user_agent, "EMPTY", 255);
                    p->user_agent[255] = '\0';
                    strncpy(p->to_200, "EMPTY", 49);
                    p->to_200[49] = '\0';
                    strncpy(p->p_asserted_id, "EMPTY", 127);
                    p->p_asserted_id[127] = '\0';
                    strncpy(p->sip_uri, "EMPTY", 99);
                    p->sip_uri[99] = '\0';
                    strncpy(p->pcv, "EMPTY", 127);
                    p->pcv[127] = '\0';
                    strncpy(p->sdp_ip_a, "EMPTY", 63);
                    p->sdp_ip_a[63] = '\0';
                    strncpy(p->sdp_codecs_a, "EMPTY", 255);
                    p->sdp_codecs_a[255] = '\0';
                    p->sdp_port_a = 0;
                    strncpy(p->sdp_ip_b, "EMPTY", 63);
                    p->sdp_ip_b[63] = '\0';
                    strncpy(p->sdp_codecs_b, "EMPTY", 255);
                    p->sdp_codecs_b[255] = '\0';
                    p->sdp_port_b = 0;
                }
            }
        }

        else if (ntohs(udp_hdr->uh_sport) >= 16384 && ntohs(udp_hdr->uh_sport) <= 32768)
        {
            sprintf(p->protocol, "RTP");
            p->rtp_seq = (payload[2] << 8) | payload[3];
            p->rtp_timestamp = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7];
        }
        else
        {
            sprintf(p->protocol, "UNKNOWN");
        }

        PyObject *capsule = PyCapsule_New(p, "Paquete", destroy_capsule);
        PyList_Append(pkt_list, capsule);
        Py_DECREF(capsule);

        count++;
    }

    if (count == 0)
    {
        Py_RETURN_NONE; // Si no hay más paquetes, devolver None
    }

    return pkt_list;
}
static PyObject *read_live(PyObject *self, PyObject *args)
{
    PyObject *pkt_list = PyList_New(0); // Lista para almacenar los paquetes
    struct pcap_pkthdr *header;
    const u_char *packet;
    int count = 0;
    int max_time_ms = 10; // Tiempo máximo en milisegundos por defecto (10 segundos)

    // Parseamos el argumento de tiempo máximo en milisegundos (opcional)
    if (!PyArg_ParseTuple(args, "|i", &max_time_ms))
    {
        PyErr_SetString(PyExc_TypeError, "Se esperaba un argumento entero opcional para el tiempo máximo.");
        return NULL;
    }

    // Aseguramos que `handle` esté abierto
    if (handle == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "Captura no ha sido abierta. Llama a open_live primero.");
        return NULL;
    }

    // Obtén el tiempo de inicio en milisegundos
    clock_t start_time = clock();

    while (count < 10)
    {
        // Calcula el tiempo transcurrido en milisegundos
        clock_t current_time = clock();
        double elapsed_time_ms = ((double)(current_time - start_time)) / CLOCKS_PER_SEC * 1000;
	//printf("Elapsed:%f\n",elapsed_time_ms);
        // Si ha pasado el tiempo máximo, salimos del bucle
        if (elapsed_time_ms >= max_time_ms)
        {
            //printf("Elapsed\n");
            break;
        }
        // Captura el siguiente paquete
        if (pcap_next_ex(handle, &header, &packet) != 1)
        {
            continue; // Si no hay más paquetes disponibles, salta
        }

        Paquete *p = malloc(sizeof(Paquete));

        struct ether_header *eth = (struct ether_header *)packet;
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
        struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4));
        const char *payload = packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr);

        p->timestamp = (header->ts.tv_sec * 1000000) + header->ts.tv_usec;
        p->src_ip = (ip_hdr->ip_src.s_addr);
        p->dst_ip = (ip_hdr->ip_dst.s_addr);
        p->src_port = ntohs(udp_hdr->uh_sport);
        p->dst_port = ntohs(udp_hdr->uh_dport);
        p->packet_size = header->len;
        p->transporte_proto = ip_hdr->ip_p;

        if (ntohs(udp_hdr->uh_sport) == 5060 || ntohs(udp_hdr->uh_dport) == 5060)
        {
            sprintf(p->protocol, "SIP");

            int ip_header_len = ip_hdr->ip_hl * 4;
            int udp_header_len = sizeof(struct udphdr);
            int l2_header_len = sizeof(struct ether_header);
            int headers_len = l2_header_len + ip_header_len + udp_header_len;

            int payload_len = header->caplen - headers_len;
            if (payload_len <= 0 || (header->caplen < headers_len))
            {
                strncpy(p->call_id, "EMPTY", 255);
                p->call_id[255] = '\0';
                strncpy(p->metodo, "EMPTY", 29);
                p->metodo[29] = '\0';
                strncpy(p->fro, "EMPTY", 49);
                p->fro[49] = '\0';
                strncpy(p->to, "EMPTY", 49);
                p->to[49] = '\0';
                strncpy(p->user_agent, "EMPTY", 255);
                p->user_agent[255] = '\0';
                strncpy(p->to_200, "EMPTY", 49);
                p->to_200[49] = '\0';
                strncpy(p->p_asserted_id, "EMPTY", 127);
                p->p_asserted_id[127] = '\0';
                strncpy(p->sip_uri, "EMPTY", 99);
                p->sip_uri[99] = '\0';
                strncpy(p->pcv, "EMPTY", 127);
                p->pcv[127] = '\0';
                strncpy(p->sdp_ip_a, "EMPTY", 63);
                p->sdp_ip_a[63] = '\0';
                strncpy(p->sdp_codecs_a, "EMPTY", 255);
                p->sdp_codecs_a[255] = '\0';
                p->sdp_port_a = 0;
                strncpy(p->sdp_ip_b, "EMPTY", 63);
                p->sdp_ip_b[63] = '\0';
                strncpy(p->sdp_codecs_b, "EMPTY", 255);
                p->sdp_codecs_b[255] = '\0';
                p->sdp_port_b = 0;
            }
            else
            {
                const char *payload = packet + headers_len;

                char *payload_copy = malloc(payload_len + 1);
                if (payload_copy)
                {
                    memcpy(payload_copy, payload, payload_len);
                    payload_copy[payload_len] = '\0';

                    // Extraer Call-ID
                    char *cid = extraer_call_id(payload_copy);
                    strncpy(p->call_id, cid ? cid : "N/A", 255);
                    p->call_id[255] = '\0';

                    if (cid)
                        free(cid);

                    // Extraer método SIP
                    char *metodo = extraer_metodo_sip(payload_copy);
                    strncpy(p->metodo, metodo ? metodo : "N/A", 29);
                    p->metodo[29] = '\0';
                    if (metodo)
                        free(metodo);

                    // Extraer from
                    char *fro = extraer_from(payload_copy);
                    strncpy(p->fro, fro ? fro : "N/A", 49);
                    p->fro[49] = '\0';
                    if (fro)
                        free(fro);

                    // Extraer to
                    char *to = extraer_to(payload_copy);
                    strncpy(p->to, to ? to : "N/A", 49);
                    p->to[49] = '\0';
                    if (to)
                        free(to);

                    // Extraer user agent
                    char *user_agent = extraer_user_agent(payload_copy);
                    strncpy(p->user_agent, user_agent ? user_agent : "N/A", 255);
                    p->user_agent[255] = '\0';
                    if (user_agent)
                        free(user_agent);
                    // Aquí se agrega la lógica de 200 OK
                    if (es_sip_200_ok(payload_copy))
                    {
                        strncpy(p->to_200, p->to, 49);
                        p->to_200[49] = '\0';

                        // Extraer IP de línea c=
                        const char *c_line = strstr(payload_copy, "\nc=IN IP4 ");
                        if (c_line)
                        {
                            sscanf(c_line, "\nc=IN IP4 %63s", p->sdp_ip_b);
                            p->sdp_ip_b[63] = '\0';
                        }

                        // Extraer puerto de línea m=
                        const char *m_line = strstr(payload_copy, "\nm=audio ");
                        if (m_line)
                        {
                            sscanf(m_line, "\nm=audio %hu", &p->sdp_port_b);
                        }

                        // Extraer codecs (a=rtpmap)
                        const char *a_line = payload_copy;
                        char *codecs_ptr = p->sdp_codecs_b;
                        size_t remaining = sizeof(p->sdp_codecs_b);
                        codecs_ptr[0] = '\0'; // Inicializar
                        const char *prefix = "\na=rtpmap:";
                        size_t prefix_len = strlen(prefix);

                        while ((a_line = strstr(a_line, prefix)) != NULL)
                        {
                            const char *start = a_line + prefix_len;

                            // Buscar el espacio después del payload number
                            const char *space_pos = strchr(start, ' ');
                            if (!space_pos)
                                break; // formato incorrecto, salir

                            const char *codec_start = space_pos + 1;

                            // Buscar fin de línea
                            const char *end = strchr(codec_start, '\n');
                            if (!end)
                                break;

                            size_t len = end - codec_start;

                            // Copiar solo si la longitud es positiva y quepa
                            if (len > 0 && len < remaining - 1)
                            {
                                // Evitar espacios al inicio o fin
                                while (len > 0 && (codec_start[0] == ' ' || codec_start[0] == '\r'))
                                {
                                    codec_start++;
                                    len--;
                                }
                                while (len > 0 && (codec_start[len - 1] == ' ' || codec_start[len - 1] == '\r'))
                                {
                                    len--;
                                }
                                if (len > 0)
                                {
                                    strncat(codecs_ptr, codec_start, len);
                                    strncat(codecs_ptr, ",", 1);
                                    codecs_ptr += len + 1;
                                    remaining -= len + 1;
                                }
                            }
                            a_line = end;
                        }

                        // Quitar coma final
                        size_t clen = strlen(p->sdp_codecs_b);
                        if (clen > 0 && p->sdp_codecs_b[clen - 1] == ',')
                        {
                            p->sdp_codecs_b[clen - 1] = '\0';
                        }
                    }
                    else
                    {
                        strncpy(p->to_200, "N/A", 49);
                        p->to_200[49] = '\0';
                        strncpy(p->sdp_ip_b, "N/A", 63);
                        p->sdp_port_b = 0;
                        strncpy(p->sdp_codecs_b, "N/A", 255);
                    }
                    // PAI
                    char *pai = extraer_p_asserted_id(payload_copy);
                    strncpy(p->p_asserted_id, pai ? pai : "N/A", 127);
                    p->p_asserted_id[127] = '\0';
                    if (pai)
                        free(pai);
                    // SIP URI
                    //  Solo si es INVITE
                    if (strcmp(p->metodo, "INVITE") == 0)
                    {

                        // Extraer IP de línea c=
                        const char *c_line = strstr(payload_copy, "\nc=IN IP4 ");
                        if (c_line)
                        {
                            sscanf(c_line, "\nc=IN IP4 %63s", p->sdp_ip_a);
                            p->sdp_ip_a[63] = '\0';
                        }

                        // Extraer puerto de línea m=
                        const char *a_line = payload_copy;
                        char *codecs_ptr = p->sdp_codecs_a;
                        size_t remaining = sizeof(p->sdp_codecs_a);
                        codecs_ptr[0] = '\0'; // Inicializar
                        const char *prefix = "\na=rtpmap:";
                        size_t prefix_len = strlen(prefix);

                        while ((a_line = strstr(a_line, prefix)) != NULL)
                        {
                            const char *start = a_line + prefix_len;

                            // Buscar el espacio después del payload number
                            const char *space_pos = strchr(start, ' ');
                            if (!space_pos)
                                break; // formato incorrecto, salir

                            const char *codec_start = space_pos + 1;

                            // Buscar fin de línea
                            const char *end = strchr(codec_start, '\n');
                            if (!end)
                                break;

                            size_t len = end - codec_start;

                            // Copiar solo si la longitud es positiva y quepa
                            if (len > 0 && len < remaining - 1)
                            {
                                // Evitar espacios al inicio o fin
                                while (len > 0 && (codec_start[0] == ' ' || codec_start[0] == '\r'))
                                {
                                    codec_start++;
                                    len--;
                                }
                                while (len > 0 && (codec_start[len - 1] == ' ' || codec_start[len - 1] == '\r'))
                                {
                                    len--;
                                }
                                if (len > 0)
                                {
                                    strncat(codecs_ptr, codec_start, len);
                                    strncat(codecs_ptr, ",", 1);
                                    codecs_ptr += len + 1;
                                    remaining -= len + 1;
                                }
                            }
                            a_line = end;
                        }

                        // Quitar coma final
                        size_t clen = strlen(p->sdp_codecs_a);
                        if (clen > 0 && p->sdp_codecs_a[clen - 1] == ',')
                        {
                            p->sdp_codecs_a[clen - 1] = '\0';
                        }

                        char *uri = extraer_sip_uri(payload_copy);
                        strncpy(p->sip_uri, uri ? uri : "N/A", 99);
                        p->sip_uri[99] = '\0';
                        if (uri)
                            free(uri);
                    }
                    // PCV
                    char *pcv = extraer_p_charging_vector(payload_copy);
                    strncpy(p->pcv, pcv ? pcv : "N/A", 127);
                    p->pcv[127] = '\0';
                    if (pcv)
                        free(pcv);
                    // Ver si es 100 Trying o 180 Ringing
                    p->es_trying_o_ringing = es_100_trying_o_180_ringing(payload_copy) ? 1 : 0;
                    //
                    free(payload_copy);
                }
                else
                {
                    strncpy(p->call_id, "ERR", 255);
                    p->call_id[255] = '\0';
                    strncpy(p->metodo, "EMPTY", 29);
                    p->metodo[29] = '\0';
                    strncpy(p->fro, "EMPTY", 49);
                    p->fro[49] = '\0';
                    strncpy(p->to, "EMPTY", 49);
                    p->to[49] = '\0';
                    strncpy(p->user_agent, "EMPTY", 255);
                    p->user_agent[255] = '\0';
                    strncpy(p->to_200, "EMPTY", 49);
                    p->to_200[49] = '\0';
                    strncpy(p->p_asserted_id, "EMPTY", 127);
                    p->p_asserted_id[127] = '\0';
                    strncpy(p->sip_uri, "EMPTY", 99);
                    p->sip_uri[99] = '\0';
                    strncpy(p->pcv, "EMPTY", 127);
                    p->pcv[127] = '\0';
                    strncpy(p->sdp_ip_a, "EMPTY", 63);
                    p->sdp_ip_a[63] = '\0';
                    strncpy(p->sdp_codecs_a, "EMPTY", 255);
                    p->sdp_codecs_a[255] = '\0';
                    p->sdp_port_a = 0;
                    strncpy(p->sdp_ip_b, "EMPTY", 63);
                    p->sdp_ip_b[63] = '\0';
                    strncpy(p->sdp_codecs_b, "EMPTY", 255);
                    p->sdp_codecs_b[255] = '\0';
                    p->sdp_port_b = 0;
                }
            }
        }

        else if (ntohs(udp_hdr->uh_sport) >= 16384 && ntohs(udp_hdr->uh_sport) <= 32768)
        {
            sprintf(p->protocol, "RTP");
            p->rtp_seq = (payload[2] << 8) | payload[3];
            p->rtp_timestamp = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7];
        }
        else
        {
            sprintf(p->protocol, "UNKNOWN");
        }

        PyObject *capsule = PyCapsule_New(p, "Paquete", destroy_capsule);
        PyList_Append(pkt_list, capsule);
        Py_DECREF(capsule);

        count++;
    }

    if (count == 0)
    {
        Py_RETURN_NONE; // Si no se capturaron paquetes, devolver None
    }

    return pkt_list;
}

/* Función para cerrar el archivo PCAP */
static PyObject *close_pcap(PyObject *self, PyObject *args)
{
    pcap_close(handle);
    Py_RETURN_NONE;
}

/* Definir métodos del módulo */
static PyMethodDef PcapMethods[] = {
    {"open_pcap", open_pcap, METH_VARARGS, "Abre un archivo PCAP"},
    {"open_live", open_live, METH_VARARGS, "Abre una interfaz de red en vivo"},
    {"read_pcap", read_pcap, METH_VARARGS, "Lee paquetes sin procesar de un archivo PCAP (devuelve bytes)"},
    {"read_live", read_live, METH_VARARGS, "Lee paquetes sin procesar en live (devuelve bytes)"},
    {"procesar_paquete", procesar_paquete, METH_VARARGS, "Procesa un paquete y devuelve su información"},
    {"close_pcap", close_pcap, METH_VARARGS, "Cierra el archivo PCAP"},
    {NULL, NULL, 0, NULL}};

/* Definir el módulo */
static struct PyModuleDef pcapmodule = {
    PyModuleDef_HEAD_INIT,
    "pcap_wrapper",
    "Wrapper en C para libpcap",
    -1,
    PcapMethods};

/* Inicializar el módulo */
PyMODINIT_FUNC PyInit_pcap_wrapper(void)
{
    return PyModule_Create(&pcapmodule);
}
