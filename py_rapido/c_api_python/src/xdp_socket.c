#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <net/if.h>
#include <bpf/xsk.h>
#include <linux/if_xdp.h>
#include <Python.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#define PY_SSIZE_T_CLEAN
#include <regex.h>
#include <stdbool.h>


#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (2U << 0)
#endif

#define NUM_FRAMES 512
#define FRAME_SIZE 2048
#define RX_BATCH 64

struct xdp_socket {
    struct xsk_umem *umem;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod fq;
    struct xsk_umem_config umem_cfg;
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket *xsk;
    void *umem_area;
    int fd;
};

static struct xdp_socket xs;






// Definición de la estructura que vamos a pasar a Python
typedef struct {
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
} Paquete2;


int xdp_open(const char *ifname) {
    xs.umem_cfg.fill_size = NUM_FRAMES;
    xs.umem_cfg.comp_size = NUM_FRAMES;
    xs.umem_cfg.frame_size = FRAME_SIZE;
    xs.umem_cfg.frame_headroom = 0;
    xs.umem_cfg.flags = 0;

    xs.xsk_cfg.rx_size = NUM_FRAMES;
    xs.xsk_cfg.tx_size = 0;
    xs.xsk_cfg.libbpf_flags = 0;
    xs.xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    xs.xsk_cfg.bind_flags = XDP_USE_NEED_WAKEUP;

    if (posix_memalign(&xs.umem_area, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        perror("posix_memalign");
        return -1;
    }

    if (mlock(xs.umem_area, NUM_FRAMES * FRAME_SIZE)) {
        perror("mlock");
        free(xs.umem_area);
        return -1;
    }

    if (xsk_umem__create(&xs.umem, xs.umem_area, NUM_FRAMES * FRAME_SIZE, &xs.fq, &xs.rx, &xs.umem_cfg)) {
        perror("xsk_umem__create");
        free(xs.umem_area);
        return -1;
    }

    // Rellenar fill queue
    uint32_t idx;
    if (xsk_ring_prod__reserve(&xs.fq, NUM_FRAMES, &idx) != NUM_FRAMES) {
        fprintf(stderr, "Error: xsk_ring_prod__reserve failed\n");
        xsk_umem__delete(xs.umem);
        free(xs.umem_area);
        return -1;
    }
    for (int i = 0; i < NUM_FRAMES; i++) {
        *xsk_ring_prod__fill_addr(&xs.fq, idx + i) = i * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&xs.fq, NUM_FRAMES);

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        xsk_umem__delete(xs.umem);
        free(xs.umem_area);
        return -1;
    }

    if (xsk_socket__create(&xs.xsk, ifname, 0, xs.umem, &xs.rx, NULL, &xs.xsk_cfg)) {
        perror("xsk_socket__create");
        xsk_umem__delete(xs.umem);
        free(xs.umem_area);
        return -1;
    }

    xs.fd = xsk_socket__fd(xs.xsk);
    return 0;
}

static void paquete_capsule_destructor(PyObject *capsule) {
    Paquete2 *p = (Paquete2 *)PyCapsule_GetPointer(capsule, "Paquete2");
    free(p);
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

PyObject* xdp_recv_py() {
    struct pollfd fds[] = {
        { .fd = xs.fd, .events = POLLIN },
    };

    int ret = poll(fds, 1, 1000);
    if (ret <= 0) {
        Py_RETURN_NONE;
    }

    uint32_t idx;
    ret = xsk_ring_cons__peek(&xs.rx, 1, &idx);
    if (ret <= 0) {
        Py_RETURN_NONE;
    }

    const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xs.rx, idx);
    uint64_t addr = desc->addr;
    void *pkt = xsk_umem__get_data(xs.umem_area, addr);
    uint32_t pkt_len = desc->len;
    Paquete2 *p = malloc(sizeof(Paquete2));
    if (!p) {
        xsk_ring_cons__release(&xs.rx, 1);
        PyErr_NoMemory();
        return NULL;
    }

    // Timestamp
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    p->timestamp = (uint64_t)ts.tv_sec * 1000000ULL + (ts.tv_nsec / 1000);
    p->packet_size = pkt_len;

    // Valores por defecto
    if (pkt_len >= sizeof(struct ether_header)) {
        struct ether_header *eth = (struct ether_header *)pkt;
        struct ip *ip_hdr = (struct ip *)(pkt + sizeof(struct ether_header));
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        const char *payload = pkt + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr);
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {

            // Guardar protocolo como número
            p->transporte_proto = ip_hdr->ip_p;

            if (ip_hdr->ip_p == IPPROTO_UDP &&
                pkt_len >= sizeof(struct ether_header) + ip_hdr_len + sizeof(struct udphdr)) {

                struct udphdr *udp_hdr = (struct udphdr *)((uint8_t *)ip_hdr + ip_hdr_len);
                p->src_ip = ip_hdr->ip_src.s_addr;
                p->dst_ip = ip_hdr->ip_dst.s_addr;
                p->src_port = ntohs(udp_hdr->uh_sport);
                p->dst_port = ntohs(udp_hdr->uh_dport);
                
                if (ntohs(udp_hdr->uh_sport) == 5060 || ntohs(udp_hdr->uh_dport) == 5060)
                {
                    sprintf(p->protocol, "SIP");
                    int ip_header_len = ip_hdr->ip_hl * 4;
                    int udp_header_len = sizeof(struct udphdr);
                    int l2_header_len = sizeof(struct ether_header);
                    int headers_len = l2_header_len + ip_header_len + udp_header_len;

                    int payload_len = (int)pkt_len - headers_len;
                    if (payload_len <= 0 || (int)pkt_len < headers_len) {
                        strncpy(p->call_id, "EMPTY", 255);     p->call_id[255] = '\0';
                        strncpy(p->metodo, "EMPTY", 29);       p->metodo[29] = '\0';
                        strncpy(p->fro, "EMPTY", 49);          p->fro[49] = '\0';
                        strncpy(p->to, "EMPTY", 49);           p->to[49] = '\0';
                        strncpy(p->user_agent, "EMPTY", 255);  p->user_agent[255] = '\0';
                        strncpy(p->to_200, "EMPTY", 49);       p->to_200[49] = '\0';
                        strncpy(p->p_asserted_id, "EMPTY", 127); p->p_asserted_id[127] = '\0';
                        strncpy(p->sip_uri, "EMPTY", 99);      p->sip_uri[99] = '\0';
                        strncpy(p->pcv, "EMPTY", 127);         p->pcv[127] = '\0';
                        strncpy(p->sdp_ip_a, "EMPTY", 63);     p->sdp_ip_a[63] = '\0';
                        strncpy(p->sdp_codecs_a, "EMPTY", 255); p->sdp_codecs_a[255] = '\0';
                        p->sdp_port_a = 0;
                        strncpy(p->sdp_ip_b, "EMPTY", 63);     p->sdp_ip_b[63] = '\0';
                        strncpy(p->sdp_codecs_b, "EMPTY", 255); p->sdp_codecs_b[255] = '\0';
                        p->sdp_port_b = 0;
                    }
                    else 
                    {
                        const char *payload = (const char *)pkt + headers_len;

                        char *payload_copy = malloc(payload_len + 1);
                        if (payload_copy) {
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
            }
        }

    }
    xsk_ring_cons__release(&xs.rx, 1);

    uint32_t fq_idx;
    if (xsk_ring_prod__reserve(&xs.fq, 1, &fq_idx) == 1) {
        *xsk_ring_prod__fill_addr(&xs.fq, fq_idx) = addr;
        xsk_ring_prod__submit(&xs.fq, 1);
    }

    PyObject *capsule = PyCapsule_New((void *)p, "Paquete2", paquete_capsule_destructor);
    if (!capsule) {
        fprintf(stderr, "[XDP] Error: PyCapsule_New devolvió NULL\n");
    }

    return capsule;
}




void xdp_close() {
    if (xs.xsk) xsk_socket__delete(xs.xsk);
    if (xs.umem) xsk_umem__delete(xs.umem);
    if (xs.umem_area) free(xs.umem_area);
}
static PyObject* xdp_open_py(PyObject *self, PyObject *args) {
    const char *ifname;
    if (!PyArg_ParseTuple(args, "s", &ifname)) {
        return NULL;
    }

    int ret = xdp_open(ifname);
    if (ret != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Fallo al abrir socket XDP");
        return NULL;
    }

    Py_RETURN_TRUE;
}

static PyObject* xdp_close_py(PyObject *self, PyObject *args) {
    xdp_close();
    Py_RETURN_NONE;
}

static PyMethodDef XDPMethods[] = {
    {"xdp_recv", (PyCFunction)xdp_recv_py, METH_NOARGS, "Recibe paquete y devuelve PyCapsule"},
    {"xdp_open", xdp_open_py, METH_VARARGS, "Inicializa socket XDP en una interfaz"},
    {"xdp_close", xdp_close_py, METH_NOARGS, "Libera recursos del socket XDP"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef xdp_module = {
    PyModuleDef_HEAD_INIT,
    "xdp",
    "Modulo para recibir paquetes XDP con PyCapsule",
    -1,
    XDPMethods
};

PyMODINIT_FUNC PyInit_xdp(void) {
    return PyModule_Create(&xdp_module);
}
