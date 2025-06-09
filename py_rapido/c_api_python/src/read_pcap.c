#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <regex.h>
#include <string.h>

typedef struct {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t packet_size;
    char protocol[20];
    char *call_id;
    uint16_t rtp_seq;
    uint32_t rtp_timestamp;

}Paquete;

char *extraer_call_id2(const char *payload)
{
	static char call_id[256]="N/A";
	char *p1=NULL,*p2=NULL;
	if((p1=strstr(payload,"Call-ID:"))!=NULL){
		p1+=8;
		if((p2=strstr(p1,"\r\n"))!=NULL){
			strncpy(call_id,p1,p2-p1);
		}
	}
	
	return call_id;
}

/* Función para extraer Call-ID de SIP */
char *extraer_call_id(const char *payload)
{
    regex_t regex;
    regmatch_t matches[2];
    static char call_id[256];

    if (regcomp(&regex, "Call-ID: ([^\r\n]+)", REG_EXTENDED) != 0)
        return NULL;

    if (regexec(&regex, payload, 2, matches, 0) == 0)
    {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        strncpy(call_id, payload + matches[1].rm_so, len);
        call_id[len] = '\0';
    }
    else
    {
        strcpy(call_id, "N/A");
    }

    regfree(&regex);
    return call_id;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <archivo_pcap>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_count = 0;
    uint64_t total_bytes=0;
    struct timeval start_time, end_time;

    /* Abrir el archivo PCAP */
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "No se pudo abrir el archivo PCAP: %s\n", errbuf);
        return 1;
    }
    gettimeofday(&start_time, NULL);
    /* Leer paquetes uno por uno */
        Paquete* p = malloc(sizeof(Paquete));

    while (pcap_next_ex(handle, &header, &packet) == 1) {
        packet_count++;
        total_bytes+=header->len;

   


        struct ether_header *eth = (struct ether_header *)packet;
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
        struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4));
        const char *payload = packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr);

        p->timestamp=(header->ts.tv_sec * 1000000) + header->ts.tv_usec;
        p->src_ip=(ip_hdr->ip_src.s_addr);
        p->dst_ip=(ip_hdr->ip_dst.s_addr);
        p->src_port=ntohs(udp_hdr->uh_sport);
        p->dst_port=ntohs(udp_hdr->uh_dport);
        p->packet_size=header->len;

        if (ntohs(udp_hdr->uh_sport) == 5060 || ntohs(udp_hdr->uh_dport) == 5060)
        {
            sprintf(p->protocol,"SIP");
            //p->call_id=extraer_call_id(payload);
            p->call_id=extraer_call_id2(payload);

        }
        else if (ntohs(udp_hdr->uh_sport) >= 16384 && ntohs(udp_hdr->uh_sport) <= 32768)
        {
            sprintf(p->protocol,"RTP");
            p->rtp_seq=(payload[2] << 8) | payload[3];
            p->rtp_timestamp=(payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7];

        }
        else
        {
             sprintf(p->protocol,"UNKNOWN");

        }

}
	free(p);



    gettimeofday(&end_time, NULL);
     double time_elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                          (end_time.tv_usec - start_time.tv_usec) / 1e6;

    if (time_elapsed > 0) {
        double bitrate = (total_bytes * 8) / time_elapsed;
        printf("\nTiempo real: %.6f segundos\n", time_elapsed);
        printf("Total de paquetes: %d\n", packet_count);
        printf("Tasa promedio: %.2f bps (%.2f Mbps)\n", bitrate, bitrate / 1e6);
    } else {
        printf("\nNo se pudo calcular la tasa: solo se capturó un paquete.\n");
    }
    /* Cerrar el manejador de captura */
    pcap_close(handle);

    
    return 0;
}
