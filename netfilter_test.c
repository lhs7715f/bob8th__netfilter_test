#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/*
struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      // header length 
           ip_v:4;         // version 
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       // version 
           ip_hl:4;        // header length 
#endif
    u_int8_t ip_tos;       // type of service 
    u_int16_t ip_len;         // total length 
    u_int16_t ip_id;          // identification 
    u_int16_t ip_off;
    u_int8_t ip_ttl;          // time to live 
    u_int8_t ip_p;            // protocol 
    u_int16_t ip_sum;         // checksum 
    struct in_addr ip_src, ip_dst; // source and dest address 
};
*/

/*
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       // source port 
    u_int16_t th_dport;       // destination port 
    u_int32_t th_seq;          // sequence number 
    u_int32_t th_ack;          // acknowledgement number 
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         // (unused) 
           th_off:4;        // data offset 
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        // data offset 
           th_x2:4;         // (unused) 
#endif
    u_int8_t  th_flags;       // control flags 
    u_int16_t th_win;         // window 
    u_int16_t th_sum;         // checksum 
    u_int16_t th_urp;         // urgent pointer 
};
*/

char blocked_host[100]; 
int flag_blocked = 0;

void filter(unsigned char *data, int ret){
	struct libnet_ipv4_hdr * ipv4 = (struct libnet_ipv4_hdr *)data;
	char http_method[6][7] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
	char check[5][1] = {"G", "P", "H", "D", "O"};
	char * host_info_start = "Host: ";
	int flag_http = 0;
	flag_blocked = 0;
	
	if((ipv4->ip_v == 4) && (ipv4->ip_p == IPPROTO_TCP)){
		struct libnet_tcp_hdr * tcp = (struct libnet_tcp_hdr *)(((uint8_t *)ipv4) + (ipv4->ip_hl * 4));
		char * data_start = NULL;

		for(int i = 0; i < 100; i++){
			char * loc = (char *)(((uint8_t *)tcp) + (tcp->th_off * 4) + i); // data가 시작하는 지점에서 바로 http method가 나타나지 않고 공백이 있을 수 있기 때문에 searching

			if(*loc == check[0][1] || *loc == check[1][1] || *loc == check[2][1] || *loc == check[3][1] || *loc == check[4][1]){
				if(!strncmp(http_method[i], loc, strlen(http_method[i]))){
					data_start = loc;
					flag_http = 1;
					break;
				}
			}
			else
				return;
		}

		if(flag_http){ // 해당 패킷이 http 패킷이라면
			for(int i = 16; i < ret; i++){ // GET Http ~~ 에서  Host: 가 나오는 부분 까지의 길이가 최소 16 이상이므로 16만큼 떨어진 위치부터 searching
				if(!strncmp(host_info_start, (data_start + i), strlen(host_info_start))){ // 만약 "Host: " 부분을 찾았다면
					if(!strncmp(blocked_host, (data_start + i + 6), strlen(blocked_host))){ // 그 이후에 나오는 부분을 우리가 블락하고자 하는 사이트와 비교하여 일치하면 flag on.
						flag_blocked = 1;
						printf("cannot access to <%s>\n", blocked_host);
						break;
					}
				}
			}
		}
	}

}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d ", ret);
		filter(data, ret);
	}

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, (flag_blocked ? NF_DROP : NF_ACCEPT), 0, NULL);
}

void usage(){
	printf("syntax: ./netfilter_test <host>\n");
	printf("example: ./netfilter_test test.gilgil.net\n");
	return;
}

int main(int argc, char **argv)
{
	if (argc != 2)  
		usage(); 

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	strncpy(blocked_host, argv[1], strlen(argv[1]));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
