// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <locale.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdpsock.h"
#include <linux/ipv6.h>
#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <netinet/tcp.h>
#include <rte_hash.h>
#include <rte_jhash.h>

extern void init_ai_models(const char* trt_path, const char* xgb_path);
extern bool run_hybrid_inference(float* sequence_data);

struct rate {
    __u64 count;
    __u64 last_time_stamp;
};

int suspicious_v4_fd = -1;
int suspicious_v6_fd = -1;
int blacklist_v4_fd = -1;
int blacklist_v6_fd = -1;
int rate_blacklist_v4_fd = -1;
int rate_blacklist_v6_fd = -1;

#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif

#define NUM_FRAMES (4 * 1024)
#define MIN_PKT_SIZE 64
#define STRERR_BUFSIZE 1024
#define EXPIRY_TIME_NS (600ULL * 1000000000ULL)

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

enum benchmark_type { BENCH_RXDROP = 0, BENCH_TXONLY = 1, BENCH_L2FWD = 2 };

static enum benchmark_type opt_bench = BENCH_RXDROP;
static enum xdp_attach_mode opt_attach_mode = XDP_MODE_NATIVE;
static const char *opt_if = "";
static int opt_ifindex;
static unsigned long opt_duration;
static unsigned long start_time;
static bool benchmark_done;
static u32 opt_batch_size = 64;
static int opt_interval = 1;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;
static int opt_mmap_flags;
static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static bool opt_need_wakeup = true;
static u32 opt_num_xsks = 12; 
static bool opt_busy_poll;
static clockid_t opt_clock = CLOCK_MONOTONIC;
static struct xdp_program *xdp_prog;
static unsigned long prev_time;

struct xsk_ring_stats {
    unsigned long rx_npkts;
    unsigned long tx_npkts;
    unsigned long prev_rx_npkts;
    unsigned long prev_tx_npkts;
    unsigned long blocked_packets;
};

struct xsk_app_stats {
    unsigned long rx_empty_polls;
    unsigned long prev_rx_empty_polls;
    unsigned long opt_polls;
};

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    struct xsk_ring_stats ring_stats;
    struct xsk_app_stats app_stats;
    u32 outstanding_tx;
};

static int num_socks;
struct xsk_socket_info *xsks[64];
int sock;
struct rte_ring *packet_ring;
struct pkt_info {
    char *data;      
    uint32_t len;    
    uint64_t addr;   
    struct xsk_socket_info *xsk; 
};
struct rte_mempool *meta_pool;

pthread_mutex_t fq_lock = PTHREAD_MUTEX_INITIALIZER;

static void drain_cq(struct xsk_socket_info *xsk) {
    uint32_t idx_cq, idx_fq;
    unsigned int completed = xsk_ring_cons__peek(&xsk->umem->cq, opt_batch_size, &idx_cq);
    if (!completed) return;

    pthread_mutex_lock(&fq_lock);
    if (xsk_ring_prod__reserve(&xsk->umem->fq, completed, &idx_fq) == completed) {
        for (unsigned int i = 0; i < completed; i++) {
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = 
                *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++);
        }
        xsk_ring_prod__submit(&xsk->umem->fq, completed);
    }
    pthread_mutex_unlock(&fq_lock);

    xsk_ring_cons__release(&xsk->umem->cq, completed);
    __sync_fetch_and_sub(&xsk->outstanding_tx, completed);
}

static unsigned long get_nsecs(void) {
    struct timespec ts;
    clock_gettime(opt_clock, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void print_benchmark(bool running) {
    const char *bench_str = "rxdrop";
    if (opt_bench == BENCH_TXONLY) bench_str = "txonly";
    else if (opt_bench == BENCH_L2FWD) bench_str = "l2fwd";
    printf("%s %s ", opt_if, bench_str);
    if (opt_attach_mode == XDP_MODE_SKB) printf("xdp-skb ");
    else printf("xdp-drv ");
    if (running) { printf("running..."); fflush(stdout); }
}

static void dump_stats(void) {
    unsigned long now = get_nsecs();
    long dt = now - prev_time;
    prev_time = now;
    int i;
    for (i = 0; i < num_socks && xsks[i]; i++) {
        double rx_pps = (xsks[i]->ring_stats.rx_npkts - xsks[i]->ring_stats.prev_rx_npkts) * 1000000000. / dt;
        double tx_pps = (xsks[i]->ring_stats.tx_npkts - xsks[i]->ring_stats.prev_tx_npkts) * 1000000000. / dt;
        printf("\n sock%d@", i); print_benchmark(false); printf("\n");
        printf("%-18s %-14s %-14s %-14.2f\n", "", "pps", "pkts", dt / 1000000000.);
        printf("%-18s %'-14.0f %'-14lu\n", "rx", rx_pps, xsks[i]->ring_stats.rx_npkts);
        printf("%-18s %'-14.0f %'-14lu\n", "tx", tx_pps, xsks[i]->ring_stats.tx_npkts);
        xsks[i]->ring_stats.prev_rx_npkts = xsks[i]->ring_stats.rx_npkts;
        xsks[i]->ring_stats.prev_tx_npkts = xsks[i]->ring_stats.tx_npkts;
        printf("%-18s %'-14lu\n", "Blocked packets", xsks[i]->ring_stats.blocked_packets);
    }
}

static bool is_benchmark_done(void) {
    if (opt_duration > 0) {
        unsigned long dt = (get_nsecs() - start_time);
        if (dt >= opt_duration) benchmark_done = true;
    }
    return benchmark_done;
}

static void cleanup_expired_blacklist(int map_fd, bool is_v6) {
    uint8_t key[16] = {0}, next[16] = {0}; 
    uint64_t timestamp;
    uint64_t current = get_nsecs(); 
    while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next, &timestamp) == 0) {
            if (current - timestamp > EXPIRY_TIME_NS) {
                bpf_map_delete_elem(map_fd, &next);
                printf("Removed expired %s from blacklist.\n", is_v6 ? "IPv6" : "IPv4");
            }
        }
        memcpy(key, next, 16);
    }
}

static void *janitor_thread_rate_removal(__attribute__((unused)) void *arg) {
    while (!is_benchmark_done()) {
        sleep(30); 
        cleanup_expired_blacklist(rate_blacklist_v4_fd, false);
        cleanup_expired_blacklist(rate_blacklist_v6_fd, true); 
    }
    return NULL;
}

static void *poller(__attribute__((unused)) void *arg) {
    while (!is_benchmark_done()) {
        sleep(opt_interval);
        dump_stats();
    }
    return NULL;
}

static void __exit_with_error(int error, const char *file, const char *func, int line) {
    fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func, line, error, strerror(error));
    exit(EXIT_FAILURE);
}
#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static void int_exit(__attribute__((unused)) int sig) { benchmark_done = true; }

struct flow_features {
    float length; float protocol; float src_port;
    float dst_port; float header_len; float tcp_flags;
};

static bool extract_features(char *pkt, uint32_t len, struct iphdr *iph, struct flow_features *feats) {
    if (!iph) return false;
    feats->length = (float)ntohs(iph->tot_len);
    feats->protocol = (float)iph->protocol;
    feats->header_len = (float)(iph->ihl * 4);
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + (iph->ihl * 4));
        feats->src_port = (float)ntohs(tcph->source);
        feats->dst_port = (float)ntohs(tcph->dest);
        feats->tcp_flags = (float)(tcph->fin | (tcph->syn << 1) | (tcph->rst << 2) | (tcph->psh << 3) | (tcph->ack << 4) | (tcph->urg << 5));
        return true;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(pkt + sizeof(struct ethhdr) + (iph->ihl * 4));
        feats->src_port = (float)ntohs(udph->source);
        feats->dst_port = (float)ntohs(udph->dest);
        feats->tcp_flags = 0.0f; 
        return true;
    }
    return false; 
}

static bool extract_features_v6(char *pkt, uint32_t len, struct ipv6hdr *ip6h, struct flow_features *feats) {
    if (!ip6h) return false;
    feats->length = (float)ntohs(ip6h->payload_len);
    feats->protocol = (float)ip6h->nexthdr;
    feats->header_len = 40.0f; 
    if (ip6h->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + 40);
        feats->src_port = (float)ntohs(tcph->source);
        feats->dst_port = (float)ntohs(tcph->dest);
        feats->tcp_flags = (float)(tcph->fin | (tcph->syn << 1) | (tcph->rst << 2) | (tcph->psh << 3) | (tcph->ack << 4) | (tcph->urg << 5));
        return true;
    } else if (ip6h->nexthdr == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(pkt + sizeof(struct ethhdr) + 40);
        feats->src_port = (float)ntohs(udph->source);
        feats->dst_port = (float)ntohs(udph->dest);
        feats->tcp_flags = 0.0f; 
        return true;
    }
    return false;
}

#define SEQ_LEN 10
#define NUM_FEATURES 6

struct flow_key {
    uint8_t src_ip[16]; 
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
} __attribute__((packed));

struct flow_state {
    float sequence[SEQ_LEN * NUM_FEATURES];
    int packet_count;
    pthread_mutex_t lock; 
};

struct rte_hash *flow_table;

void init_flow_table() {
    struct rte_hash_parameters hash_params = {
        .name = "flow_hash",
        .entries = 1000000, 
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    flow_table = rte_hash_create(&hash_params);
}

static void add_to_suspicious_map(int map_fd, void *ip, bool is_v6) {
    struct rate r = { .count = 1, .last_time_stamp = get_nsecs() };
    if (bpf_map_update_elem(map_fd, ip, &r, BPF_ANY) != 0) {
        fprintf(stderr, "Error updating suspicious map\n");
    }
}

static struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"xdp-skb", no_argument, 0, 'S'},
    {0, 0, 0, 0}
};

static void parse_command_line(int argc, char **argv) {
    int option_index, c;
    opterr = 0;
    for (;;) {
        c = getopt_long(argc, argv, "i:S", long_options, &option_index);
        if (c == -1) break;
        switch (c) {
        case 'i': opt_if = optarg; break;
        case 'S': opt_attach_mode = XDP_MODE_SKB; opt_xdp_bind_flags |= XDP_COPY; break;
        }
    }
    opt_ifindex = if_nametoindex(opt_if);
    if (!opt_ifindex) {
        fprintf(stderr, "ERROR: interface \"%s\" does not exist\n", opt_if);
        exit(EXIT_FAILURE);
    }
}

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size) {
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    struct xsk_umem_config cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = opt_xsk_frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = opt_umem_flags
    };
    int err = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
    if (err) exit_with_error(-err);
    umem->buffer = buffer;
    return umem;
}

static void xsk_populate_fill_ring(struct xsk_umem_info *umem) {
    int err, i; u32 idx;
    err = xsk_ring_prod__reserve(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
    if (err != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2) exit_with_error(-err);
    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * opt_xsk_frame_size;
    xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, bool rx, bool tx, int queue_id) {
    struct xsk_socket_config cfg;
    struct xsk_socket_info *xsk = calloc(1, sizeof(*xsk));
    if (!xsk) exit_with_error(errno);

    xsk->umem = umem;
    memset(&cfg, 0, sizeof(cfg)); 
    cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    cfg.xdp_flags = (opt_attach_mode == XDP_MODE_SKB) ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    cfg.bind_flags = opt_xdp_bind_flags;

    int err = xsk_socket__create(&xsk->xsk, opt_if, queue_id, umem->umem, rx ? &xsk->rx : NULL, tx ? &xsk->tx : NULL, &cfg);
    if (err) {
        fprintf(stderr, "\nERROR: Socket creation failed on Queue %d (Error %d)\n", queue_id, -err);
        exit_with_error(-err);
    }
    return xsk;
}

static void apply_setsockopt(struct xsk_socket_info *xsk) {
    if (!opt_busy_poll) return;
    int sock_opt = 1;
    setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt));
    sock_opt = 20;
    setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt));
    sock_opt = opt_batch_size;
    setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET, (void *)&sock_opt, sizeof(sock_opt));
}

static void rx_drop(struct xsk_socket_info *xsk) {
    unsigned int rcvd, i;
    u32 idx_rx = 0;

    rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
    if (!rcvd) return;

    for (i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
        uint64_t addr = desc->addr;
        uint32_t len = desc->len;
        uint64_t orig = addr; 
        addr = xsk_umem__add_offset_to_addr(addr);

        struct pkt_info *meta;
        if (rte_mempool_get(meta_pool, (void **)&meta) < 0) {
            pthread_mutex_lock(&fq_lock);
            uint32_t idx_fq;
            if (xsk_ring_prod__reserve(&xsk->umem->fq, 1, &idx_fq) == 1) {
                *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq) = orig;
                xsk_ring_prod__submit(&xsk->umem->fq, 1);
            }
            pthread_mutex_unlock(&fq_lock);
            continue;
        }

        meta->data = xsk_umem__get_data(xsk->umem->buffer, addr);
        meta->len = len;
        meta->addr = orig;
        meta->xsk = xsk;

        if (rte_ring_enqueue(packet_ring, meta) < 0) {
            pthread_mutex_lock(&fq_lock);
            uint32_t idx_fq;
            if (xsk_ring_prod__reserve(&xsk->umem->fq, 1, &idx_fq) == 1) {
                *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq) = orig;
                xsk_ring_prod__submit(&xsk->umem->fq, 1);
            }
            pthread_mutex_unlock(&fq_lock);
            rte_mempool_put(meta_pool, meta);
        }       
    }    
    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk->ring_stats.rx_npkts += rcvd; 
}

static void rx_drop_all(void) {
    struct pollfd fds[64] = {};
    int i, p_ret;
    
    for (i = 0; i < num_socks; i++) {
        fds[i].fd = xsk_socket__fd(xsks[i]->xsk);
        fds[i].events = POLLIN;
    }
    
    for (;;) {
        for (i = 0; i < num_socks; i++) {
            drain_cq(xsks[i]);
        }

        p_ret = poll(fds, num_socks, 100);
        
        if (p_ret > 0) {
            for (i = 0; i < num_socks; i++) {
                if (fds[i].revents & POLLIN) {
                    rx_drop(xsks[i]);
                }
            }
        }
        if (benchmark_done) break;
    }
}

static int worker_thread(__attribute__((unused)) void *arg) {
    struct pkt_info *meta;

    while (!benchmark_done) {
        if (rte_ring_dequeue(packet_ring, (void **)&meta) < 0) {
            usleep(10);
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)meta->data;
        struct flow_key key = {0};
        struct flow_features current_feats;
        bool valid_pkt = false, is_ipv6 = false, drop_packet = false; 

        if (eth->h_proto == htons(ETH_P_IP)) {
            struct iphdr *iph = (struct iphdr *)(meta->data + sizeof(struct ethhdr));
            if (extract_features(meta->data, meta->len, iph, &current_feats)) {
                if (iph->saddr < iph->daddr) {
                    memcpy(&key.src_ip[12], &iph->saddr, 4);
                    memcpy(&key.dst_ip[12], &iph->daddr, 4);
                } else {
                    memcpy(&key.src_ip[12], &iph->daddr, 4);
                    memcpy(&key.dst_ip[12], &iph->saddr, 4);
                }
                key.proto = iph->protocol;
                valid_pkt = true;
            }
        } 
        else if (eth->h_proto == htons(ETH_P_IPV6)) {
            struct ipv6hdr *ip6h = (struct ipv6hdr *)(meta->data + sizeof(struct ethhdr));
            if (extract_features_v6(meta->data, meta->len, ip6h, &current_feats)) {
                if (memcmp(&ip6h->saddr, &ip6h->daddr, 16) < 0) {
                    memcpy(key.src_ip, &ip6h->saddr, 16);
                    memcpy(key.dst_ip, &ip6h->daddr, 16);
                } else {
                    memcpy(key.src_ip, &ip6h->daddr, 16);
                    memcpy(key.dst_ip, &ip6h->saddr, 16);
                }
                key.proto = ip6h->nexthdr;
                valid_pkt = true;
                is_ipv6 = true;
            }
        }

        if (valid_pkt) {
            if (current_feats.src_port < current_feats.dst_port) {
                key.src_port = (uint16_t)current_feats.src_port;
                key.dst_port = (uint16_t)current_feats.dst_port;
            } else {
                key.src_port = (uint16_t)current_feats.dst_port;
                key.dst_port = (uint16_t)current_feats.src_port;
            }

            struct flow_state *state = NULL;
            if (rte_hash_lookup_data(flow_table, &key, (void **)&state) < 0) {
                state = calloc(1, sizeof(struct flow_state));
                pthread_mutex_init(&state->lock, NULL); 
                rte_hash_add_key_data(flow_table, &key, state);
            }

            pthread_mutex_lock(&state->lock); 
            int p_idx = state->packet_count % SEQ_LEN;
            memcpy(&state->sequence[p_idx * NUM_FEATURES], &current_feats, sizeof(float) * NUM_FEATURES);
            state->packet_count++;

            if (state->packet_count >= SEQ_LEN) {
                float flat_sequence[SEQ_LEN * NUM_FEATURES];
                for(int i = 0; i < SEQ_LEN; i++) {
                    int actual_idx = (state->packet_count + i) % SEQ_LEN;
                    memcpy(&flat_sequence[i * NUM_FEATURES], &state->sequence[actual_idx * NUM_FEATURES], sizeof(float) * NUM_FEATURES);
                }

                if (run_hybrid_inference(flat_sequence)) {
                    drop_packet = true; 
                    printf("\n >>> HYBRID AI DETECTED MALICIOUS %s FLOW -> BLOCKING IP <<<\n", is_ipv6 ? "IPv6" : "IPv4");
                    fflush(stdout);
                    __sync_fetch_and_add(&meta->xsk->ring_stats.blocked_packets, 1);
                    if (is_ipv6) {
                        struct ipv6hdr *ip6h = (struct ipv6hdr *)(meta->data + sizeof(struct ethhdr));
                        add_to_suspicious_map(suspicious_v6_fd, &ip6h->saddr, true);
                    } else {
                        struct iphdr *iph = (struct iphdr *)(meta->data + sizeof(struct ethhdr));
                        add_to_suspicious_map(suspicious_v4_fd, &iph->saddr, false);
                    }
                }
            }
            pthread_mutex_unlock(&state->lock); 
        }

        pthread_mutex_lock(&fq_lock);
        if (drop_packet) {
            uint32_t idx_fq;
            while (xsk_ring_prod__reserve(&meta->xsk->umem->fq, 1, &idx_fq) != 1) {
                pthread_mutex_unlock(&fq_lock); usleep(5); pthread_mutex_lock(&fq_lock);
            }
            *xsk_ring_prod__fill_addr(&meta->xsk->umem->fq, idx_fq) = meta->addr;
            xsk_ring_prod__submit(&meta->xsk->umem->fq, 1);
            pthread_mutex_unlock(&fq_lock);
        } else {
            uint32_t idx_tx;
            if (xsk_ring_prod__reserve(&meta->xsk->tx, 1, &idx_tx) == 1) {
                xsk_ring_prod__tx_desc(&meta->xsk->tx, idx_tx)->addr = meta->addr;
                xsk_ring_prod__tx_desc(&meta->xsk->tx, idx_tx)->len = meta->len;
                xsk_ring_prod__submit(&meta->xsk->tx, 1);
                
                __sync_fetch_and_add(&meta->xsk->ring_stats.tx_npkts, 1); 
                __sync_fetch_and_add(&meta->xsk->outstanding_tx, 1);
                
                pthread_mutex_unlock(&fq_lock);
                if (opt_need_wakeup) sendto(xsk_socket__fd(meta->xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            } else {
                uint32_t idx_fq;
                while (xsk_ring_prod__reserve(&meta->xsk->umem->fq, 1, &idx_fq) != 1) {
                    pthread_mutex_unlock(&fq_lock); usleep(5); pthread_mutex_lock(&fq_lock);
                }
                *xsk_ring_prod__fill_addr(&meta->xsk->umem->fq, idx_fq) = meta->addr;
                xsk_ring_prod__submit(&meta->xsk->umem->fq, 1);
                pthread_mutex_unlock(&fq_lock);
            }
        }
        
        rte_mempool_put(meta_pool, meta);
    }
    return 0;
}

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    bool rx = true, tx = true; 
    pthread_t pt, jt;
    int i;
    void *bufs;
    
    int ret1 = rte_eal_init(argc, argv);
    if (ret1 < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret1; argv += ret1;

    meta_pool = rte_mempool_lookup("META_POOL");
    if (!meta_pool) meta_pool = rte_mempool_create("META_POOL", 65535, sizeof(struct pkt_info), 256, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (!meta_pool) rte_exit(EXIT_FAILURE, "Failed to initialize DPDK META_POOL\n");

    packet_ring = rte_ring_lookup("PACKET_RING");
    if (!packet_ring) packet_ring = rte_ring_create("PACKET_RING", 4096, rte_socket_id(), RING_F_SP_ENQ);
    if (!packet_ring) rte_exit(EXIT_FAILURE, "Failed to initialize DPDK PACKET_RING\n");

    parse_command_line(argc, argv);
    init_flow_table();
    init_ai_models("cnn_lstm.engine", "xgboost_nips.json");

    if (setrlimit(RLIMIT_MEMLOCK, &r)) exit(EXIT_FAILURE);

    xdp_prog = xdp_program__open_file("xdp_prog_kern2.o", "xdp", NULL);
    if (libxdp_get_error(xdp_prog)) exit(EXIT_FAILURE); 
    xdp_program__set_xdp_frags_support(xdp_prog, false);
    if (xdp_program__attach(xdp_prog, opt_ifindex, opt_attach_mode, 0)) {
        fprintf(stderr, "ERROR: Multiprog attach failed\n");
        exit(EXIT_FAILURE);}

    struct bpf_object *obj = xdp_program__bpf_obj(xdp_prog);
    suspicious_v4_fd = bpf_object__find_map_fd_by_name(obj, "ipv4_suspicious");
    suspicious_v6_fd = bpf_object__find_map_fd_by_name(obj, "ipv6_suspicious");
    rate_blacklist_v4_fd = bpf_object__find_map_fd_by_name(obj, "ipv4_rate_blacklist");
    rate_blacklist_v6_fd = bpf_object__find_map_fd_by_name(obj, "ipv6_rate_blacklist");

    size_t alloc_size = opt_num_xsks * NUM_FRAMES * opt_xsk_frame_size;
    bufs = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
    if (bufs == MAP_FAILED) exit(EXIT_FAILURE);

    num_socks = 0;
    for (i = 0; i < opt_num_xsks; i++) {
        void *socket_buf = (uint8_t *)bufs + (i * NUM_FRAMES * opt_xsk_frame_size);
        struct xsk_umem_info *umem = xsk_configure_umem(socket_buf, NUM_FRAMES * opt_xsk_frame_size);
        
        xsks[num_socks++] = xsk_configure_socket(umem, rx, tx, i); 
        
        if (rx) {
            xsk_populate_fill_ring(umem);
        }
    }

    for (i = 0; i < opt_num_xsks; i++) apply_setsockopt(xsks[i]);

    int xsks_map = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (xsks_map < 0) {
        fprintf(stderr, "ERROR: Failed to find xsks_map in kernel.\n");
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < num_socks; i++) {
        int fd = xsk_socket__fd(xsks[i]->xsk);
        int key = i; 
        if (bpf_map_update_elem(xsks_map, &key, &fd, 0)) {
            fprintf(stderr, "ERROR: Map update failed for queue %d\n", i);
        }
    }

    int hp_idx = if_nametoindex("honeypot");
    if (hp_idx > 0) {
        int hp_map = bpf_object__find_map_fd_by_name(obj, "honeypot_map");
        if (hp_map >= 0) {
            int hp_key = 0;
            bpf_map_update_elem(hp_map, &hp_key, &hp_idx, 0);
            printf("Dynamically mapped honeypot to ifindex %d\n", hp_idx);
        }
    } else {
        printf("WARNING: 'honeypot' interface not found. Suspicious flow redirection will fail.\n");
    }

    signal(SIGINT, int_exit); signal(SIGTERM, int_exit); signal(SIGABRT, int_exit);
    prev_time = get_nsecs(); start_time = prev_time;

    pthread_create(&pt, NULL, poller, NULL);
    pthread_create(&jt, NULL, janitor_thread_rate_removal, NULL);

    rte_eal_mp_remote_launch(worker_thread, NULL, SKIP_MAIN);
    rx_drop_all();

    benchmark_done = true;
    pthread_join(pt, NULL); pthread_join(jt, NULL);
    return 0;
}