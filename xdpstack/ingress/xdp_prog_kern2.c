#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define THRESHHOLD 20
#define PERIOD 300000000000

struct rate {
    __u64 count;
    __u64 last_time_stamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} honeypot_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);        
    __type(value, struct rate);     
    __uint(max_entries, 10000);
} ipv4_suspicious SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);      
    __type(value, struct rate);   
    __uint(max_entries, 10000);
} ipv6_suspicious SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);         
    __type(value, struct rate);      
    __uint(max_entries, 10000);
} ipv4_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);         
    __type(value, struct rate);     
    __uint(max_entries, 10000);
} ipv6_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10000);
} ipv4_rate_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, __u64);
    __uint(max_entries, 10000);
} ipv6_rate_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rate);
    __uint(max_entries, 10000);
} ipv4_rate_limiter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, struct rate);
    __uint(max_entries, 10000);
} ipv6_rate_limiter SEC(".maps");

static __always_inline int is_ipv4_suspicious(struct iphdr *iphdr, void *data_end) {
    if ((void*)(iphdr + 1) > data_end) return 0;
    struct rate *map_val = bpf_map_lookup_elem(&ipv4_suspicious, &iphdr->saddr);
    return map_val ? 1 : 0;
}

static __always_inline int is_ipv6_suspicious(struct ipv6hdr *ipv6, void *data_end) {
    if ((void*)(ipv6 + 1) > data_end) return 0;
    struct rate *map_val = bpf_map_lookup_elem(&ipv6_suspicious, &ipv6->saddr);
    return map_val ? 1 : 0;
}

static __always_inline int is_ipv4_blacklisted(struct iphdr *iphdr, void *data_end) {
    if ((void*)(iphdr + 1) > data_end) return 0;
    struct rate *map_val = bpf_map_lookup_elem(&ipv4_blacklist, &iphdr->saddr);
    return map_val ? 1 : 0;
}

static __always_inline int is_ipv6_blacklisted(struct ipv6hdr *ipv6, void *data_end) {
    if ((void*)(ipv6 + 1) > data_end) return 0;
    struct rate *map_val = bpf_map_lookup_elem(&ipv6_blacklist, &ipv6->saddr);
    return map_val ? 1 : 0;
}

static __always_inline int ipv4_rate_blacklist_check(struct iphdr *iphdr) {
    __u64 *timestamp = bpf_map_lookup_elem(&ipv4_rate_blacklist, &iphdr->saddr);
    return timestamp ? 1 : 0;
}

static __always_inline int ipv6_rate_blacklist_check(struct ipv6hdr *ipv6) {
    __u64 *timestamp = bpf_map_lookup_elem(&ipv6_rate_blacklist, &ipv6->saddr);
    return timestamp ? 1 : 0;
}

static __always_inline void update_add_ipv4_rate_blacklist(struct iphdr *iphdr) {
    __u64 time_stamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&ipv4_rate_blacklist, &iphdr->saddr, &time_stamp, BPF_ANY);
}

static __always_inline void update_add_ipv6_rate_blacklist(struct ipv6hdr *ipv6) {
    __u64 time_stamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&ipv6_rate_blacklist, &ipv6->saddr, &time_stamp, BPF_ANY);
}

static __always_inline void update_add_ipv4_rate(struct iphdr *iphdr) {
    struct rate *map_val = bpf_map_lookup_elem(&ipv4_rate_limiter, &iphdr->saddr);
    if (map_val) {
        __sync_fetch_and_add(&map_val->count, 1);
        if (map_val->count == 20)
            map_val->last_time_stamp = bpf_ktime_get_ns(); 
    } else {
        struct rate new_val = {.count = 1, .last_time_stamp = bpf_ktime_get_ns()};
        bpf_map_update_elem(&ipv4_rate_limiter, &iphdr->saddr, &new_val, BPF_NOEXIST);
    }
}

static __always_inline void update_add_ipv6_rate(struct ipv6hdr *ipv6) {
    struct rate *map_val = bpf_map_lookup_elem(&ipv6_rate_limiter, &ipv6->saddr);
    if (map_val) {
        __sync_fetch_and_add(&map_val->count, 1);
        if (map_val->count == 20)
            map_val->last_time_stamp = bpf_ktime_get_ns(); 
    } else {
        struct rate new_val = {.count = 1, .last_time_stamp = bpf_ktime_get_ns()};
        bpf_map_update_elem(&ipv6_rate_limiter, &ipv6->saddr, &new_val, BPF_NOEXIST);
    }
}

static __always_inline int ipv4_rate_check(struct iphdr *iphdr) {
    struct rate *map_val = bpf_map_lookup_elem(&ipv4_rate_limiter, &iphdr->saddr);
    if (!map_val) return 0;
    __u64 now = bpf_ktime_get_ns();
    if (now - map_val->last_time_stamp <= (__u64)PERIOD) {
        return (map_val->count >= (__u64)THRESHHOLD);
    }
    __sync_lock_test_and_set(&map_val->count, 0);
    map_val->last_time_stamp = now;
    return 0;
}

static __always_inline int ipv6_rate_check(struct ipv6hdr *ipv6) {
    struct rate *map_val = bpf_map_lookup_elem(&ipv6_rate_limiter, &ipv6->saddr);
    if (!map_val) return 0;
    __u64 now = bpf_ktime_get_ns();
    if (now - map_val->last_time_stamp <= (__u64)PERIOD) {
        return (map_val->count >= (__u64)THRESHHOLD);
    }
    __sync_lock_test_and_set(&map_val->count, 0);
    map_val->last_time_stamp = now;
    return 0;
}

static __always_inline void swap_src_dst_mac(void *data)
{
    struct ethhdr *eth = data;
    __u8 tmp[ETH_ALEN];
    memcpy(tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp, ETH_ALEN);
}

SEC("xdp")
int xdp_firewall_engine(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = {.pos = data};
    struct ethhdr *eth;
    int eth_type, ip_type;
    __u32 action = XDP_PASS;
    
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6;
    int blacklist_check, suspicious_check, rate_blacklist_check, rate_list_check;

    __u32 q_index = ctx->rx_queue_index;    
    eth_type = parse_ethhdr(&nh, data_end, &eth);

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (!iphdr) return XDP_ABORTED;
        if ((void*)(iphdr + 1) > data_end) return XDP_ABORTED;
        
        blacklist_check = is_ipv4_blacklisted(iphdr, data_end);
        suspicious_check = is_ipv4_suspicious(iphdr, data_end);
        
        if (blacklist_check) {
            action = XDP_DROP;
            goto out;
        }
        
        if (suspicious_check) {
            if (data + sizeof(struct ethhdr) > data_end) {
                return XDP_ABORTED;
            }
            swap_src_dst_mac(data);
            __u8 honeypot_mac[ETH_ALEN] = {0x3a, 0x15, 0xf4, 0x67, 0xa5, 0xbc};
            memcpy(eth->h_dest, honeypot_mac, ETH_ALEN);
            
            int hp_key = 0;
            action = bpf_redirect_map(&honeypot_map, hp_key, 0);
            goto out;
        } 
        
        if (ip_type == IPPROTO_ICMP) {
            rate_blacklist_check = ipv4_rate_blacklist_check(iphdr);
            if (rate_blacklist_check) {
                action = XDP_DROP;
                goto out;
            } else {
                rate_list_check = ipv4_rate_check(iphdr);
                if (rate_list_check) {
                    update_add_ipv4_rate_blacklist(iphdr);
                    action = XDP_DROP; 
                    goto out;
                } else {
                    update_add_ipv4_rate(iphdr);
                    action = XDP_PASS; 
                    goto out;
                }
            }
        } 
        else if (ip_type == IPPROTO_UDP || ip_type == IPPROTO_TCP) {
            action = bpf_redirect_map(&xsks_map, q_index, 0); 
            goto out;
        } else {
            action = XDP_PASS;
            goto out;
        }
    } 
    else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ipv6);
        if (!ipv6) return XDP_ABORTED;
        if ((void*)(ipv6 + 1) > data_end) return XDP_ABORTED;

        if (is_ipv6_blacklisted(ipv6, data_end)) {
            action = XDP_DROP;
            goto out;
        }

        if (is_ipv6_suspicious(ipv6, data_end)) {
            if (data + sizeof(struct ethhdr) > data_end) {
                return XDP_ABORTED;
            }
            swap_src_dst_mac(data);
            __u8 honeypot_mac[ETH_ALEN] = {0x3a, 0x15, 0xf4, 0x67, 0xa5, 0xbc};
            memcpy(eth->h_dest, honeypot_mac, ETH_ALEN);
            
            int hp_key = 0;
            action = bpf_redirect_map(&honeypot_map, hp_key, 0);
            goto out;
        }

        if (ip_type == IPPROTO_ICMPV6) {
            if (ipv6_rate_blacklist_check(ipv6)) {
                action = XDP_DROP;
                goto out;
            } else if (ipv6_rate_check(ipv6)) {
                update_add_ipv6_rate_blacklist(ipv6);
                action = XDP_DROP;
                goto out;
            } else {
                update_add_ipv6_rate(ipv6);
                action = XDP_PASS;
                goto out;
            }
        } 
        else if (ip_type == IPPROTO_UDP || ip_type == IPPROTO_TCP) {
            action = bpf_redirect_map(&xsks_map, q_index, 0); 
            goto out;
        } else {
            action = XDP_PASS;
            goto out;
        }
    } else {
        action = XDP_PASS;
        goto out;
    }

out:
    return xdp_stats_record_action(ctx, action);
}
char _license[] SEC("license") = "GPL";