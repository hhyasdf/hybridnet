#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <lib/time.h>
#include <lib/endian.h>
#include <linux/bpf.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/if_ether.h>


// This map format is 5.10 only.
struct bpf_elf_map __section("maps") tstamp_map = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(__u32),
        .size_value     = sizeof(__u64),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 1,
};

__section("edt")
int classifier(struct __ctx_buff *skb)
{
        void *data_end = (void *)(unsigned long long)skb->data_end;
        __u64 *tstamp, delay_ns, now, rate = 62500000;    /* 500 Mbits/sec */
        void *data = (void *)(unsigned long long)skb->data;
        struct ethhdr *eth = data;
        __u64 len = skb->len;
        int index = 0;

        now = bpf_ktime_get_nsec();

        if (data + sizeof(struct ethhdr) > data_end)
                return TC_ACT_OK;
        if (eth->h_proto != ___constant_swab16(ETH_P_IP))
                return TC_ACT_OK;
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                return TC_ACT_OK;

        delay_ns = len * NSEC_PER_SEC / (rate);


        tstamp = map_lookup_elem(&tstamp_map, &index);
        if (!tstamp)    /* unlikely */
                return TC_ACT_OK;

        if (*tstamp < now) {
                *tstamp = now + delay_ns;
                skb->tstamp = now;
                return TC_ACT_OK;
        }

        skb->tstamp = *tstamp;
        __sync_fetch_and_add(tstamp, delay_ns);

        return TC_ACT_OK;
}


BPF_LICENSE("Dual BSD/GPL");
