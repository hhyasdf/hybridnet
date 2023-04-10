#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <lib/time.h>
#include <lib/endian.h>
#include <lib/dbg.h>
#include <linux/bpf.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

struct token_bucket {
    __u64 last_generate_tstamp;
    __u64 buckets;  // bytes
};

// This map format is 5.10 only
struct bpf_elf_map __section("maps") token_bucket_map = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(__u32),
        .size_value     = sizeof(struct token_bucket),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 1,
};

__section("police")
int classifier(struct __ctx_buff *skb)
{
        void *data_end = (void *)(unsigned long long)skb->data_end;
        struct token_bucket *tb;
        __u64 token_rate, token_bucket_capacity, generated_tokens, generate_period = NSEC_PER_MSEC * 10, now, rate = 62500000;    /* 500 Mbits/sec -> 62500000 bytes/sec */
        void *data = (void *)(unsigned long long)skb->data;
        struct ethhdr *eth = data;
        __u64 len = skb->len;
        int index = 0;
//        const char dbgMsg[] = "tb->buckets: %llu";

        now = bpf_ktime_get_nsec();

        if (data + sizeof(struct ethhdr) > data_end)
                return TC_ACT_OK;
        if (eth->h_proto != ___constant_swab16(ETH_P_IP))
                return TC_ACT_OK;
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                return TC_ACT_OK;

        // generate tokens per generate_period
        token_rate = rate * generate_period / NSEC_PER_SEC;
        token_bucket_capacity = 100 * token_rate;

        tb = map_lookup_elem(&token_bucket_map, &index);
        if (!tb)    /* unlikely */
                return TC_ACT_OK;

        if (!tb) {
                struct token_bucket init_token_bucket = {
                        .last_generate_tstamp = now,
                        .buckets = token_bucket_capacity,
                };
                map_update_elem(&token_bucket_map, &index, &init_token_bucket, BPF_ANY);
        } else if (now - tb->last_generate_tstamp > generate_period) {
                generated_tokens = token_rate * (now - tb->last_generate_tstamp) / generate_period;
                if (tb->buckets + generated_tokens > token_bucket_capacity) {
                        WRITE_ONCE(tb->buckets, token_bucket_capacity);
                } else {
                        WRITE_ONCE(tb->buckets, tb->buckets + generated_tokens);
                }
                WRITE_ONCE(tb->last_generate_tstamp, now);
        }

        if (tb->buckets < len) {
//                trace_printk(dbgMsg, sizeof(dbgMsg), tb->buckets);
                return TC_ACT_SHOT;
        }

        WRITE_ONCE(tb->buckets, tb->buckets - len);

//        trace_printk(dbgMsg, sizeof(dbgMsg), tb->buckets);
//        trace_printk(dbgMsg, sizeof(dbgMsg), tb->last_generate_tstamp);

        return TC_ACT_OK;
}


BPF_LICENSE("Dual BSD/GPL");
