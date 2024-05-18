/*
 *
 * kretprobe to trace nf_tables skb processing
 * The objective is to find where a packet gets dropped
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#include <net/ip.h>
#include <net/netfilter/nf_tables.h>	/* nft_do_chains() and struct nft_pktinfo */

#define NAME_LEN 50

static char func_name[NAME_LEN] = "nft_do_chain";

/* Per-instance private data struct */
struct steph {
	struct nft_pktinfo *pkt;
};

/*
 * Grabbing the registers/arguments before we move on into the function
 */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct steph *data;

	data = (struct steph *)ri->data;

	data->pkt = (struct nft_pktinfo *) regs_get_kernel_argument(regs, 0);
	if (IS_ERR_OR_NULL(data->pkt)) {
		pr_err("%s found NULL nft_pktinfo pointer", func_name);
		return 1;
	}

	return 0;
}

/*
 * The packet and nft verdict inspection
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned int verdict;
	struct steph *data;
	struct sk_buff *skb;
	const struct nf_hook_state *state;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u32 saddr, daddr;
	__u16 src, dst;
	unsigned int proto;
	const char *devin, *devout;
	int devidxin, devidxout;

	verdict = regs_return_value(regs) & NF_VERDICT_MASK;

	/* We don't care about accepted packets so exit quickly */
	if (verdict == NF_ACCEPT)
		return 0;

	/* Initialize the devices & indexes */
	devin = NULL;
	devidxin = 0;
	devout = NULL;
	devidxout = 0;

	data = (struct steph *)ri->data;
	if (!data) {
		pr_err("%s: NULL private data", __func__);
		return 1;
	}

	if (!data->pkt) {
		pr_err("%s: NULL private data->pkt", __func__);
		return 1;
	}

	skb = (struct sk_buff *)data->pkt->skb;
	if (!skb) {
		pr_err("%s: NULL struct sk_buff", __func__);
		return 1;
	}

	iph = ip_hdr(skb);
	if (!iph) {
		pr_err("%s: failed to find the iphdr structure", __func__);
		return 1;
	}

	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);

	switch(iph->protocol) {
		case IPPROTO_TCP:
		       	tcph = tcp_hdr(skb);

			if (!tcph) {
				pr_err("%s: failed to find the tcphdr structure", __func__);
				return 1;
			}

			proto = 0x000000ff & IPPROTO_TCP;
			src = ntohs(tcph->source);
			dst = ntohs(tcph->dest);

			break;
		case IPPROTO_UDP:
			udph = udp_hdr(skb);

			if (!udph) {
				pr_err("%s: failed to find the udph structure", __func__);
				return 1;
			}

			proto = 0x000000ff & IPPROTO_UDP;
			src = ntohs(udph->source);
			dst = ntohs(udph->dest);

			break;
		default:
			pr_warn("%s: unsupported L4 protocol; only TCP and UDP are supported", func_name);
			return 0;
	}

	state = data->pkt->state;
	if (state) {
		if (state->in) {
			devin = state->in->name;
			devidxin = state->in->ifindex;
		}

		if (state->out) {
			devout = state->out->name;
			devidxout = state->out->ifindex;
		}
	}

	pr_info("%s - devin=%s/%d, devout=%s/%d, saddr=0x%x, daddr=0x%x, proto=%d, "
		"spt=0x%x, dpt=0x%x, verdict=0x%x\n", func_name, devin,
					devidxin, devout, devidxout, saddr, daddr,
					proto, src, dst, verdict);

	return 0;
}

static struct kretprobe my_kretprobe = {
	.entry_handler		= entry_handler,
	.handler		= ret_handler,
	/* Necessary for the proper kzalloc() size to include data[] */
	.data_size		= sizeof(struct steph),
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
};

static int __init kretprobe_init(void)
{
	int ret;

	my_kretprobe.kp.symbol_name = func_name;

	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return -2;
	}
	pr_info("Planted return probe at %s: 0x%lx\n",
			my_kretprobe.kp.symbol_name, (unsigned long) my_kretprobe.kp.addr);
	return 0;
}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&my_kretprobe);
	pr_info("kretprobe at 0x%lx unregistered\n", (unsigned long) my_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	pr_info("Missed probing %d instances of %s\n",
		my_kretprobe.nmissed, my_kretprobe.kp.symbol_name);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
