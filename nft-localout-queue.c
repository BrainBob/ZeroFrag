// SPDX-License-Identifier: GPL-2.0
/* Audit-only: install an IPv4 LOCAL_OUT nftables base chain that queues all
 * packets to NFQUEUE 0.  Intended only for the isolated skb audit guest.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSZ 16384

static unsigned int seq;

static struct nlmsghdr *nft_hdr(void *buf, uint16_t type, uint8_t family,
				unsigned int flags)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct nfgenmsg *nfg;

	nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | type;
	nlh->nlmsg_flags = NLM_F_REQUEST | flags;
	nlh->nlmsg_seq = ++seq;
	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;
	return nlh;
}

static void batch_marker(struct mnl_nlmsg_batch *batch, uint16_t type)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	struct nfgenmsg *nfg;

	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = ++seq;
	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(NFNL_SUBSYS_NFTABLES);
	mnl_nlmsg_batch_next(batch);
}

int main(void)
{
	char buf[BUFSZ], rbuf[BUFSZ];
	struct mnl_nlmsg_batch *batch;
	struct mnl_socket *nl;
	struct nlattr *list, *elem, *data, *hook;
	struct nlmsghdr *nlh;
	unsigned int portid;
	int ret, acks = 0;

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (!nl) {
		perror("mnl_socket_open");
		return 1;
	}
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return 1;
	}
	portid = mnl_socket_get_portid(nl);
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
	batch_marker(batch, NFNL_MSG_BATCH_BEGIN);

	nlh = nft_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWTABLE,
		      NFPROTO_IPV4, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	mnl_attr_put_strz(nlh, NFTA_TABLE_NAME, "skbaudit");
	mnl_nlmsg_batch_next(batch);

	nlh = nft_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWCHAIN,
		      NFPROTO_IPV4, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	mnl_attr_put_strz(nlh, NFTA_CHAIN_TABLE, "skbaudit");
	mnl_attr_put_strz(nlh, NFTA_CHAIN_NAME, "outq");
	mnl_attr_put_strz(nlh, NFTA_CHAIN_TYPE, "filter");
	hook = mnl_attr_nest_start(nlh, NFTA_CHAIN_HOOK);
	mnl_attr_put_u32(nlh, NFTA_HOOK_HOOKNUM, htonl(NF_INET_LOCAL_OUT));
	mnl_attr_put_u32(nlh, NFTA_HOOK_PRIORITY, htonl(0));
	mnl_attr_nest_end(nlh, hook);
	mnl_nlmsg_batch_next(batch);

	nlh = nft_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWRULE,
		      NFPROTO_IPV4, NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK);
	mnl_attr_put_strz(nlh, NFTA_RULE_TABLE, "skbaudit");
	mnl_attr_put_strz(nlh, NFTA_RULE_CHAIN, "outq");
	list = mnl_attr_nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	elem = mnl_attr_nest_start(nlh, NFTA_LIST_ELEM);
	mnl_attr_put_strz(nlh, NFTA_EXPR_NAME, "queue");
	data = mnl_attr_nest_start(nlh, NFTA_EXPR_DATA);
	mnl_attr_put_u16(nlh, NFTA_QUEUE_NUM, htons(0));
	mnl_attr_nest_end(nlh, data);
	mnl_attr_nest_end(nlh, elem);
	mnl_attr_nest_end(nlh, list);
	mnl_nlmsg_batch_next(batch);

	batch_marker(batch, NFNL_MSG_BATCH_END);
	ret = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
				mnl_nlmsg_batch_size(batch));
	mnl_nlmsg_batch_stop(batch);
	if (ret < 0) {
		perror("mnl_socket_sendto");
		return 1;
	}

	while (acks < 3 && (ret = mnl_socket_recvfrom(nl, rbuf, sizeof(rbuf))) > 0) {
		ret = mnl_cb_run(rbuf, ret, 0, portid, NULL, NULL);
		if (ret < 0) {
			perror("nft batch acknowledgement");
			return 1;
		}
		acks++;
	}
	if (acks < 3) {
		fprintf(stderr, "received only %d nft acknowledgements: %s\n",
			acks, strerror(errno));
		return 1;
	}
	printf("NFT_QUEUE_SETUP table=skbaudit chain=outq hook=LOCAL_OUT queue=0 acks=%d\n",
	       acks);
	mnl_socket_close(nl);
	return 0;
}
