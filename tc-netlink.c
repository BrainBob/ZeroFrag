// SPDX-License-Identifier: GPL-2.0
/*
 * Behavior-faithful reconstruction of tc-netlink.c.
 * Provenance: ELF 0x40a320..0x40ae42.  The original was compiled twice for
 * 22-key/88-byte and 24-key/96-byte frames; this source shares one core.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_pedit.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "unified.h"

#define TC_BUFSZ 16384
#define MAX_PEDIT_KEYS 24

static unsigned int tc_seq;

static int send_ack(struct mnl_socket *nl, struct nlmsghdr *nlh,
                    unsigned int portid)
{
    char buf[TC_BUFSZ];
    int ret;

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
        return -1;
    do {
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (ret < 0)
            return -1;
        ret = mnl_cb_run(buf, ret, nlh->nlmsg_seq, portid, NULL, NULL);
    } while (ret > 0);
    return ret == MNL_CB_STOP ? 0 : -1;
}

static int add_clsact(struct mnl_socket *nl, unsigned int portid,
                      unsigned int ifindex)
{
    char buf[TC_BUFSZ] = {0};
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    struct tcmsg *tcm;

    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_seq = ++tc_seq;
    tcm = mnl_nlmsg_put_extra_header(nlh, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = (int)ifindex;
    tcm->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    tcm->tcm_parent = TC_H_CLSACT;
    mnl_attr_put_strz(nlh, TCA_KIND, "clsact");
    return send_ack(nl, nlh, portid);
}

struct pedit_options {
    struct tc_pedit_sel selector;
    struct tc_pedit_key keys[MAX_PEDIT_KEYS];
};

static int add_filter(struct mnl_socket *nl, unsigned int portid,
                      unsigned int source_ifindex,
                      unsigned int destination_ifindex,
                      const uint8_t *frame, size_t key_count)
{
    char buf[TC_BUFSZ] = {0};
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    struct tcmsg *tcm;
    struct nlattr *options, *actions, *action, *action_options;
    struct tc_u32_sel selector = {0};
    struct pedit_options pedit = {0};
    struct tc_mirred mirred = {0};
    size_t i;

    nlh->nlmsg_type = RTM_NEWTFILTER;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_seq = ++tc_seq;
    tcm = mnl_nlmsg_put_extra_header(nlh, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = (int)source_ifindex;
    tcm->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    tcm->tcm_info = TC_H_MAKE(1U << 16, htons(ETH_P_ALL));

    selector.flags = TC_U32_TERMINAL;
    selector.nkeys = 1;
    mnl_attr_put_strz(nlh, TCA_KIND, "u32");
    options = mnl_attr_nest_start(nlh, TCA_OPTIONS);
    mnl_attr_put(nlh, TCA_U32_SEL, sizeof(selector), &selector);
    actions = mnl_attr_nest_start(nlh, TCA_U32_ACT);

    action = mnl_attr_nest_start(nlh, 1);
    pedit.selector.action = TC_ACT_PIPE;
    pedit.selector.nkeys = (unsigned char)key_count;
    for (i = 0; i < key_count; i++) {
        uint32_t value;

        memcpy(&value, frame + i * sizeof(value), sizeof(value));
        pedit.keys[i].mask = 0;
        pedit.keys[i].val = value;
        pedit.keys[i].off = (uint32_t)(i * sizeof(value));
    }
    mnl_attr_put_strz(nlh, TCA_ACT_KIND, "pedit");
    action_options = mnl_attr_nest_start(nlh, TCA_ACT_OPTIONS);
    mnl_attr_put(nlh, TCA_PEDIT_PARMS,
                 sizeof(pedit.selector) + key_count * sizeof(pedit.keys[0]),
                 &pedit);
    mnl_attr_nest_end(nlh, action_options);
    mnl_attr_nest_end(nlh, action);

    action = mnl_attr_nest_start(nlh, 2);
    mirred.action = TC_ACT_STOLEN;
    mirred.eaction = TCA_EGRESS_REDIR;
    mirred.ifindex = (int)destination_ifindex;
    mnl_attr_put_strz(nlh, TCA_ACT_KIND, "mirred");
    action_options = mnl_attr_nest_start(nlh, TCA_ACT_OPTIONS);
    mnl_attr_put(nlh, TCA_MIRRED_PARMS, sizeof(mirred), &mirred);
    mnl_attr_nest_end(nlh, action_options);
    mnl_attr_nest_end(nlh, action);

    mnl_attr_nest_end(nlh, actions);
    mnl_attr_nest_end(nlh, options);
    return send_ack(nl, nlh, portid);
}

static int tc_netlink_setup(const uint8_t *frame, size_t length)
{
    struct mnl_socket *nl;
    unsigned int nlmon_index, loopback_index, portid;
    size_t key_count;
    int saved_errno, rc = -1;

    if (!frame || (length != 88 && length != 96)) {
        errno = EINVAL;
        return -1;
    }
    key_count = length / sizeof(uint32_t);
    nlmon_index = if_nametoindex("nlmon0");
    loopback_index = if_nametoindex("lo");
    if (!nlmon_index || !loopback_index)
        return -1;
    nl = mnl_socket_open(NETLINK_ROUTE);
    if (!nl)
        return -1;
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
        goto out;
    portid = mnl_socket_get_portid(nl);
    if (add_clsact(nl, portid, nlmon_index) < 0) {
        fprintf(stderr, "TC_NETLINK_SETUP stage=clsact status=FAIL errno=%d error=%s\n",
                errno, strerror(errno));
        goto out;
    }
    if (add_filter(nl, portid, nlmon_index, loopback_index,
                   frame, key_count) < 0) {
        fprintf(stderr, "TC_NETLINK_SETUP stage=filter status=FAIL errno=%d error=%s\n",
                errno, strerror(errno));
        goto out;
    }
    printf("TC_NETLINK_SETUP device=nlmon0 hook=egress classifier=u32 "
           "pedit_keys=%zu redirect=lo status=PASS\n", key_count);
    rc = 0;
out:
    saved_errno = errno;
    mnl_socket_close(nl);
    errno = saved_errno;
    return rc;
}

int tc_netlink_setup_88(const uint8_t *frame, size_t length)
{
    if (length != 88) {
        errno = EINVAL;
        return -1;
    }
    return tc_netlink_setup(frame, length);
}

int tc_netlink_setup_96(const uint8_t *frame, size_t length)
{
    if (length != 96) {
        errno = EINVAL;
        return -1;
    }
    return tc_netlink_setup(frame, length);
}
