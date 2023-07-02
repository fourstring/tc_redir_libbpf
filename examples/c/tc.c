// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tc.skel.h"

#define LO_IFINDEX 1
#define ETH_IFINDEX 2
__u32 veth_ifindex[2];
char veth_ip_char[2][15];
in_addr_t veth_ip[2];

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

struct bpf_redirect_hook {
	struct bpf_tc_hook hook;
	struct bpf_tc_opts prog_opts;
	int hook_created;
	int prog_attached;
};

static struct bpf_redirect_hook *new_bpf_redirect_hook(int ifindex, int prog_fd)
{
	struct bpf_redirect_hook *this = malloc(sizeof(*this));

	if (!this) {
		return NULL;
	}

	memset(&this->hook, 0, sizeof(this->hook));
	memset(&this->prog_opts, 0, sizeof(this->prog_opts));

	this->hook_created = false;
	this->prog_attached = false;

	this->hook.ifindex = ifindex;
	this->hook.attach_point = BPF_TC_INGRESS;
	this->hook.sz = sizeof(this->hook);
	
	this->prog_opts.handle = 1;
	this->prog_opts.priority = 1;
	this->prog_opts.prog_fd = prog_fd;
	this->prog_opts.sz = sizeof(this->prog_opts);
	return this;
}

static int bpf_redirect_hook_attach(struct bpf_redirect_hook *this)
{
	int ret;

	ret = bpf_tc_hook_create(&this->hook);
	if (!ret) {
		this->hook_created = true;
	} else if (ret != -EEXIST) {
		/* The hook (i.e. qdisc) may already exists because:
		*   1. it is created by other processes or users
		*   2. or since we are attaching to the TC ingress ONLY,
		*      bpf_tc_hook_destroy does NOT really remove the qdisc,
		*      there may be an egress filter on the qdisc
		*/
		fprintf(stderr, "Failed to create TC hook on if %d: ret=%d\n", this->hook.ifindex, ret);
		return ret;
	}

	ret = bpf_tc_attach(&this->hook, &this->prog_opts);
	if (ret) {
		fprintf(stderr, "Failed to attach TC to if %d: ret=%d\n", this->hook.ifindex, ret);
		return ret;
	}
	this->prog_attached = true;

	return 0;
}

static int bpf_redirect_hook_destroy(struct bpf_redirect_hook *this)
{
	int ret;

	if (this->prog_attached) {
		this->prog_opts.prog_fd = 0;
		this->prog_opts.prog_id = 0;
		this->prog_opts.flags = 0;

		ret = bpf_tc_detach(&this->hook, &this->prog_opts);
		if (ret) {
			fprintf(stderr, "Failed to detach prog on if %d: ret=%d\n", this->hook.ifindex, ret);
		}
	}

	if (this->hook_created) {
		ret = bpf_tc_hook_destroy(&this->hook);
		if (ret) {
			fprintf(stderr, "Failed to destroy TC hook on if %d: ret=%d\n", this->hook.ifindex, ret);
		}
	}

	return ret;
}

static struct bpf_redirect_hook *hooks[3];
#define HOOKS_NUM (sizeof(hooks)/sizeof(struct bpf_redirect_hook *))

static void init_hooks(int prog_fd)
{
	hooks[0] = new_bpf_redirect_hook(veth_ifindex[0], prog_fd);
	hooks[1] = new_bpf_redirect_hook(veth_ifindex[1], prog_fd);

	assert(hooks[0]);
	assert(hooks[1]);
}

static void init_hooks_eth(int prog_fd)
{
	hooks[2] = new_bpf_redirect_hook(ETH_IFINDEX, prog_fd);

	assert(hooks[2]);
}

int main(int argc, char **argv)
{
	struct tc_bpf *skel;
	int err, i;

	libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}


	fprintf(stdout, "please input veth1_ip and veth1_ifindex.\n");
	scanf("%s%u", &veth_ip_char[0][0], &veth_ifindex[0]);
	fprintf(stdout, "please input veth2_ip and veth2_ifindex.\n");
	scanf("%s%u", &veth_ip_char[1][0], &veth_ifindex[1]);
	// printf("ip: %s, ifindex: %u\t", veth_ip_char[0], veth_ifindex[0]);
	// printf("ip: %s, ifindex: %u\t", veth_ip_char[1], veth_ifindex[1]);
	for (int i = 0; i < 2; ++i) {
		veth_ip[i] = inet_addr(veth_ip_char[i]);
		err = bpf_map__update_elem(skel->maps.netns_route_map, &veth_ip[i], sizeof(__u32), &veth_ifindex[i], sizeof(__u32), BPF_ANY);
		if (err) {
			goto cleanup;
		}
	}

	init_hooks(bpf_program__fd(skel->progs.redirect_ingress));
	init_hooks_eth(bpf_program__fd(skel->progs.redirect_ingress_eth));

	for (i = 0; i < HOOKS_NUM; i++) {
		err = bpf_redirect_hook_attach(hooks[i]);
		if (err) {
			goto cleanup;
		}
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	for (i = 0; i < HOOKS_NUM; i++) {
		bpf_redirect_hook_destroy(hooks[i]);
	}
	tc_bpf__destroy(skel);
	return -err;
}
