/*
 * Re:Kernel v10.0 - Integrate version
 * Based on Re-Kernel LKM-Source, adapted for in-tree compilation.
 *
 * Uses direct function calls from binder.c/signal.c (no vendor hooks).
 * Lazy init via start_rekernel() on first event.
 * Raw netlink transport for userspace communication.
 */
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/pid.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/netlink.h>
#include <net/rtnetlink.h>

#include <linux/tcp.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include <linux/signal.h>
#include <uapi/linux/android/binder.h>
#include "rekernel.h"

/* ---- netlink transport ---- */

static struct sock *netlink_socket;
extern struct net init_net;
static unsigned long netlink_unit;
#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry;
#endif

static int rekernel_send_msg(char *packet_buffer, uint16_t len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	skb = nlmsg_new(len, GFP_ATOMIC);
	if (!skb) {
		pr_err("Re:Kernel: netlink alloc failure\n");
		return LINE_ERROR;
	}

	nlh = nlmsg_put(skb, 0, 0, netlink_unit, len, 0);
	if (!nlh) {
		pr_err("Re:Kernel: nlmsg_put failure\n");
		nlmsg_free(skb);
		return LINE_ERROR;
	}

	memcpy(nlmsg_data(nlh), packet_buffer, len);
	return netlink_unicast(netlink_socket, skb, USER_PORT, MSG_DONTWAIT);
}

static void netlink_rcv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct rekernel_cmd {
		int type;
	} *cmd;
	struct rekernel_monitor_net_args {
		int uid;
	} *margs;
	struct rekernel_kill_net_args {
		int pid;
	} *kargs;

	if (skb->len < nlmsg_total_size(sizeof(*cmd)))
		return;

	nlh = nlmsg_hdr(skb);
	cmd = NLMSG_DATA(nlh);

	switch (cmd->type) {
	case 1: /* REMOVE_PROC */
#ifdef CONFIG_PROC_FS
		if (rekernel_unit_entry) {
			proc_remove(rekernel_unit_entry);
			rekernel_unit_entry = NULL;
		}
		if (rekernel_dir) {
			proc_remove(rekernel_dir);
			rekernel_dir = NULL;
		}
#endif
		break;
	case 2: /* ADD_MONITOR_NET */
	case 3: /* DEL_MONITOR_NET */
		if (nlmsg_len(nlh) < sizeof(*cmd) + sizeof(*margs))
			break;
		margs = (void *)cmd + sizeof(*cmd);
		if (cmd->type == 3)
			net_uid_del(margs->uid);
		else
			net_uid_add(margs->uid);
		break;
	case 4: /* KILL_NET */
		if (nlmsg_len(nlh) < sizeof(*cmd) + sizeof(*kargs))
			break;
		kargs = (void *)cmd + sizeof(*cmd);
		rekernel_kill_net_connections(kargs->pid);
		break;
	default:
		break;
	}
}

static struct netlink_kernel_cfg rekernel_nl_cfg = {
	.input = netlink_rcv_msg,
};

#ifdef CONFIG_PROC_FS
static int rekernel_unit_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", netlink_unit);
	return 0;
}

static int rekernel_unit_open(struct inode *inode, struct file *file)
{
	return single_open(file, rekernel_unit_show, NULL);
}

static const struct proc_ops rekernel_unit_fops = {
	.proc_open = rekernel_unit_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#endif /* CONFIG_PROC_FS */

/* ---- network monitoring (RCU hashmap) ---- */

#ifdef CONFIG_REKERNEL_NETWORK
#define REKERNEL_NET_UID_HASH_BITS 6
static DEFINE_HASHTABLE(rekernel_net_uid_map, REKERNEL_NET_UID_HASH_BITS);

struct uid_info {
	uid_t uid;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_MUTEX(rekernel_net_uid_mutex);

static bool net_uid_monitored(uid_t uid)
{
	struct uid_info *entry;

	hash_for_each_possible_rcu(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid)
			return true;
	}
	return false;
}

void net_uid_add(uid_t uid)
{
	mutex_lock(&rekernel_net_uid_mutex);
	if (!net_uid_monitored(uid)) {
		struct uid_info *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (entry) {
			entry->uid = uid;
			hash_add_rcu(rekernel_net_uid_map, &entry->hnode, uid);
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}

void net_uid_del(uid_t uid)
{
	struct uid_info *entry;

	mutex_lock(&rekernel_net_uid_mutex);
	hash_for_each_possible(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->hnode);
			kfree_rcu(entry, rcu);
			break;
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}

static inline uid_t sock2uid(struct sock *sk)
{
	if (sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;
	return 0;
}

static unsigned int rekernel_nf_hook(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	struct sock *sk;
	unsigned int thoff = 0;
	unsigned short frag_off = 0;
	uid_t uid;
	struct tcphdr *th;
	int data_len = 0;
	bool monitored;

	if (!skb || !skb->len || !state)
		return NF_ACCEPT;

	if (state->hook != NF_INET_LOCAL_IN)
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (!sk || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = sock2uid(sk);
	if (uid < MIN_USERAPP_UID)
		return NF_ACCEPT;

	rcu_read_lock();
	monitored = net_uid_monitored(uid);
	rcu_read_unlock();
	if (!monitored)
		return NF_ACCEPT;

	if (ip_hdr(skb)->version == 4) {
		struct iphdr *iph4;

		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return NF_ACCEPT;
		iph4 = ip_hdr(skb);
		if (iph4->protocol != IPPROTO_TCP)
			return NF_ACCEPT;
		if (!pskb_may_pull(skb, (iph4->ihl << 2) + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		iph4 = ip_hdr(skb);
		th = (struct tcphdr *)((unsigned char *)iph4 + (iph4->ihl << 2));
		data_len = ntohs(iph4->tot_len) - (iph4->ihl << 2) - (th->doff << 2);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (ip_hdr(skb)->version == 6) {
		struct ipv6hdr *iph6;

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return NF_ACCEPT;
		if (ipv6_find_hdr(skb, &thoff, -1, &frag_off, NULL) != IPPROTO_TCP)
			return NF_ACCEPT;
		if (!pskb_may_pull(skb, thoff + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		iph6 = ipv6_hdr(skb);
		th = (struct tcphdr *)(skb_network_header(skb) + thoff);
		data_len = ntohs(iph6->payload_len) - (thoff - sizeof(struct ipv6hdr)) - (th->doff << 2);
#endif
	} else {
		return NF_ACCEPT;
	}

	if (data_len <= 0 && !th->syn && !th->fin && !th->rst)
		return NF_ACCEPT;

	if (netlink_socket) {
		char msg[PACKET_SIZE];
		int len;

		if (ip_hdr(skb)->version == 4)
			len = scnprintf(msg, sizeof(msg),
					"type=Network,target=%d,proto=ipv4,data_len=%d;",
					uid, data_len);
#if IS_ENABLED(CONFIG_IPV6)
		else if (ip_hdr(skb)->version == 6)
			len = scnprintf(msg, sizeof(msg),
					"type=Network,target=%d,proto=ipv6,data_len=%d;",
					uid, data_len);
#endif
		else
			return NF_ACCEPT;
		rekernel_send_msg(msg, len);
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops rekernel_nf_ops[] = {
	{
		.hook = rekernel_nf_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook = rekernel_nf_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	},
#endif
};

static int register_netfilter(void)
{
	int rc;
	struct net *net = NULL;

	hash_init(rekernel_net_uid_map);

	rtnl_lock();
	for_each_net(net) {
		rc = nf_register_net_hooks(net, rekernel_nf_ops,
					   ARRAY_SIZE(rekernel_nf_ops));
		if (rc) {
			pr_err("Re:Kernel: register netfilter hooks failed, rc=%d\n", rc);
			break;
		}
	}
	rtnl_unlock();

	if (rc) {
		for_each_net(net)
			nf_unregister_net_hooks(net, rekernel_nf_ops,
						ARRAY_SIZE(rekernel_nf_ops));
		return LINE_ERROR;
	}
	return LINE_SUCCESS;
}
#endif /* CONFIG_REKERNEL_NETWORK */

/* ---- socket kill ---- */

#define REKERNEL_MAX_KILL_SOCKS 1024

struct rekernel_sock_set {
	struct sock **socks;
	int count;
};

static bool rekernel_sk_is_loopback(struct sock *sk)
{
	if (sk->sk_family == AF_INET)
		return ipv4_is_loopback(sk->sk_rcv_saddr) ||
		       ipv4_is_loopback(sk->sk_daddr);
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		return ipv6_addr_loopback(&sk->sk_v6_rcv_saddr) ||
		       ipv6_addr_loopback(&sk->sk_v6_daddr);
#endif
	return false;
}

static int rekernel_collect_socket(const void *p, struct file *file, unsigned fd)
{
	struct rekernel_sock_set *set = (struct rekernel_sock_set *)p;
	struct socket *sock;
	struct sock *sk;

	if (set->count >= REKERNEL_MAX_KILL_SOCKS)
		return 1;

	if (!S_ISSOCK(file_inode(file)->i_mode))
		return 0;

	sock = file->private_data;
	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;

	if ((sk->sk_family == AF_INET || sk->sk_family == AF_INET6) &&
	    (sk->sk_protocol == IPPROTO_TCP || sk->sk_protocol == IPPROTO_UDP)) {
		if (sk->sk_protocol == IPPROTO_TCP) {
			if (rekernel_sk_is_loopback(sk))
				return 0;
			if (sk->sk_uid.val == 2000)
				return 0;
		}
		sock_hold(sk);
		set->socks[set->count++] = sk;
	}
	return 0;
}

int rekernel_kill_net_connections(pid_t pid)
{
	struct task_struct *task;
	struct files_struct *files;
	struct pid *pid_struct;
	struct rekernel_sock_set set;
	int i, killed = 0;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return -ESRCH;
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return -ESRCH;

	set.count = 0;
	set.socks = kmalloc_array(REKERNEL_MAX_KILL_SOCKS,
				   sizeof(struct sock *), GFP_KERNEL);
	if (!set.socks) {
		put_task_struct(task);
		return -ENOMEM;
	}

	task_lock(task);
	files = task->files;
	if (files)
		iterate_fd(files, 0, rekernel_collect_socket, &set);
	task_unlock(task);

	put_task_struct(task);

	for (i = 0; i < set.count; i++) {
		struct sock *sk = set.socks[i];

		if (sk->sk_prot && sk->sk_prot->diag_destroy) {
			sk->sk_prot->diag_destroy(sk, ECONNABORTED);
			killed++;
		}
		sock_put(sk);
	}
	kfree(set.socks);
	return killed;
}

/* ---- lazy init ---- */

static int start_rekernel(void)
{
	if (netlink_unit)
		return 0;

	pr_info("Re:Kernel v%s | DEVELOPER: Sakion Team | USER PORT: %d\n",
		REKERNEL_MAJOR_VERSION, USER_PORT);
	pr_info("Trying to create Re:Kernel Server......\n");

	for (netlink_unit = 22; netlink_unit < 26; netlink_unit++) {
		netlink_socket = netlink_kernel_create(&init_net, netlink_unit,
						       &rekernel_nl_cfg);
		if (netlink_socket)
			break;
	}

	if (!netlink_socket) {
		netlink_unit = 0;
		pr_err("Failed to create Re:Kernel server!\n");
		return LINE_ERROR;
	}

	pr_info("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);

#ifdef CONFIG_PROC_FS
	rekernel_dir = proc_mkdir("rekernel", NULL);
	if (!rekernel_dir) {
		pr_err("Re:Kernel: create /proc/rekernel failed!\n");
	} else {
		char buff[32];

		sprintf(buff, "%d", netlink_unit);
		rekernel_unit_entry = proc_create(buff, 0644,
						  rekernel_dir, &rekernel_unit_fops);
		if (!rekernel_unit_entry)
			pr_err("Re:Kernel: create rekernel unit failed!\n");
	}
#endif

#ifdef CONFIG_REKERNEL_NETWORK
	if (register_netfilter()) {
		pr_err("Re:Kernel: Failed to hook netfilter!\n");
		return LINE_ERROR;
	}
#endif

	return LINE_SUCCESS;
}

/* ---- binder handlers ---- */

void binder_reply_handler(pid_t src_pid, struct task_struct *src,
			  pid_t dst_pid, struct task_struct *dst,
			  bool oneway, struct binder_transaction_data *tr)
{
	if (!dst)
		return;
	if (task_uid(dst).val > MAX_SYSTEM_UID || src_pid == dst_pid)
		return;
	rekernel_report(BINDER, REPLY, src_pid, src, dst_pid, dst, oneway, tr);
}

void binder_trans_handler(pid_t src_pid, struct task_struct *src,
			  pid_t dst_pid, struct task_struct *dst,
			  bool oneway, struct binder_transaction_data *tr)
{
	if (!dst)
		return;
	if (task_uid(dst).val <= MIN_USERAPP_UID || src_pid == dst_pid)
		return;
	rekernel_report(BINDER, TRANSACTION, src_pid, src, dst_pid, dst, oneway, tr);
}

void binder_overflow_handler(pid_t src_pid, struct task_struct *src,
			     pid_t dst_pid, struct task_struct *dst,
			     bool oneway, struct binder_transaction_data *tr)
{
	if (!dst)
		return;
	rekernel_report(BINDER, OVERFLOW, src_pid, src, dst_pid, dst, oneway, tr);
}

void rekernel_binder_transaction(bool reply, struct binder_transaction *t,
				 struct binder_node *target_node,
				 struct binder_transaction_data *tr)
{
	struct binder_proc *to_proc;
	struct binder_alloc *target_alloc;

	if (!t->to_proc)
		return;
	to_proc = t->to_proc;

	if (reply) {
		binder_reply_handler(task_tgid_nr(current), current,
				     to_proc->pid, to_proc->tsk, false, tr);
	} else if (t->from) {
		if (t->from->proc) {
			binder_trans_handler(t->from->proc->pid,
					     t->from->proc->tsk,
					     to_proc->pid, to_proc->tsk,
					     false, tr);
		}
	} else {
		binder_trans_handler(task_tgid_nr(current), current,
				     to_proc->pid, to_proc->tsk, true, tr);

		target_alloc = &to_proc->alloc;
		if (target_alloc->free_async_space <
		    (target_alloc->buffer_size / 10 + 0x300)) {
			binder_overflow_handler(task_tgid_nr(current), current,
						to_proc->pid, to_proc->tsk,
						true, tr);
		}
	}
}

/* ---- main report function ---- */

void rekernel_report(int reporttype, int type, pid_t src_pid,
		     struct task_struct *src, pid_t dst_pid,
		     struct task_struct *dst, bool oneway,
		     struct binder_transaction_data *tr)
{
	char msg[PACKET_SIZE];
	char buf_data[INTERFACETOKEN_BUFF_SIZE];
	size_t buf_data_size;
	char buf[INTERFACETOKEN_BUFF_SIZE] = {0};
	char *p;
	int i = 0, j = 0;

	if (start_rekernel())
		return;

#ifdef CONFIG_REKERNEL_NETWORK
	if (reporttype == NETWORK) {
		scnprintf(msg, sizeof(msg),
			  "type=Network,target=%d,proto=ipv%d,data_len=%d;",
			  dst_pid, type, src_pid);
		rekernel_send_msg(msg, strlen(msg));
		return;
	}
#endif

	if (!frozen_task_group(dst))
		return;

	if (task_uid(src).val == task_uid(dst).val)
		return;

	switch (reporttype) {
	case BINDER:
		if (oneway && type == TRANSACTION) {
			if (tr->code < 29 || tr->code > 32)
				return;
			buf_data_size = tr->data_size > INTERFACETOKEN_BUFF_SIZE ?
					INTERFACETOKEN_BUFF_SIZE : tr->data_size;
			if (copy_from_user(buf_data, (char __user *)tr->data.ptr.buffer,
					   buf_data_size))
				return;
			j = PARCEL_OFFSET + 1;
			p = buf_data + PARCEL_OFFSET;
			while (i < INTERFACETOKEN_BUFF_SIZE && j < buf_data_size && *p) {
				buf[i++] = *p;
				j += 2;
				p += 2;
			}
			if (i == INTERFACETOKEN_BUFF_SIZE)
				buf[i - 1] = '\0';
			scnprintf(msg, sizeof(msg),
				  "type=Binder,bindertype=transaction,oneway=1,"
				  "from_pid=%d,from=%d,target_pid=%d,target=%d,"
				  "rpc_name=%s,code=%d;",
				  src_pid, task_uid(src).val,
				  dst_pid, task_uid(dst).val, buf, tr->code);
		} else {
			static const char * const binder_type_str[] = {
				"reply", "transaction", "free_buffer_full",
			};
			static const char * const rpc_type_str[] = {
				"SYNC_BINDER_REPLY", "SYNC_BINDER", "FREE_BUFFER_FULL",
			};
			scnprintf(msg, sizeof(msg),
				  "type=Binder,bindertype=%s,oneway=%d,"
				  "from_pid=%d,from=%d,target_pid=%d,target=%d,"
				  "rpc_name=%s,code=%d;",
				  binder_type_str[type], oneway,
				  src_pid, task_uid(src).val,
				  dst_pid, task_uid(dst).val,
				  rpc_type_str[type], -1);
		}
		break;
	case SIGNAL:
		scnprintf(msg, sizeof(msg),
			  "type=Signal,signal=%d,killer_pid=%d,killer=%d,"
			  "dst_pid=%d,dst=%d;",
			  type, src_pid, task_uid(src).val,
			  dst_pid, task_uid(dst).val);
		break;
	default:
		return;
	}

	rekernel_send_msg(msg, strlen(msg));
}
