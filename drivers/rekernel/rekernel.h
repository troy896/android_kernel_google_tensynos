#ifndef __REKERNEL_H
#define __REKERNEL_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cgroup.h>
#include <linux/freezer.h>
#include <linux/version.h>
#include <uapi/linux/android/binder.h>

struct binder_transaction;
struct binder_node;

#define REKERNEL_MAJOR_VERSION		"10.0"

#define CLEAN_UP_ASYNC_BINDER

#define MIN_USERAPP_UID			10000
#define MAX_SYSTEM_UID			2000
#define SYSTEM_APP_UID			1000
#define RESERVE_ORDER			17
#define WARN_AHEAD_SPACE		(1 << RESERVE_ORDER)
#define INTERFACETOKEN_BUFF_SIZE	140
#define PARCEL_OFFSET			16
#define LINE_ERROR			(-1)
#define LINE_SUCCESS			0

#define USER_PORT			100
#define PACKET_SIZE			256

enum report_type {
	BINDER,
	SIGNAL,
#ifdef CONFIG_REKERNEL_NETWORK
	NETWORK,
#endif
};

enum binder_type {
	REPLY,
	TRANSACTION,
	OVERFLOW,
};

/* ---- freeze-state predicate ---- */

static inline bool rekernel_is_frozen_state_compatible(struct task_struct *task)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return READ_ONCE(task->__state) & TASK_FROZEN;
#else
	return frozen(task);
#endif
}

static inline bool rekernel_is_jobctl_frozen_compatible(struct task_struct *task)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 10, 0))
	return cgroup_task_freeze(task);
#else
	return ((task->jobctl & JOBCTL_TRAP_FREEZE) != 0);
#endif
}

static inline bool frozen_task_group(struct task_struct *task)
{
	if (cgroup_task_frozen(task) || rekernel_is_jobctl_frozen_compatible(task))
		return true;
	if (!task->group_leader)
		return true;
	return rekernel_is_frozen_state_compatible(task->group_leader) ||
	       freezing(task->group_leader);
}

/* ---- exported functions ---- */

extern void rekernel_report(int reporttype, int type, pid_t src_pid,
			    struct task_struct *src, pid_t dst_pid,
			    struct task_struct *dst, bool oneway,
			    struct binder_transaction_data *tr);

extern void binder_reply_handler(pid_t src_pid, struct task_struct *src,
				 pid_t dst_pid, struct task_struct *dst,
				 bool oneway, struct binder_transaction_data *tr);

extern void binder_trans_handler(pid_t src_pid, struct task_struct *src,
				 pid_t dst_pid, struct task_struct *dst,
				 bool oneway, struct binder_transaction_data *tr);

extern void binder_overflow_handler(pid_t src_pid, struct task_struct *src,
				    pid_t dst_pid, struct task_struct *dst,
				    bool oneway, struct binder_transaction_data *tr);

extern void rekernel_binder_transaction(bool reply, struct binder_transaction *t,
					struct binder_node *target_node,
					struct binder_transaction_data *tr);

#endif /* __REKERNEL_H */
