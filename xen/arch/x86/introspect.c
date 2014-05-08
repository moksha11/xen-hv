#include <xen/config.h>
#include <xen/version.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/shutdown.h>
#include <xen/nmi.h>
#include <asm/current.h>
//#include <asm/flushtlb.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>

#include <public/callback.h>

#include <asm/spinlock.h>
#include <xen/softirq.h>
#include <mini.h>

#ifdef ENABLE_INTROSPECT
// Begin: Taken from linux
typedef unsigned int kernel_cap_t;
typedef unsigned int uid_t, gid_t;
typedef unsigned long cputime_t;
typedef long time_t;

struct timespec {
        time_t  tv_sec;         /* seconds */
        long    tv_nsec;        /* nanoseconds */
};

enum pid_type
{
        PIDTYPE_PID,
        PIDTYPE_PGID,
        PIDTYPE_SID,
        PIDTYPE_MAX
};

struct completion;
struct pid;
struct pid_link
{
        struct hlist_node node;
        struct pid *pid;
};

struct sched_info {
        /* cumulative counters */
        unsigned long   cpu_time,       /* time spent on the cpu */
                        run_delay,      /* time spent waiting on a runqueue */
                        pcnt;           /* # of timeslices run on this cpu */

        /* timestamps */
        unsigned long   last_arrival,   /* when we last ran on a cpu */
                        last_queued;    /* when we were last queued to run */
};


typedef unsigned long mm_segment_t;

/*
 * System call restart block.
 */
struct restart_block {
        long (*fn)(struct restart_block *);
        unsigned long arg0, arg1, arg2, arg3;
};

struct thread_info {
        struct task_struct      *task;          /* main task structure */
        struct exec_domain      *exec_domain;   /* execution domain */
        unsigned long           flags;          /* low level flags */
        unsigned long           status;         /* thread-synchronous flags */
        __u32                   cpu;            /* current CPU */
        int                     preempt_count;  /* 0 => preemptable, <0 => BUG */


        mm_segment_t            addr_limit;     /* thread address space:
                                                   0-0xBFFFFFFF for user-thead
                                                   0-0xFFFFFFFF for kernel-thread
                                                */
        void                    *sysenter_return;
        struct restart_block    restart_block;

        unsigned long           previous_esp;   /* ESP of the previous stack in case
                                                   of nested (IRQ) stacks
                                                */
        __u8                    supervisor_stack[0];
};

enum sleep_type {
        SLEEP_NORMAL,
        SLEEP_NONINTERACTIVE,
        SLEEP_INTERACTIVE,
        SLEEP_INTERRUPTED,
};

struct prio_array;
struct linux_binfmt;
typedef int pid_t;

#define TASK_COMM_LEN		16
struct task_struct {
        volatile long state;    /* -1 unrunnable, 0 runnable, >0 stopped */
        struct thread_info *thread_info;
        atomic_t usage;
        unsigned long flags;    /* per process flags, defined below */
        unsigned long ptrace;

        int lock_depth;         /* BKL lock depth */

        int load_weight;        /* for niceness load balancing purposes */
        int prio, static_prio, normal_prio;
        struct list_head run_list;
        struct prio_array *array;

        unsigned short ioprio;
        unsigned int btrace_seq;

        unsigned long sleep_avg;
        unsigned long long timestamp, last_ran;
        unsigned long long sched_time; /* sched_clock time spent running */
        enum sleep_type sleep_type;

        unsigned long policy;
        cpumask_t cpus_allowed;	// CONFIG_NR_CPUS=32
        unsigned int time_slice, first_time_slice;

        struct sched_info sched_info;	// CONFIG_TASK_DELAY_ACCT

        struct list_head tasks;
        /*
         * ptrace_list/ptrace_children forms the list of my children
         * that were stolen by a ptracer.
         */
        struct list_head ptrace_children;
        struct list_head ptrace_list;

        struct mm_struct *mm, *active_mm;

/* task state */
        struct linux_binfmt *binfmt;
        long exit_state;
        int exit_code, exit_signal;
        int pdeath_signal;  /*  The signal sent when the parent dies  */
        /* ??? */
        unsigned long personality;
        unsigned did_exec:1;
        pid_t pid;
        pid_t tgid;

        /*
         * pointers to (original) parent process, youngest child, younger sibling,
         * older sibling, respectively.  (p->father can be replaced with
         * p->parent->pid)
         */
        struct task_struct *real_parent; /* real parent process (when being debugged) */
        struct task_struct *parent;     /* parent process */
        /*
         * children/sibling forms the list of my children plus the
         * tasks I'm ptracing.
         */
        struct list_head children;      /* list of my children */
        struct list_head sibling;       /* linkage in my parent's children list */
        struct task_struct *group_leader;       /* threadgroup leader */

        /* PID/PID hash table linkage. */
        struct pid_link pids[PIDTYPE_MAX];
        struct list_head thread_group;

        struct completion *vfork_done;          /* for vfork() */
        int __user *set_child_tid;              /* CLONE_CHILD_SETTID */
        int __user *clear_child_tid;            /* CLONE_CHILD_CLEARTID */

        unsigned long rt_priority;
        cputime_t utime, stime;
        unsigned long nvcsw, nivcsw; /* context switch counts */
        struct timespec start_time;
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
        unsigned long min_flt, maj_flt;

        cputime_t it_prof_expires, it_virt_expires;
        unsigned long long it_sched_expires;
        struct list_head cpu_timers[3];

/* process credentials */
        uid_t uid,euid,suid,fsuid;
        gid_t gid,egid,sgid,fsgid;
        struct group_info *group_info;
        kernel_cap_t   cap_effective, cap_inheritable, cap_permitted;
        unsigned keep_capabilities:1;
        struct user_struct *user;
// CONFIG_KEYS
        struct key *request_key_auth;   /* assumed request_key authority */
        struct key *thread_keyring;     /* keyring private to this thread */
        unsigned char jit_keyring;      /* default keyring to attach requested keys to */
// end of CONFIG_KEYS
        int oomkilladj; /* OOM kill score adjustment (bit shift). */
        char comm[TASK_COMM_LEN]; /* executable name excluding path
                                     - access with [gs]et_task_comm (which lock
                                       it with task_lock())
                                     - initialized normally by flush_old_exec */

	// TODO
};



/*
 * Per process flags
 */
#define PF_ALIGNWARN    0x00000001      /* Print alignment warning msgs */
                                        /* Not implemented yet, only for 486*/
#define PF_STARTING     0x00000002      /* being created */
#define PF_EXITING      0x00000004      /* getting shut down */
#define PF_DEAD         0x00000008      /* Dead */
#define PF_FORKNOEXEC   0x00000040      /* forked but didn't exec */
#define PF_SUPERPRIV    0x00000100      /* used super-user privileges */
#define PF_DUMPCORE     0x00000200      /* dumped core */
#define PF_SIGNALED     0x00000400      /* killed by a signal */
#define PF_MEMALLOC     0x00000800      /* Allocating memory */
#define PF_FLUSHER      0x00001000      /* responsible for disk writeback */
#define PF_USED_MATH    0x00002000      /* if unset the fpu must be initialized before use */
#define PF_FREEZE       0x00004000      /* this task is being frozen for suspend now */
#define PF_NOFREEZE     0x00008000      /* this thread should not be frozen */
#define PF_FROZEN       0x00010000      /* frozen for system suspend */
#define PF_FSTRANS      0x00020000      /* inside a filesystem transaction */
#define PF_KSWAPD       0x00040000      /* I am kswapd */
#define PF_SWAPOFF      0x00080000      /* I am in swapoff */
#define PF_LESS_THROTTLE 0x00100000     /* Throttle me less: I clean memory */
#define PF_BORROWED_MM  0x00200000      /* I am a kthread doing use_mm */
#define PF_RANDOMIZE    0x00400000      /* randomize virtual address space */
#define PF_SWAPWRITE    0x00800000      /* Allowed to write to swap */
#define PF_SPREAD_PAGE  0x01000000      /* Spread page cache over cpuset */
#define PF_SPREAD_SLAB  0x02000000      /* Spread some slab caches over cpuset */
#define PF_MEMPOLICY    0x10000000      /* Non-default NUMA mempolicy */
#define PF_MUTEX_TESTER 0x20000000      /* Thread belongs to the rt mutex tester */

// End of 'Taken from linux'

// start of apriori knowledges
#define LINUX_KERNEL_STACK_MASK		(~0x1FFF)
// end of apriori knowledges

struct introspect_guessing {

};


int get_tgid(unsigned long kstack)
{
	kstack = kstack & LINUX_KERNEL_STACK_MASK;
	if (!kstack)
		return -1;
	MYASSERT(kstack >= 0xC0000000);
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	int i;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->tgid;
}

int get_static_prio(unsigned long kstack)
{
	kstack = kstack & LINUX_KERNEL_STACK_MASK;
	if (!kstack)
		return -1;
	MYASSERT(kstack >= 0xC0000000);
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	int i;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->static_prio;
}

int get_normal_prio(unsigned long kstack)
{
	kstack = kstack & LINUX_KERNEL_STACK_MASK;
	if (!kstack)
		return -1;
	MYASSERT(kstack >= 0xC0000000);
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	int i;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->normal_prio;
}

int get_rt_prio(unsigned long kstack)
{
	kstack = kstack & LINUX_KERNEL_STACK_MASK;
	if (!kstack)
		return -1;
	MYASSERT(kstack >= 0xC0000000);
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	int i;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->rt_priority;
}

int get_prio(unsigned long kstack)
{
	kstack = kstack & LINUX_KERNEL_STACK_MASK;
	if (!kstack)
		return -1;
	MYASSERT(kstack >= 0xC0000000);
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	int i;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->prio;
}

int get_pid(unsigned long kstack)
{
	kstack = kstack & LINUX_KERNEL_STACK_MASK;
	if (!kstack)
		return -1;
	MYASSERT(kstack >= 0xC0000000);
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	int i;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->pid;
}

int get_mm(unsigned long kstack)
{
	kstack = kstack & LINUX_KERNEL_STACK_MASK;
	if (!kstack)
		return -1;
	MYASSERT(kstack >= 0xC0000000);
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	int i;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->mm;
}

char *get_comm(unsigned long kstack)
{
	kstack = kstack & LINUX_KERNEL_STACK_MASK;
	if (!kstack)
		return "(idle)";
	MYASSERT(kstack >= 0xC0000000);
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	int i;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->comm;
//	myprintk("ti:%4x, ti->cpu:%d, pid=%d, tgid=%d,min_flt:%d,maj_flt:%d, %s\n ", ti, ti->cpu, ts->pid, ts->tgid, ts->min_flt, ts->maj_flt, ts->comm );
//	printk("TI:%x TS:%x ->flags:%x status:%x, cpu:%x, pcount:%d, addr_limit:%x / cpus_allowed:%x mm:%x activemm:%x pid:%d tgid:%d flt(min:%d,maj:%d) comm:%16s\n", ti, ts, ti->flags, ti->status, ti->cpu, ti->preempt_count, ti->addr_limit, ts->cpus_allowed, ts->mm, ts->active_mm, ts->pid, ts->tgid, ts->min_flt, ts->maj_flt, ts->comm);
//	myprintk("mm:%x activemm:%x pid:%d tgid:%d comm:%16s\n", ts->mm, ts->active_mm, ts->pid, ts->tgid, ts->comm);
}

unsigned long translate_into_laxity(unsigned long esp)
{
	unsigned long kstack = esp & LINUX_KERNEL_STACK_MASK;
	MYASSERT(esp == 0 || esp >= 0xC0000000);

	if (!kstack)
		return 140;
	struct thread_info *ti = (struct thread_info *)kstack;
	struct task_struct *ts = ti->task;
	if (!ts)
		return 140;
#ifdef DEBUG_ASSERT
	if (ts->thread_info != ti)
		mypanic("ts->thread_info != ti?!?");
#endif
	return ts->prio;
}



// called from do_stack_switch()
void update_guest_task(unsigned long old, unsigned long esp)
{
//	old = old & LINUX_KERNEL_STACK_MASK;
//	esp = esp & LINUX_KERNEL_STACK_MASK;
	// these commented are what I was using before...
//	struct thread_info *ti = (struct thread_info *)(get_cpu_info()->guest_cpu_user_regs.esp & LINUX_KERNEL_STACK_MASK );	// get thread_info
//	struct task_struct *ts;

//	myprintk("esp:%x==%x kss:%x ksp:%x\n",get_cpu_info()->guest_cpu_user_regs.esp, current->arch.guest_context.user_regs.esp,   current->arch.guest_context.kernel_ss, current->arch.guest_context.kernel_sp);
//	if ((unsigned long)ti < 0xC0000000) {	// correction if it's from page fault
//		ti = (struct thread_info *)(current->arch.guest_context.kernel_sp & LINUX_KERNEL_STACK_MASK);
//	}
	TRACE_4D(TRC_MIN_STACK_SWITCH, current->domain->domain_id, current->vcpu_id, old, esp);

//#ifdef VERBOSE_GUEST_TASK
	if (current->print_countdown) {
#ifdef ENABLE_INTROSPECT
		myprintk("[%s,%5d.%5d %d,%d,%d,%d -> %s,%5d.%5d %d,%d,%d,%d]\n", get_comm(old), get_pid(old), get_tgid(old), get_prio(old), get_static_prio(old), get_normal_prio(old), get_rt_prio(old), get_comm(esp), get_pid(esp), get_tgid(esp), get_prio(esp), get_static_prio(esp), get_normal_prio(esp) , get_rt_prio(esp) );
#endif
		current->print_countdown--;
	}


/*
	safe_strcpy(tsk->comm, ts->comm);
	struct task_struct *ts = 0;
	myprintk("offset: %d,%d,%d,%d,%d,%d\n",
		(int)&ts->prio,
		(int)&ts->static_prio,
		(int)&ts->pid,
		(int)&ts->tgid,
		(int)&ts->rt_priority,
		(int)&ts->comm
		);*/
//#endif

	// TODO: inconsistent period ?
}
#else

char *get_comm(unsigned long kstack)
{
	return "(unknown)";
}
#endif
