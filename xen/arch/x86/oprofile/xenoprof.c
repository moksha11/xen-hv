/*
 * Copyright (C) 2005 Hewlett-Packard Co.
 * written by Aravind Menon & Jose Renato Santos
 *            (email: xenoprof@groups.hp.com)
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 * x86 specific part
 */

#include <xen/guest_access.h>
#include <xen/sched.h>
#include <public/xenoprof.h>
#ifdef CONFIG_COMPAT
#include <compat/xenoprof.h>
#endif
#include <asm/hvm/support.h>

#include "op_counter.h"
#include <mini.h>

#ifdef ENABLE_MYPROF
void myprof_counter(void)
{
    struct xenoprof_counter counter;
    counter.ind = 0;
    counter.count = 10000;
    counter.enabled = 1;
    counter.event = 12;
    counter.hypervisor = 0;	// don't know..looks like garbage
    counter.kernel = 1;
    counter.user = 1;
    counter.unit_mask = 0x100;

    counter_config[counter.ind].count     = counter.count;
    counter_config[counter.ind].enabled   = counter.enabled;
    counter_config[counter.ind].event     = counter.event;
    counter_config[counter.ind].kernel    = counter.kernel;
    counter_config[counter.ind].user      = counter.user;
    counter_config[counter.ind].unit_mask = counter.unit_mask;
	int i;
	for(i=1;i<4;i++) {
    counter.ind = i;
    counter.count = 0;
    counter.enabled = 0;
    counter.event = 0;
    counter.hypervisor = 0;	// don't know..looks like garbage
    counter.kernel = 0;
    counter.user = 0;
    counter.unit_mask = 0;

    counter_config[counter.ind].count     = counter.count;
    counter_config[counter.ind].enabled   = counter.enabled;
    counter_config[counter.ind].event     = counter.event;
    counter_config[counter.ind].kernel    = counter.kernel;
    counter_config[counter.ind].user      = counter.user;
    counter_config[counter.ind].unit_mask = counter.unit_mask;
	}
}
#endif


int xenoprof_arch_counter(XEN_GUEST_HANDLE(void) arg)
{
    struct xenoprof_counter counter;

    if ( copy_from_guest(&counter, arg, 1) )
        return -EFAULT;

    if ( counter.ind > OP_MAX_COUNTER )
        return -E2BIG;

    counter_config[counter.ind].count     = counter.count;
    counter_config[counter.ind].enabled   = counter.enabled;
    counter_config[counter.ind].event     = counter.event;
    counter_config[counter.ind].kernel    = counter.kernel;
    counter_config[counter.ind].user      = counter.user;
    counter_config[counter.ind].unit_mask = counter.unit_mask;

#ifdef ENABLE_MYPROF
	printk("counter:: ind:%x count:%llx enabled:%x event:%x hypervisor:%x kernel:%x user:%x unit_mask:%llx\n", counter.ind, counter.count, counter.enabled, counter.event, counter.hypervisor, counter.kernel, counter.user, counter.unit_mask );	// why myprintk doesn't compile?
#endif

    return 0;
}

int xenoprof_arch_ibs_counter(XEN_GUEST_HANDLE(void) arg)
{
    struct xenoprof_ibs_counter ibs_counter;

    if ( copy_from_guest(&ibs_counter, arg, 1) )
        return -EFAULT;

    ibs_config.op_enabled = ibs_counter.op_enabled;
    ibs_config.fetch_enabled = ibs_counter.fetch_enabled;
    ibs_config.max_cnt_fetch = ibs_counter.max_cnt_fetch;
    ibs_config.max_cnt_op = ibs_counter.max_cnt_op;
    ibs_config.rand_en = ibs_counter.rand_en;
    ibs_config.dispatched_ops = ibs_counter.dispatched_ops;

    return 0;
}

#ifdef CONFIG_COMPAT
int compat_oprof_arch_counter(XEN_GUEST_HANDLE(void) arg)
{
    struct compat_oprof_counter counter;

    if ( copy_from_guest(&counter, arg, 1) )
        return -EFAULT;

    if ( counter.ind > OP_MAX_COUNTER )
        return -E2BIG;

    counter_config[counter.ind].count     = counter.count;
    counter_config[counter.ind].enabled   = counter.enabled;
    counter_config[counter.ind].event     = counter.event;
    counter_config[counter.ind].kernel    = counter.kernel;
    counter_config[counter.ind].user      = counter.user;
    counter_config[counter.ind].unit_mask = counter.unit_mask;

    return 0;
}
#endif

int xenoprofile_get_mode(struct vcpu *v, struct cpu_user_regs * const regs)
{
    if ( !guest_mode(regs) )
        return 2;

    if ( is_hvm_vcpu(v) )
        return ((regs->cs & 3) != 3);

    return guest_kernel_mode(v, regs);  
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
