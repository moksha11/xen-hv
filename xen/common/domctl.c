/******************************************************************************
 * domctl.c
 * 
 * Domain management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/rcupdate.h>
#include <xen/guest_access.h>
#include <xen/bitmap.h>
#include <xen/paging.h>
#include <asm/current.h>
#include <public/domctl.h>
#include <xsm/xsm.h>
#include <mini.h>
#ifdef PERF_MON
#define NUM_CTRS 4
#endif

static DEFINE_SPINLOCK(domctl_lock);

extern long arch_do_domctl(
    struct xen_domctl *op, XEN_GUEST_HANDLE(xen_domctl_t) u_domctl);

int cpumask_to_xenctl_cpumap(
    struct xenctl_cpumap *xenctl_cpumap, cpumask_t *cpumask)
{
    unsigned int guest_bytes, copy_bytes, i;
    uint8_t zero = 0;
    uint8_t bytemap[(NR_CPUS + 7) / 8];

    guest_bytes = (xenctl_cpumap->nr_cpus + 7) / 8;
    copy_bytes  = min_t(unsigned int, guest_bytes, sizeof(bytemap));

    bitmap_long_to_byte(bytemap, cpus_addr(*cpumask), NR_CPUS);

    if ( copy_bytes != 0 )
        if ( copy_to_guest(xenctl_cpumap->bitmap, bytemap, copy_bytes) )
            return -EFAULT;

    for ( i = copy_bytes; i < guest_bytes; i++ )
        if ( copy_to_guest_offset(xenctl_cpumap->bitmap, i, &zero, 1) )
            return -EFAULT;

    return 0;
}

int xenctl_cpumap_to_cpumask(
    cpumask_t *cpumask, struct xenctl_cpumap *xenctl_cpumap)
{
    unsigned int guest_bytes, copy_bytes;
    uint8_t bytemap[(NR_CPUS + 7) / 8];

    guest_bytes = (xenctl_cpumap->nr_cpus + 7) / 8;
    copy_bytes  = min_t(unsigned int, guest_bytes, sizeof(bytemap));

    memset(bytemap, 0, sizeof(bytemap));

    if ( copy_bytes != 0 )
    {
        if ( copy_from_guest(bytemap, xenctl_cpumap->bitmap, copy_bytes) )
            return -EFAULT;
        if ( (xenctl_cpumap->nr_cpus & 7) && (guest_bytes <= sizeof(bytemap)) )
            bytemap[guest_bytes-1] &= ~(0xff << (xenctl_cpumap->nr_cpus & 7));
    }

    bitmap_byte_to_long(cpus_addr(*cpumask), bytemap, NR_CPUS);

    return 0;
}

static inline int is_free_domid(domid_t dom)
{
    struct domain *d;

    if ( dom >= DOMID_FIRST_RESERVED )
        return 0;

    if ( (d = rcu_lock_domain_by_id(dom)) == NULL )
        return 1;

    rcu_unlock_domain(d);
    return 0;
}

void getdomaininfo(struct domain *d, struct xen_domctl_getdomaininfo *info)
{
    struct vcpu *v;
    u64 cpu_time = 0;
    int flags = XEN_DOMINF_blocked;
    struct vcpu_runstate_info runstate;
    
    info->domain = d->domain_id;
    info->nr_online_vcpus = 0;
    info->ssidref = 0;
    
    /* 
     * - domain is marked as blocked only if all its vcpus are blocked
     * - domain is marked as running if any of its vcpus is running
     */
    for_each_vcpu ( d, v )
    {
        vcpu_runstate_get(v, &runstate);
        cpu_time += runstate.time[RUNSTATE_running];
        info->max_vcpu_id = v->vcpu_id;
        if ( !test_bit(_VPF_down, &v->pause_flags) )
        {
            if ( !(v->pause_flags & VPF_blocked) )
                flags &= ~XEN_DOMINF_blocked;
            if ( v->is_running )
                flags |= XEN_DOMINF_running;
            info->nr_online_vcpus++;
        }
    }

    info->cpu_time = cpu_time;

    info->flags = (info->nr_online_vcpus ? flags : 0) |
        ((d->is_dying == DOMDYING_dead) ? XEN_DOMINF_dying    : 0) |
        (d->is_shut_down                ? XEN_DOMINF_shutdown : 0) |
        (d->is_paused_by_controller     ? XEN_DOMINF_paused   : 0) |
        (d->debugger_attached           ? XEN_DOMINF_debugged : 0) |
        d->shutdown_code << XEN_DOMINF_shutdownshift;

    if ( is_hvm_domain(d) )
        info->flags |= XEN_DOMINF_hvm_guest;

    xsm_security_domaininfo(d, info);

    info->tot_pages         = d->tot_pages;
    info->max_pages         = d->max_pages;
    info->shr_pages         = atomic_read(&d->shr_pages);
    info->shared_info_frame = mfn_to_gmfn(d, __pa(d->shared_info)>>PAGE_SHIFT);
    BUG_ON(SHARED_M2P(info->shared_info_frame));

    info->cpupool = d->cpupool ? d->cpupool->cpupool_id : CPUPOOLID_NONE;

    memcpy(info->handle, d->handle, sizeof(xen_domain_handle_t));
}

static unsigned int default_vcpu0_location(cpumask_t *online)
{
    struct domain *d;
    struct vcpu   *v;
    unsigned int   i, cpu, nr_cpus, *cnt;
    cpumask_t      cpu_exclude_map;

    /* Do an initial CPU placement. Pick the least-populated CPU. */
    nr_cpus = last_cpu(cpu_online_map) + 1;
    cnt = xmalloc_array(unsigned int, nr_cpus);
    if ( cnt )
    {
        memset(cnt, 0, nr_cpus * sizeof(*cnt));

        rcu_read_lock(&domlist_read_lock);
        for_each_domain ( d )
            for_each_vcpu ( d, v )
                if ( !test_bit(_VPF_down, &v->pause_flags)
                     && ((cpu = v->processor) < nr_cpus) )
                    cnt[cpu]++;
        rcu_read_unlock(&domlist_read_lock);
    }

    /*
     * If we're on a HT system, we only auto-allocate to a non-primary HT. We 
     * favour high numbered CPUs in the event of a tie.
     */
    cpu = first_cpu(per_cpu(cpu_sibling_map, 0));
    if ( cpus_weight(per_cpu(cpu_sibling_map, 0)) > 1 )
        cpu = next_cpu(cpu, per_cpu(cpu_sibling_map, 0));
    cpu_exclude_map = per_cpu(cpu_sibling_map, 0);
    for_each_cpu_mask(i, *online)
    {
        if ( cpu_isset(i, cpu_exclude_map) )
            continue;
        if ( (i == first_cpu(per_cpu(cpu_sibling_map, i))) &&
             (cpus_weight(per_cpu(cpu_sibling_map, i)) > 1) )
            continue;
        cpus_or(cpu_exclude_map, cpu_exclude_map, per_cpu(cpu_sibling_map, i));
        if ( !cnt || cnt[i] <= cnt[cpu] )
            cpu = i;
    }

    xfree(cnt);

    return cpu;
}

bool_t domctl_lock_acquire(void)
{
    /*
     * Caller may try to pause its own VCPUs. We must prevent deadlock
     * against other non-domctl routines which try to do the same.
     */
    if ( !spin_trylock(&current->domain->hypercall_deadlock_mutex) )
        return 0;

    /*
     * Trylock here is paranoia if we have multiple privileged domains. Then
     * we could have one domain trying to pause another which is spinning
     * on domctl_lock -- results in deadlock.
     */
    if ( spin_trylock(&domctl_lock) )
        return 1;

    spin_unlock(&current->domain->hypercall_deadlock_mutex);
    return 0;
}

void domctl_lock_release(void)
{
    spin_unlock(&domctl_lock);
    spin_unlock(&current->domain->hypercall_deadlock_mutex);
}

long do_domctl(XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    long ret = 0;
    struct xen_domctl curop, *op = &curop;

    if ( copy_from_guest(op, u_domctl, 1) )
        return -EFAULT;

    if ( op->interface_version != XEN_DOMCTL_INTERFACE_VERSION )
        return -EACCES;

    switch ( op->cmd )
    {
    case XEN_DOMCTL_ioport_mapping:
    case XEN_DOMCTL_memory_mapping:
    case XEN_DOMCTL_bind_pt_irq:
    case XEN_DOMCTL_unbind_pt_irq: {
        struct domain *d;
        bool_t is_priv = IS_PRIV(current->domain);
        if ( !is_priv && ((d = rcu_lock_domain_by_id(op->domain)) != NULL) )
        {
            is_priv = IS_PRIV_FOR(current->domain, d);
            rcu_unlock_domain(d);
        }
        if ( !is_priv )
            return -EPERM;
        break;
    }
    default:
        if ( !IS_PRIV(current->domain) )
            return -EPERM;
        break;
    }

    if ( !domctl_lock_acquire() )
        return hypercall_create_continuation(
            __HYPERVISOR_domctl, "h", u_domctl);

    switch ( op->cmd )
    {

    case XEN_DOMCTL_setvcpucontext:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);
        vcpu_guest_context_u c = { .nat = NULL };
        unsigned int vcpu = op->u.vcpucontext.vcpu;
        struct vcpu *v;

        ret = -ESRCH;
        if ( d == NULL )
            break;

        ret = xsm_setvcpucontext(d);
        if ( ret )
            goto svc_out;

        ret = -EINVAL;
        if ( (d == current->domain) || /* no domain_pause() */
             (vcpu >= d->max_vcpus) || ((v = d->vcpu[vcpu]) == NULL) )
            goto svc_out;

        if ( guest_handle_is_null(op->u.vcpucontext.ctxt) )
        {
            vcpu_reset(v);
            ret = 0;
            goto svc_out;
        }

#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(sizeof(struct vcpu_guest_context)
                     < sizeof(struct compat_vcpu_guest_context));
#endif
        ret = -ENOMEM;
        if ( (c.nat = xmalloc(struct vcpu_guest_context)) == NULL )
            goto svc_out;

#ifdef CONFIG_COMPAT
        if ( !is_pv_32on64_vcpu(v) )
            ret = copy_from_guest(c.nat, op->u.vcpucontext.ctxt, 1);
        else
            ret = copy_from_guest(c.cmp,
                                  guest_handle_cast(op->u.vcpucontext.ctxt,
                                                    void), 1);
#else
        ret = copy_from_guest(c.nat, op->u.vcpucontext.ctxt, 1);
#endif
        ret = ret ? -EFAULT : 0;

        if ( ret == 0 )
        {
            domain_pause(d);
            ret = arch_set_info_guest(v, c);
            domain_unpause(d);
        }

    svc_out:
        xfree(c.nat);
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_pausedomain:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = xsm_pausedomain(d);
            if ( ret )
                goto pausedomain_out;

            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_pause_by_systemcontroller(d);
                ret = 0;
            }
        pausedomain_out:
            rcu_unlock_domain(d);
        }
    }
    break;

    case XEN_DOMCTL_unpausedomain:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);

        ret = -ESRCH;
        if ( d == NULL )
            break;

        ret = xsm_unpausedomain(d);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        domain_unpause_by_systemcontroller(d);
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_resumedomain:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);

        ret = -ESRCH;
        if ( d == NULL )
            break;

        ret = xsm_resumedomain(d);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        domain_resume(d);
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_createdomain:
    {
        struct domain *d;
        domid_t        dom;
        static domid_t rover = 0;
        unsigned int domcr_flags;

        ret = -EINVAL;
        if ( supervisor_mode_kernel ||
             (op->u.createdomain.flags &
             ~(XEN_DOMCTL_CDF_hvm_guest | XEN_DOMCTL_CDF_hap |
               XEN_DOMCTL_CDF_s3_integrity | XEN_DOMCTL_CDF_oos_off)) )
            break;

        dom = op->domain;
        if ( (dom > 0) && (dom < DOMID_FIRST_RESERVED) )
        {
            ret = -EINVAL;
            if ( !is_free_domid(dom) )
                break;
        }
        else
        {
            for ( dom = rover + 1; dom != rover; dom++ )
            {
                if ( dom == DOMID_FIRST_RESERVED )
                    dom = 0;
                if ( is_free_domid(dom) )
                    break;
            }

            ret = -ENOMEM;
            if ( dom == rover )
                break;

            rover = dom;
        }

        domcr_flags = 0;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_hvm_guest )
            domcr_flags |= DOMCRF_hvm;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_hap )
            domcr_flags |= DOMCRF_hap;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_s3_integrity )
            domcr_flags |= DOMCRF_s3_integrity;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_oos_off )
            domcr_flags |= DOMCRF_oos_off;

        ret = -ENOMEM;
        d = domain_create(dom, domcr_flags, op->u.createdomain.ssidref);
        if ( d == NULL )
            break;

        ret = 0;

        memcpy(d->handle, op->u.createdomain.handle,
               sizeof(xen_domain_handle_t));

        op->domain = d->domain_id;
        if ( copy_to_guest(u_domctl, op, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_DOMCTL_max_vcpus:
    {
        struct domain *d;
        unsigned int i, max = op->u.max_vcpus.max, cpu;
        cpumask_t *online;
#ifdef PERF_MON
        int mon_enable = 1;
#endif

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
            break;

        ret = -EINVAL;
        if ( (d == current->domain) || /* no domain_pause() */
             (max > MAX_VIRT_CPUS) ||
             (is_hvm_domain(d) && (max > MAX_HVM_VCPUS)) )
        {
            rcu_unlock_domain(d);
            break;
        }

        ret = xsm_max_vcpus(d);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        /* Until Xenoprof can dynamically grow its vcpu-s array... */
        if ( d->xenoprof )
        {
            rcu_unlock_domain(d);
            ret = -EAGAIN;
            break;
        }

        /* Needed, for example, to ensure writable p.t. state is synced. */
        domain_pause(d);

        /* We cannot reduce maximum VCPUs. */
        ret = -EINVAL;
        if ( (max < d->max_vcpus) && (d->vcpu[max] != NULL) )
            goto maxvcpu_out;

        /*
         * For now don't allow increasing the vcpu count from a non-zero
         * value: This code and all readers of d->vcpu would otherwise need
         * to be converted to use RCU, but at present there's no tools side
         * code path that would issue such a request.
         */
        ret = -EBUSY;
        if ( (d->max_vcpus > 0) && (max > d->max_vcpus) )
            goto maxvcpu_out;
#ifdef PERF_MON
		d->mon_enable = mon_enable;
#endif

        ret = -ENOMEM;
        online = (d->cpupool == NULL) ? &cpu_online_map : &d->cpupool->cpu_valid;
#ifdef PERF_MON
        if(d->cpupool != NULL)
          printk("cpupool ID = %d, domain ID = %d, max_vcpus = %d, max = %d\n", d->cpupool->cpupool_id, d->domain_id, d->max_vcpus, max );
#endif
        if ( max > d->max_vcpus )
        {
            struct vcpu **vcpus;

            BUG_ON(d->vcpu != NULL);
            BUG_ON(d->max_vcpus != 0);

#ifdef PERF_MON
            d->sum = (uint64_t **)xmalloc_array(uint64_t *, max);
            memset(d->sum, 0, max * sizeof(uint64_t *));
            for (i = 0; i < max; i++) {
                d->sum[i] = (uint64_t *)xmalloc_array(uint64_t, NUM_CTRS);
                memset(d->sum[i], 0, sizeof(uint64_t) * NUM_CTRS);
            }
#endif
            if ( (vcpus = xmalloc_array(struct vcpu *, max)) == NULL )
                goto maxvcpu_out;
            memset(vcpus, 0, max * sizeof(*vcpus));

            /* Install vcpu array /then/ update max_vcpus. */
            d->vcpu = vcpus;
            wmb();
            d->max_vcpus = max;
        }

        for ( i = 0; i < max; i++ )
        {
            if ( d->vcpu[i] != NULL )
                continue;

            cpu = (i == 0) ?
                default_vcpu0_location(online) :
                cycle_cpu(d->vcpu[i-1]->processor, *online);
#ifdef PERF_MON
            printk("Allocating domain %d vcpu %d on cpu %d\n", d->domain_id, i, cpu);
            if ( alloc_vcpu(d, i, cpu, mon_enable) == NULL )
#else
            if ( alloc_vcpu(d, i, cpu) == NULL )
#endif
                goto maxvcpu_out;
        }

        ret = 0;

    maxvcpu_out:
        domain_unpause(d);
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_destroydomain:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = xsm_destroydomain(d) ? : domain_kill(d);
            rcu_unlock_domain(d);
        }
    }
    break;

    case XEN_DOMCTL_setvcpuaffinity:
    case XEN_DOMCTL_getvcpuaffinity:
    {
        domid_t dom = op->domain;
        struct domain *d = rcu_lock_domain_by_id(dom);
        struct vcpu *v;
        cpumask_t new_affinity;

        ret = -ESRCH;
        if ( d == NULL )
            break;

        ret = xsm_vcpuaffinity(op->cmd, d);
        if ( ret )
            goto vcpuaffinity_out;

        ret = -EINVAL;
        if ( op->u.vcpuaffinity.vcpu >= d->max_vcpus )
            goto vcpuaffinity_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.vcpuaffinity.vcpu]) == NULL )
            goto vcpuaffinity_out;

        if ( op->cmd == XEN_DOMCTL_setvcpuaffinity )
        {
            ret = xenctl_cpumap_to_cpumask(
                &new_affinity, &op->u.vcpuaffinity.cpumap);
            if ( !ret )
                ret = vcpu_set_affinity(v, &new_affinity);
        }
        else
        {
            ret = cpumask_to_xenctl_cpumap(
                &op->u.vcpuaffinity.cpumap, &v->cpu_affinity);
        }

    vcpuaffinity_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_scheduler_op:
    {
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
            break;

        ret = xsm_scheduler(d);
        if ( ret )
            goto scheduler_op_out;

        ret = sched_adjust(d, &op->u.scheduler_op);
        if ( copy_to_guest(u_domctl, op, 1) )
            ret = -EFAULT;

    scheduler_op_out:
        rcu_unlock_domain(d);
    }
    break;

#ifdef PERF_MON
    case XEN_DOMCTL_getvcpuctrs:
    {
        struct domain *d;
        int i = 0;
        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
           break;
        
        ret = sched_vcpu_readctrs(d);
        // copy d->sum one by one using guest offset into guest memory.
        // reference implementation: XEN_DOMCTL_getmemlist

        for (i = 0; i < d->max_vcpus; i++)
        {
//           if (copy_to_guest_offset((op->u.vcpuctrs.ctrsptr + (i*sizeof(uint64_t)*NUM_CTRS)), 0, d->sum[i], sizeof(uint64_t)*NUM_CTRS))
           //if (copy_to_guest_offset(op->u.vcpuctrs.ctrsptr, i*NUM_CTRS, d->sum[i], sizeof(uint64_t)*NUM_CTRS))
             //ret = -EFAULT; 
        }

        rcu_unlock_domain(d);

    }
    break;
#endif
    case XEN_DOMCTL_getdomaininfo:
    { 
        struct domain *d;
        domid_t dom = op->domain;

        rcu_read_lock(&domlist_read_lock);

        for_each_domain ( d )
            if ( d->domain_id >= dom )
                break;

        if ( d == NULL )
        {
            rcu_read_unlock(&domlist_read_lock);
            ret = -ESRCH;
            break;
        }

        ret = xsm_getdomaininfo(d);
        if ( ret )
            goto getdomaininfo_out;

        getdomaininfo(d, &op->u.getdomaininfo);

        op->domain = op->u.getdomaininfo.domain;
        if ( copy_to_guest(u_domctl, op, 1) )
            ret = -EFAULT;

    getdomaininfo_out:
        rcu_read_unlock(&domlist_read_lock);
    }
    break;

    case XEN_DOMCTL_getvcpucontext:
    { 
        vcpu_guest_context_u c = { .nat = NULL };
        struct domain       *d;
        struct vcpu         *v;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
            break;

        ret = xsm_getvcpucontext(d);
        if ( ret )
            goto getvcpucontext_out;

        ret = -EINVAL;
        if ( op->u.vcpucontext.vcpu >= d->max_vcpus )
            goto getvcpucontext_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.vcpucontext.vcpu]) == NULL )
            goto getvcpucontext_out;

        ret = -ENODATA;
        if ( !v->is_initialised )
            goto getvcpucontext_out;

#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(sizeof(struct vcpu_guest_context)
                     < sizeof(struct compat_vcpu_guest_context));
#endif
        ret = -ENOMEM;
        if ( (c.nat = xmalloc(struct vcpu_guest_context)) == NULL )
            goto getvcpucontext_out;

        if ( v != current )
            vcpu_pause(v);

        arch_get_info_guest(v, c);
        ret = 0;

        if ( v != current )
            vcpu_unpause(v);

#ifdef CONFIG_COMPAT
        if ( !is_pv_32on64_vcpu(v) )
            ret = copy_to_guest(op->u.vcpucontext.ctxt, c.nat, 1);
        else
            ret = copy_to_guest(guest_handle_cast(op->u.vcpucontext.ctxt,
                                                  void), c.cmp, 1);
#else
        ret = copy_to_guest(op->u.vcpucontext.ctxt, c.nat, 1);
#endif

        if ( copy_to_guest(u_domctl, op, 1) || ret )
            ret = -EFAULT;

    getvcpucontext_out:
        xfree(c.nat);
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_getvcpuinfo:
    { 
        struct domain *d;
        struct vcpu   *v;
        struct vcpu_runstate_info runstate;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
            break;

        ret = xsm_getvcpuinfo(d);
        if ( ret )
            goto getvcpuinfo_out;

        ret = -EINVAL;
        if ( op->u.getvcpuinfo.vcpu >= d->max_vcpus )
            goto getvcpuinfo_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.getvcpuinfo.vcpu]) == NULL )
            goto getvcpuinfo_out;

        vcpu_runstate_get(v, &runstate);

        op->u.getvcpuinfo.online   = !test_bit(_VPF_down, &v->pause_flags);
        op->u.getvcpuinfo.blocked  = test_bit(_VPF_blocked, &v->pause_flags);
        op->u.getvcpuinfo.running  = v->is_running;
        op->u.getvcpuinfo.cpu_time = runstate.time[RUNSTATE_running];
        op->u.getvcpuinfo.cpu      = v->processor;
        ret = 0;

        if ( copy_to_guest(u_domctl, op, 1) )
            ret = -EFAULT;

    getvcpuinfo_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_max_mem:
    {
        struct domain *d;
        unsigned long new_max;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        ret = xsm_setdomainmaxmem(d);
        if ( ret )
            goto max_mem_out;

        ret = -EINVAL;
        new_max = op->u.max_mem.max_memkb >> (PAGE_SHIFT-10);

        spin_lock(&d->page_alloc_lock);
        /*
         * NB. We removed a check that new_max >= current tot_pages; this means
         * that the domain will now be allowed to "ratchet" down to new_max. In
         * the meantime, while tot > max, all new allocations are disallowed.
         */
        d->max_pages = new_max;
        ret = 0;
        spin_unlock(&d->page_alloc_lock);

    max_mem_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_setdomainhandle:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        ret = xsm_setdomainhandle(d);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        memcpy(d->handle, op->u.setdomainhandle.handle,
               sizeof(xen_domain_handle_t));
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_setdebugging:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        ret = -EINVAL;
        if ( d == current->domain ) /* no domain_pause() */
        {
            rcu_unlock_domain(d);
            break;
        }

        ret = xsm_setdebugging(d);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        domain_pause(d);
        d->debugger_attached = !!op->u.setdebugging.enable;
        domain_unpause(d); /* causes guest to latch new status */
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_irq_permission:
    {
        struct domain *d;
        unsigned int pirq = op->u.irq_permission.pirq;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        if ( pirq >= d->nr_pirqs )
            ret = -EINVAL;
        else if ( op->u.irq_permission.allow_access )
            ret = irq_permit_access(d, pirq);
        else
            ret = irq_deny_access(d, pirq);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_iomem_permission:
    {
        struct domain *d;
        unsigned long mfn = op->u.iomem_permission.first_mfn;
        unsigned long nr_mfns = op->u.iomem_permission.nr_mfns;

        ret = -EINVAL;
        if ( (mfn + nr_mfns - 1) < mfn ) /* wrap? */
            break;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        if ( op->u.iomem_permission.allow_access )
            ret = iomem_permit_access(d, mfn, mfn + nr_mfns - 1);
        else
            ret = iomem_deny_access(d, mfn, mfn + nr_mfns - 1);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_settimeoffset:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        ret = xsm_domain_settime(d);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        domain_set_time_offset(d, op->u.settimeoffset.time_offset_seconds);
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_set_target:
    {
        struct domain *d, *e;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        ret = -ESRCH;
        e = get_domain_by_id(op->u.set_target.target);
        if ( e == NULL )
            goto set_target_out;

        ret = -EINVAL;
        if ( (d == e) || (d->target != NULL) )
        {
            put_domain(e);
            goto set_target_out;
        }

        ret = xsm_set_target(d, e);
        if ( ret ) {
            put_domain(e);
            goto set_target_out;            
        }

        /* Hold reference on @e until we destroy @d. */
        d->target = e;

        ret = 0;

    set_target_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_subscribe:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d != NULL )
        {
            d->suspend_evtchn = op->u.subscribe.port;
            rcu_unlock_domain(d);
            ret = 0;
        }
    }
    break;

    case XEN_DOMCTL_disable_migrate:
    {
        struct domain *d;
        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) != NULL )
        {
            d->disable_migrate = op->u.disable_migrate.disable;
            rcu_unlock_domain(d);
            ret = 0;
        }
    }
    break;

    default:
        ret = arch_do_domctl(op, u_domctl);
        break;
    }

    domctl_lock_release();

    return ret;
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
