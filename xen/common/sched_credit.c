/****************************************************************************
 * (C) 2005-2006 - Emmanuel Ackaouy - XenSource Inc.
 ****************************************************************************
 *
 *        File: common/csched_credit.c
 *      Author: Emmanuel Ackaouy
 *
 * Description: Credit-based SMP CPU scheduler
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <asm/atomic.h>
#include <xen/errno.h>
#include <xen/keyhandler.h>
#include <mini.h>
#include <xen/heterovisor.h>
#include <xen/guest_access.h>

#define HETEROPERF


/*
 * CSCHED_STATS
 *
 * Manage very basic per-vCPU counters and stats.
 *
 * Useful for debugging live systems. The stats are displayed
 * with runq dumps ('r' on the Xen console).
 */
#ifdef PERF_COUNTERS
#define CSCHED_STATS
#endif


/*
 * Basic constants
 */
#define CSCHED_DEFAULT_WEIGHT       256
#define CSCHED_TICKS_PER_TSLICE     3
#define CSCHED_TICKS_PER_ACCT       3
#define CSCHED_MSECS_PER_TICK       10
#define CSCHED_MSECS_PER_TSLICE     \
    (CSCHED_MSECS_PER_TICK * CSCHED_TICKS_PER_TSLICE)
#define CSCHED_CREDITS_PER_MSEC     10
#define CSCHED_CREDITS_PER_TSLICE   \
    (CSCHED_CREDITS_PER_MSEC * CSCHED_MSECS_PER_TSLICE)
#define CSCHED_CREDITS_PER_ACCT     \
    (CSCHED_CREDITS_PER_MSEC * CSCHED_MSECS_PER_TICK * CSCHED_TICKS_PER_ACCT)


/*
 * Priorities
 */
#define CSCHED_PRI_TS_BOOST      0      /* time-share waking up */
#define CSCHED_PRI_TS_UNDER     -1      /* time-share w/ credits */
#define CSCHED_PRI_TS_OVER      -2      /* time-share w/o credits */
#define CSCHED_PRI_IDLE         -64     /* idle */


/*
 * Flags
 */
#define CSCHED_FLAG_VCPU_PARKED    0x0001  /* VCPU over capped credits */
#define CSCHED_FLAG_VCPU_YIELD     0x0002  /* VCPU yielding */


/*
 * Useful macros
 */
#define CSCHED_PRIV(_ops)   \
    ((struct csched_private *)((_ops)->sched_data))
#define CSCHED_PCPU(_c)     \
    ((struct csched_pcpu *)per_cpu(schedule_data, _c).sched_priv)
#define CSCHED_VCPU(_vcpu)  ((struct csched_vcpu *) (_vcpu)->sched_priv)
#define CSCHED_DOM(_dom)    ((struct csched_dom *) (_dom)->sched_priv)
#define RUNQ(_cpu)          (&(CSCHED_PCPU(_cpu)->runq))
#define CSCHED_CPUONLINE(_pool)    \
    (((_pool) == NULL) ? &cpupool_free_cpus : &(_pool)->cpu_valid)


/*
 * Stats
 */
#define CSCHED_STAT_CRANK(_X)               (perfc_incr(_X))

#ifdef CSCHED_STATS

#define CSCHED_VCPU_STATS_RESET(_V)                     \
    do                                                  \
    {                                                   \
        memset(&(_V)->stats, 0, sizeof((_V)->stats));   \
    } while ( 0 )

#define CSCHED_VCPU_STAT_CRANK(_V, _X)      (((_V)->stats._X)++)

#define CSCHED_VCPU_STAT_SET(_V, _X, _Y)    (((_V)->stats._X) = (_Y))

#else /* CSCHED_STATS */

#define CSCHED_VCPU_STATS_RESET(_V)         do {} while ( 0 )
#define CSCHED_VCPU_STAT_CRANK(_V, _X)      do {} while ( 0 )
#define CSCHED_VCPU_STAT_SET(_V, _X, _Y)    do {} while ( 0 )

#endif /* CSCHED_STATS */

#ifdef HETERO_VISOR
cpumask_t bigcore_mask, smallcore_mask;
uint16_t hetero_nb_cores=0, hetero_ns_cores=0;
DEFINE_PER_CPU(bool_t,core_type) = 0;//big/small
uint16_t big_core_count = 0,num_active_cpus=12; //controls number of big cores on platform
uint16_t num_sockets= 2; //num_sockets
uint16_t hetero_speed_ratio = 4;
uint16_t TOTAL_SCREDITS = 100;
uint16_t TOTAL_FCREDITS = 0;

uint16_t espeed_step = 20;
uint16_t espeed_min = 20;

//Flags
bool_t hetero_visor_active = 0;//system-wide flag: enables everything
bool_t hetero_init = 0;//initialization
bool_t hetero_visor_mem = 1;//system-wide flag: enables everything

bool_t hetero_sched_active = 0;//enables hetero scheduling
uint16_t hetero_sched_tick = 0;
uint16_t hetero_debug_level = 0;//multiple levels of debug printing
uint16_t hetero_debug_tick = 0;
uint16_t hetero_hcredit_policy = 0;//enable dynamic credit allocation
uint16_t hetero_hcredit_tick = 0;//
/*DEFINE_PER_CPU(uint16_t,hetero_sched_tick) = 0;*/
/*DEFINE_PER_CPU(bool_t,do_idle_cpu) = 0;*/
#endif

/*
 * Boot parameters
 */
static bool_t __read_mostly sched_credit_default_yield;
boolean_param("sched_credit_default_yield", sched_credit_default_yield);

/*
 * Physical CPU
 */
struct csched_pcpu {
    struct list_head runq;
    uint32_t runq_sort_last;
    struct timer ticker;
    unsigned int tick;
    unsigned int idle_bias;
#ifdef ENABLE_PCPU_STAT
	s_time_t start_time;
	s_time_t sched_time;
#endif
};

/*
 * Virtual CPU
 */
struct csched_vcpu {
    struct list_head runq_elem;
    struct list_head active_vcpu_elem;
    struct csched_dom *sdom;
    struct vcpu *vcpu;
    atomic_t credit;
#ifdef HETERO_VISOR
	atomic_t fcredit;
    atomic_t scredit;
	bool_t core_type;
    struct list_head fast_vcpu_elem;
    struct list_head hetero_vcpu_elem;
	struct perf_ctrs * pctr;
	struct counters * ctr;
#endif
    s_time_t start_time;   /* When we were scheduled (used for credit) */
    uint16_t flags;
    int16_t pri;
#ifdef CSCHED_STATS
    struct {
        int credit_last;
        uint32_t credit_incr;
        uint32_t state_active;
        uint32_t state_idle;
        uint32_t migrate_q;
        uint32_t migrate_r;
    } stats;
#endif
#ifdef ENABLE_BINPACKING
	s_time_t last_passed;	// in nano sec
	long diff_passed;
	long count_passed;	// also this means # of switch for this vcpu
	long count_cosched;
#endif
#ifdef ENABLE_MEASURE_UNBALANCE
	int myprocessor;
#endif
};

#ifdef ENABLE_BINPACKING
int csched_info(struct vcpu *v, unsigned long array[])
{
	struct csched_vcpu * const svc = CSCHED_VCPU(v);
	array[0] = (svc->diff_passed<0) ? 1:0;	//sign
	array[1] = (svc->diff_passed<0) ? -svc->diff_passed:svc->diff_passed;
	array[2] = svc->count_passed;
	array[3] = svc->count_cosched;
	svc->diff_passed = 0;
	svc->count_passed = 0;
	svc->count_cosched = 0;
	return 4;
}
#endif

/*
 * Domain
 */
struct csched_dom {
    struct list_head active_vcpu;
    struct list_head active_sdom_elem;
    struct domain *dom;
    uint16_t active_vcpu_count;
    uint16_t weight;
    uint16_t cap;
#ifdef HETERO_VISOR
    int scap;
    int fcap;
	struct list_head dom_priority_elem;
    struct list_head fast_vcpu;
    struct list_head hetero_vcpu;
    uint16_t vcpu_count;
	bool_t hetero_sched_done;
	uint16_t fast_vcpu_count;
	uint16_t estate;
    uint16_t eweight;
	uint16_t elastic_speed;
	uint16_t guest_speed;
	uint16_t epriority;
#endif
};

/*
 * System-wide private data
 */
struct csched_private {
    spinlock_t lock;
    struct list_head active_sdom;
    uint32_t ncpus;
    struct timer  master_ticker;
    unsigned int master;
    cpumask_t idlers;
    cpumask_t cpus;
    uint32_t weight;
    uint32_t credit;
    int credit_balance;
    uint32_t runq_sort;
#ifdef HETERO_VISOR
	struct list_head dom_priority_list;
    uint32_t eweight;
#endif
};

static void csched_tick(void *_cpu);
static void csched_acct(void *dummy);

static inline int
__vcpu_on_runq(struct csched_vcpu *svc)
{
    return !list_empty(&svc->runq_elem);
}

static inline struct csched_vcpu *
__runq_elem(struct list_head *elem)
{
    return list_entry(elem, struct csched_vcpu, runq_elem);
}

static inline void
__runq_insert(unsigned int cpu, struct csched_vcpu *svc)
{
    const struct list_head * const runq = RUNQ(cpu);
    struct list_head *iter;

    BUG_ON( __vcpu_on_runq(svc) );
    BUG_ON( cpu != svc->vcpu->processor );

    list_for_each( iter, runq )
    {
        const struct csched_vcpu * const iter_svc = __runq_elem(iter);
        if ( svc->pri > iter_svc->pri )
            break;
    }

    /* If the vcpu yielded, try to put it behind one lower-priority
     * runnable vcpu if we can.  The next runq_sort will bring it forward
     * within 30ms if the queue too long. */
    if ( svc->flags & CSCHED_FLAG_VCPU_YIELD
         && __runq_elem(iter)->pri > CSCHED_PRI_IDLE )
    {
        iter=iter->next;

        /* Some sanity checks */
        BUG_ON(iter == runq);
    }

    list_add_tail(&svc->runq_elem, iter);
#ifdef ENABLE_MEASURE_UNBALANCE
#ifdef VERBOSE_MEASURE_UNBALANCE
	// credit scheduler also has some transient unbalanced states..., so don't worry about this so much.
	int f = -1,t = -1;
	if (mini_activated) {
		has_core_unbalance(&f, &t);
	}
#endif
	MYASSERT(svc->myprocessor == -1);
	svc->myprocessor = cpu;
	// don't use is_idle_vcpu() things. we're counting all vcpus including idle ones.
	// idle vcpu represent currently running vcpu, so number is correct still.
	if (atomic_read(&cacheman[proc2intcache[cpu]].vcpu_count)<0) {
		myprintk("BUG?? was negative ?\n");
	}
	if (atomic_inc_and_test(&cacheman[proc2intcache[cpu]].vcpu_count)) {
//		myprintk("BUG?? was -1?\n");
	}
#ifdef VERBOSE_MEASURE_UNBALANCE
	if (mini_activated) {
		int a = -1,b = -1;
		has_core_unbalance(&a, &b);
		if ((f==-1 && a!=-1))
			printk("Unbal:");
		if ((f!=-1 && a==-1))
			printk("Bal:");
	}
#endif
#endif
}

static inline void
__runq_remove(struct csched_vcpu *svc)
{
    BUG_ON( !__vcpu_on_runq(svc) );
    list_del_init(&svc->runq_elem);
#ifdef ENABLE_MEASURE_UNBALANCE
#ifdef VERBOSE_MEASURE_UNBALANCE
	int f = -1,t = -1;
	if (mini_activated) {
		has_core_unbalance(&f, &t);
	}
#endif
	// if svc==svc->myprocessor always, we can remove myprocesor
	BUG_ON(max_proc==0);
	BUG_ON(!(svc->myprocessor >=0 && svc->myprocessor < max_proc ));
	if (svc->myprocessor != svc->vcpu->processor)
		myprintk("They differ sometimes\n");
	if (atomic_read(&cacheman[proc2intcache[svc->myprocessor]].vcpu_count)<=0) {
		myprintk("BUG??? was <=0?? \n");
	}
	atomic_dec(&cacheman[proc2intcache[svc->myprocessor]].vcpu_count);
	svc->myprocessor = -1;
#ifdef VERBOSE_MEASURE_UNBALANCE
	if (mini_activated) {
		int a = -1,b = -1;
		has_core_unbalance(&a, &b);
		if ((f==-1 && a!=-1))
			printk("Unbal:");
		if ((f!=-1 && a==-1))
			printk("Bal:");
	}
#endif
#endif
}

static void burn_credits(struct csched_vcpu *svc, s_time_t now)
{
    s_time_t delta;
    unsigned int credits;

#ifdef HETERO_VISOR
	uint64_t mytime, mysec;
	rdtscll(mytime);
	mysec = tsc_ticks2ns(mytime)/1000000;
#endif
    /* Assert svc is current */
    ASSERT(svc==CSCHED_VCPU(per_cpu(schedule_data, svc->vcpu->processor).curr));

    if ( (delta = now - svc->start_time) <= 0 )
        return;

    credits = (delta*CSCHED_CREDITS_PER_MSEC + MILLISECS(1)/2) / MILLISECS(1);
    atomic_sub(credits, &svc->credit);
    svc->start_time += (credits * MILLISECS(1)) / CSCHED_CREDITS_PER_MSEC;
#ifdef HETERO_VISOR
	if(hetero_visor_active)
	{
		if( svc->core_type == SMALL)
			atomic_sub(credits, &svc->scredit);
		else
			atomic_sub(credits, &svc->fcredit);

		if(hetero_debug_level >= 2)
			printk("%lu [burn_credits] vcpu:%d %d %d %d %d %d\n",mysec,svc->vcpu->vcpu_id,svc->vcpu->domain->domain_id,svc->vcpu->processor,credits,atomic_read(&svc->scredit),atomic_read(&svc->fcredit));
	}
#endif
}

static bool_t __read_mostly opt_tickle_one_idle = 1;
boolean_param("tickle_one_idle_cpu", opt_tickle_one_idle);

DEFINE_PER_CPU(unsigned int, last_tickle_cpu);

static inline void
__runq_tickle(unsigned int cpu, struct csched_vcpu *new)
{
    struct csched_vcpu * const cur =
        CSCHED_VCPU(per_cpu(schedule_data, cpu).curr);
    struct csched_private *prv = CSCHED_PRIV(per_cpu(scheduler, cpu));
    cpumask_t mask;

    ASSERT(cur);
    cpus_clear(mask);

    /* If strictly higher priority than current VCPU, signal the CPU */
    if ( new->pri > cur->pri )
    {
        if ( cur->pri == CSCHED_PRI_IDLE )
            CSCHED_STAT_CRANK(tickle_local_idler);
        else if ( cur->pri == CSCHED_PRI_TS_OVER )
            CSCHED_STAT_CRANK(tickle_local_over);
        else if ( cur->pri == CSCHED_PRI_TS_UNDER )
            CSCHED_STAT_CRANK(tickle_local_under);
        else
            CSCHED_STAT_CRANK(tickle_local_other);

        cpu_set(cpu, mask);
    }

    /*
     * If this CPU has at least two runnable VCPUs, we tickle any idlers to
     * let them know there is runnable work in the system...
     */
    if ( cur->pri > CSCHED_PRI_IDLE )
    {
        if ( cpus_empty(prv->idlers) )
        {
            CSCHED_STAT_CRANK(tickle_idlers_none);
        }
        else
        {
            cpumask_t idle_mask;

            cpus_and(idle_mask, prv->idlers, new->vcpu->cpu_affinity);
            if ( !cpus_empty(idle_mask) )
            {
                CSCHED_STAT_CRANK(tickle_idlers_some);
                if ( opt_tickle_one_idle )
                {
                    this_cpu(last_tickle_cpu) = 
                        cycle_cpu(this_cpu(last_tickle_cpu), idle_mask);
                    cpu_set(this_cpu(last_tickle_cpu), mask);
                }
                else
                    cpus_or(mask, mask, idle_mask);
            }
            cpus_and(mask, mask, new->vcpu->cpu_affinity);
        }
    }

    /* Send scheduler interrupts to designated CPUs */
    if ( !cpus_empty(mask) )
        cpumask_raise_softirq(mask, SCHEDULE_SOFTIRQ);
}

static void
csched_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    struct csched_private *prv = CSCHED_PRIV(ops);
    struct csched_pcpu *spc = pcpu;
    unsigned long flags;

    if ( spc == NULL )
        return;

    spin_lock_irqsave(&prv->lock, flags);

    prv->credit -= CSCHED_CREDITS_PER_ACCT;
    prv->ncpus--;
    cpu_clear(cpu, prv->idlers);
    cpu_clear(cpu, prv->cpus);
    if ( (prv->master == cpu) && (prv->ncpus > 0) )
    {
        prv->master = first_cpu(prv->cpus);
        migrate_timer(&prv->master_ticker, prv->master);
    }
    kill_timer(&spc->ticker);
    if ( prv->ncpus == 0 )
        kill_timer(&prv->master_ticker);

    spin_unlock_irqrestore(&prv->lock, flags);

    xfree(spc);
}

static void *
csched_alloc_pdata(const struct scheduler *ops, int cpu)
{
    struct csched_pcpu *spc;
    struct csched_private *prv = CSCHED_PRIV(ops);
    unsigned long flags;

    /* Allocate per-PCPU info */
    spc = xmalloc(struct csched_pcpu);
    if ( spc == NULL )
        return NULL;
    memset(spc, 0, sizeof(*spc));

    spin_lock_irqsave(&prv->lock, flags);

    /* Initialize/update system-wide config */
    prv->credit += CSCHED_CREDITS_PER_ACCT;
    prv->ncpus++;
    cpu_set(cpu, prv->cpus);
    if ( prv->ncpus == 1 )
    {
        prv->master = cpu;
        init_timer(&prv->master_ticker, csched_acct, prv, cpu);
        set_timer(&prv->master_ticker, NOW() +
                  MILLISECS(CSCHED_MSECS_PER_TICK) * CSCHED_TICKS_PER_ACCT);
    }

    init_timer(&spc->ticker, csched_tick, (void *)(unsigned long)cpu, cpu);
    set_timer(&spc->ticker, NOW() + MILLISECS(CSCHED_MSECS_PER_TICK));

    INIT_LIST_HEAD(&spc->runq);
    spc->runq_sort_last = prv->runq_sort;
    spc->idle_bias = NR_CPUS - 1;
    if ( per_cpu(schedule_data, cpu).sched_priv == NULL )
        per_cpu(schedule_data, cpu).sched_priv = spc;

#ifdef ENABLE_PCPU_STAT
	spc->start_time = 0;
	spc->sched_time = 0;
#endif

    /* Start off idling... */
    BUG_ON(!is_idle_vcpu(per_cpu(schedule_data, cpu).curr));
    cpu_set(cpu, prv->idlers);

    spin_unlock_irqrestore(&prv->lock, flags);

    return spc;
}

#ifndef NDEBUG
static inline void
__csched_vcpu_check(struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    struct csched_dom * const sdom = svc->sdom;

    BUG_ON( svc->vcpu != vc );
    BUG_ON( sdom != CSCHED_DOM(vc->domain) );
    if ( sdom )
    {
        BUG_ON( is_idle_vcpu(vc) );
        BUG_ON( sdom->dom != vc->domain );
    }
    else
    {
        BUG_ON( !is_idle_vcpu(vc) );
    }

    CSCHED_STAT_CRANK(vcpu_check);
}
#define CSCHED_VCPU_CHECK(_vc)  (__csched_vcpu_check(_vc))
#else
#define CSCHED_VCPU_CHECK(_vc)
#endif

/*
 * Delay, in microseconds, between migrations of a VCPU between PCPUs.
 * This prevents rapid fluttering of a VCPU between CPUs, and reduces the
 * implicit overheads such as cache-warming. 1ms (1000) has been measured
 * as a good value.
 */
static unsigned int vcpu_migration_delay;
integer_param("vcpu_migration_delay", vcpu_migration_delay);

void set_vcpu_migration_delay(unsigned int delay)
{
    vcpu_migration_delay = delay;
}

unsigned int get_vcpu_migration_delay(void)
{
    return vcpu_migration_delay;
}

static inline int
__csched_vcpu_is_cache_hot(struct vcpu *v)
{
    int hot = ((NOW() - v->last_run_time) <
               ((uint64_t)vcpu_migration_delay * 1000u));

    if ( hot )
        CSCHED_STAT_CRANK(vcpu_hot);

    return hot;
}

static inline int
__csched_vcpu_is_migrateable(struct vcpu *vc, int dest_cpu)
{
    /*
     * Don't pick up work that's in the peer's scheduling tail or hot on
     * peer PCPU. Only pick up work that's allowed to run on our CPU.
     */
    return !vc->is_running &&
           !__csched_vcpu_is_cache_hot(vc) &&
           cpu_isset(dest_cpu, vc->cpu_affinity);
}

static int
_csched_cpu_pick(const struct scheduler *ops, struct vcpu *vc, bool_t commit)
{
    cpumask_t cpus;
    cpumask_t idlers;
    cpumask_t *online;
    int cpu;

    /*
     * Pick from online CPUs in VCPU's affinity mask, giving a
     * preference to its current processor if it's in there.
     */
    online = CSCHED_CPUONLINE(vc->domain->cpupool);
    cpus_and(cpus, *online, vc->cpu_affinity);
#ifdef ENABLE_PAGE_TOUCH
	// implementing uschedule
	struct page_dir *pgd = vc->current_pgd;
	int cache = vc->dest_cache;
//	char temp[512];
	if (cache != -1) {
		MYASSERT(pgd);
		ASSERT(cache >=0 && cache < MAX_CACHE );
//	cpumask_scnprintf(temp, 511, cpus);
//	myprintk("ori cpus:%s \n", temp);
		cpus_and(cpus, cpus, cache2cpumask[cache] );
		// dest_cache will be cleared at vcpu_migrate at schedule.c
	}
#endif
    cpu = cpu_isset(vc->processor, cpus)
            ? vc->processor
            : cycle_cpu(vc->processor, cpus);
    ASSERT( !cpus_empty(cpus) && cpu_isset(cpu, cpus) );

    /*
     * Try to find an idle processor within the above constraints.
     *
     * In multi-core and multi-threaded CPUs, not all idle execution
     * vehicles are equal!
     *
     * We give preference to the idle execution vehicle with the most
     * idling neighbours in its grouping. This distributes work across
     * distinct cores first and guarantees we don't do something stupid
     * like run two VCPUs on co-hyperthreads while there are idle cores
     * or sockets.
     */
    cpus_and(idlers, cpu_online_map, CSCHED_PRIV(ops)->idlers);

#ifdef ENABLE_PAGE_TOUCH
	if (cache != -1) {	// usched will prefer idle cpus
	    cpus_and(cpus, cpus, idlers);
	    if (!cpus_empty(cpus)) {
		    cpu = cpu_isset(vc->processor, cpus)
		            ? vc->processor
		            : cycle_cpu(vc->processor, cpus);
		    cpu_clear(cpu, cpus);
	    }
	} else {	// awakened vcpu prefers its previous cpu
#endif
    cpu_set(cpu, idlers);
    cpus_and(cpus, cpus, idlers);
    cpu_clear(cpu, cpus);
#ifdef ENABLE_PAGE_TOUCH
	}
#endif
#if 0
// distribute.. even memlat runs equally on cores...
if (!cpus_empty(cpus))
cpu = cycle_cpu(cpu, cpus);
return cpu;
#endif
    while ( !cpus_empty(cpus) )
    {
        cpumask_t cpu_idlers;
        cpumask_t nxt_idlers;
        int nxt, weight_cpu, weight_nxt;
        int migrate_factor;

        nxt = cycle_cpu(cpu, cpus);

        if ( cpu_isset(cpu, per_cpu(cpu_core_map, nxt)) )
        {
            /* We're on the same socket, so check the busy-ness of threads.
             * Migrate if # of idlers is less at all */
            ASSERT( cpu_isset(nxt, per_cpu(cpu_core_map, cpu)) );
            migrate_factor = 1;
            cpus_and(cpu_idlers, idlers, per_cpu(cpu_sibling_map, cpu));
            cpus_and(nxt_idlers, idlers, per_cpu(cpu_sibling_map, nxt));
        }
        else
        {
            /* We're on different sockets, so check the busy-ness of cores.
             * Migrate only if the other core is twice as idle */
            ASSERT( !cpu_isset(nxt, per_cpu(cpu_core_map, cpu)) );
            migrate_factor = 2;
            cpus_and(cpu_idlers, idlers, per_cpu(cpu_core_map, cpu));
            cpus_and(nxt_idlers, idlers, per_cpu(cpu_core_map, nxt));
        }

        weight_cpu = cpus_weight(cpu_idlers);
        weight_nxt = cpus_weight(nxt_idlers);
        /* smt_power_savings: consolidate work rather than spreading it */
        if ( ( sched_smt_power_savings
               && (weight_cpu > weight_nxt) )
             || ( !sched_smt_power_savings
                  && (weight_cpu * migrate_factor < weight_nxt) ) )
        {
            cpus_and(nxt_idlers, cpus, nxt_idlers);
            cpu = cycle_cpu(CSCHED_PCPU(nxt)->idle_bias, nxt_idlers);
            if ( commit )
               CSCHED_PCPU(nxt)->idle_bias = cpu;
            cpus_andnot(cpus, cpus, per_cpu(cpu_sibling_map, cpu));
        }
        else
        {
            cpus_andnot(cpus, cpus, nxt_idlers);
        }
    }
    return cpu;
}

static int
csched_cpu_pick(const struct scheduler *ops, struct vcpu *vc)
{
    return _csched_cpu_pick(ops, vc, 1);
}

static inline void
__csched_vcpu_acct_start(struct csched_private *prv, struct csched_vcpu *svc)
{
    struct csched_dom * const sdom = svc->sdom;
    unsigned long flags;

    spin_lock_irqsave(&prv->lock, flags);

    if ( list_empty(&svc->active_vcpu_elem) )
    {
        CSCHED_VCPU_STAT_CRANK(svc, state_active);
        CSCHED_STAT_CRANK(acct_vcpu_active);

        sdom->active_vcpu_count++;
        list_add(&svc->active_vcpu_elem, &sdom->active_vcpu);
        /* Make weight per-vcpu */
        prv->weight += sdom->weight;
        if ( list_empty(&sdom->active_sdom_elem) )
        {
            list_add(&sdom->active_sdom_elem, &prv->active_sdom);
        }
    }

    spin_unlock_irqrestore(&prv->lock, flags);
}

static inline void
__csched_vcpu_acct_stop_locked(struct csched_private *prv,
    struct csched_vcpu *svc)
{
    struct csched_dom * const sdom = svc->sdom;

    BUG_ON( list_empty(&svc->active_vcpu_elem) );

    CSCHED_VCPU_STAT_CRANK(svc, state_idle);
    CSCHED_STAT_CRANK(acct_vcpu_idle);

    BUG_ON( prv->weight < sdom->weight );
    sdom->active_vcpu_count--;
    list_del_init(&svc->active_vcpu_elem);
    prv->weight -= sdom->weight;
    if ( list_empty(&sdom->active_vcpu) )
    {
        list_del_init(&sdom->active_sdom_elem);
    }
}

static void
csched_vcpu_acct(struct csched_private *prv, unsigned int cpu)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(current);
    const struct scheduler *ops = per_cpu(scheduler, cpu);

    ASSERT( current->processor == cpu );
    ASSERT( svc->sdom != NULL );

    /*
     * If this VCPU's priority was boosted when it last awoke, reset it.
     * If the VCPU is found here, then it's consuming a non-negligeable
     * amount of CPU resources and should no longer be boosted.
     */
    if ( svc->pri == CSCHED_PRI_TS_BOOST )
        svc->pri = CSCHED_PRI_TS_UNDER;

    /*
     * Update credits
     */
    if ( !is_idle_vcpu(svc->vcpu) )
        burn_credits(svc, NOW());

    /*
     * Put this VCPU and domain back on the active list if it was
     * idling.
     *
     * If it's been active a while, check if we'd be better off
     * migrating it to run elsewhere (see multi-core and multi-thread
     * support in csched_cpu_pick()).
     */
    if ( list_empty(&svc->active_vcpu_elem) )
    {
        __csched_vcpu_acct_start(prv, svc);
    }
    else if ( _csched_cpu_pick(ops, current, 0) != cpu )
    {
        CSCHED_VCPU_STAT_CRANK(svc, migrate_r);
        CSCHED_STAT_CRANK(migrate_running);
        set_bit(_VPF_migrating, &current->pause_flags);
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    }
}

static void *
csched_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct csched_vcpu *svc;

    /* Allocate per-VCPU info */
    svc = xmalloc(struct csched_vcpu);
    if ( svc == NULL )
        return NULL;
    memset(svc, 0, sizeof(*svc));

#ifdef ENABLE_BINPACKING
	svc->last_passed = 1;
	svc->diff_passed = 0;
	svc->count_passed = 0;
	svc->count_cosched = 0;
#endif
#ifdef ENABLE_MEASURE_UNBALANCE
	svc->myprocessor = -1;
#endif
    INIT_LIST_HEAD(&svc->runq_elem);
    INIT_LIST_HEAD(&svc->active_vcpu_elem);
    svc->sdom = dd;
    svc->vcpu = vc;
    atomic_set(&svc->credit, 0);
#ifdef HETERO_VISOR
    atomic_set(&svc->scredit, 0);
	atomic_set(&svc->fcredit, 0);
	svc->core_type = 0;
    svc->ctr = xmalloc(struct counters);
    svc->pctr = xmalloc(struct perf_ctrs);
	svc->ctr->last_update = 0;
    INIT_LIST_HEAD(&svc->fast_vcpu_elem);
    INIT_LIST_HEAD(&svc->hetero_vcpu_elem);
#endif
    svc->flags = 0U;
    svc->pri = is_idle_domain(vc->domain) ?
        CSCHED_PRI_IDLE : CSCHED_PRI_TS_UNDER;
    CSCHED_VCPU_STATS_RESET(svc);
    CSCHED_STAT_CRANK(vcpu_init);
    return svc;
}

static void
csched_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu *svc = vc->sched_priv;

    if ( !__vcpu_on_runq(svc) && vcpu_runnable(vc) && !vc->is_running )
        __runq_insert(vc->processor, svc);
}

static void
csched_free_vdata(const struct scheduler *ops, void *priv)
{
    struct csched_vcpu *svc = priv;

    BUG_ON( !list_empty(&svc->runq_elem) );

    xfree(svc);
}

static void
csched_vcpu_remove(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_private *prv = CSCHED_PRIV(ops);
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    struct csched_dom * const sdom = svc->sdom;
    unsigned long flags;

    CSCHED_STAT_CRANK(vcpu_destroy);

    if ( __vcpu_on_runq(svc) )
        __runq_remove(svc);

    spin_lock_irqsave(&(prv->lock), flags);

    if ( !list_empty(&svc->active_vcpu_elem) )
        __csched_vcpu_acct_stop_locked(prv, svc);

    spin_unlock_irqrestore(&(prv->lock), flags);

    BUG_ON( sdom == NULL );
    BUG_ON( !list_empty(&svc->runq_elem) );
}

static void
csched_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);

    CSCHED_STAT_CRANK(vcpu_sleep);

    BUG_ON( is_idle_vcpu(vc) );
#ifdef VERBOSE_USCHED_DETAIL
	if (vc->dest_cache != -1) {
//		myprintk("csched_vcpu_sleep\n");
		MYASSERT( per_cpu(schedule_data, vc->processor).curr == vc );
	}
#endif

    if ( per_cpu(schedule_data, vc->processor).curr == vc )
        cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
    else if ( __vcpu_on_runq(svc) )
        __runq_remove(svc);
}

static void
csched_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    const unsigned int cpu = vc->processor;

    BUG_ON( is_idle_vcpu(vc) );

    if ( unlikely(per_cpu(schedule_data, cpu).curr == vc) )
    {
        CSCHED_STAT_CRANK(vcpu_wake_running);
        return;
    }
    if ( unlikely(__vcpu_on_runq(svc)) )
    {
        CSCHED_STAT_CRANK(vcpu_wake_onrunq);
        return;
    }

    if ( likely(vcpu_runnable(vc)) )
        CSCHED_STAT_CRANK(vcpu_wake_runnable);
    else
        CSCHED_STAT_CRANK(vcpu_wake_not_runnable);

    /*
     * We temporarly boost the priority of awaking VCPUs!
     *
     * If this VCPU consumes a non negligeable amount of CPU, it
     * will eventually find itself in the credit accounting code
     * path where its priority will be reset to normal.
     *
     * If on the other hand the VCPU consumes little CPU and is
     * blocking and awoken a lot (doing I/O for example), its
     * priority will remain boosted, optimizing it's wake-to-run
     * latencies.
     *
     * This allows wake-to-run latency sensitive VCPUs to preempt
     * more CPU resource intensive VCPUs without impacting overall 
     * system fairness.
     *
     * The one exception is for VCPUs of capped domains unpausing
     * after earning credits they had overspent. We don't boost
     * those.
     */
#if 1
    if ( svc->pri == CSCHED_PRI_TS_UNDER &&
         !(svc->flags & CSCHED_FLAG_VCPU_PARKED) )
    {
        svc->pri = CSCHED_PRI_TS_BOOST;
    }
#endif

    /* Put the VCPU on the runq and tickle CPUs */
    __runq_insert(cpu, svc);
    __runq_tickle(cpu, svc);
}

static void
csched_vcpu_yield(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const sv = CSCHED_VCPU(vc);

    if ( !sched_credit_default_yield )
    {
        /* Let the scheduler know that this vcpu is trying to yield */
        sv->flags |= CSCHED_FLAG_VCPU_YIELD;
    }
}

static int
csched_dom_cntl(
    const struct scheduler *ops,
    struct domain *d,
    struct xen_domctl_scheduler_op *op)
{
    struct csched_dom * const sdom = CSCHED_DOM(d);
    struct csched_private *prv = CSCHED_PRIV(ops);
    unsigned long flags;

    if ( op->cmd == XEN_DOMCTL_SCHEDOP_getinfo )
    {
        op->u.credit.weight = sdom->weight;
        op->u.credit.cap = sdom->cap;
    }
    else
    {
        ASSERT(op->cmd == XEN_DOMCTL_SCHEDOP_putinfo);

        spin_lock_irqsave(&prv->lock, flags);

        if ( op->u.credit.weight != 0 )
        {
            if ( !list_empty(&sdom->active_sdom_elem) )
            {
                prv->weight -= sdom->weight * sdom->active_vcpu_count;
                prv->weight += op->u.credit.weight * sdom->active_vcpu_count;
            }
            sdom->weight = op->u.credit.weight;
        }

        if ( op->u.credit.cap != (uint16_t)~0U )
            sdom->cap = op->u.credit.cap;

        spin_unlock_irqrestore(&prv->lock, flags);
    }

    return 0;
}

static void *
csched_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    struct csched_dom *sdom;

    sdom = xmalloc(struct csched_dom);
    if ( sdom == NULL )
        return NULL;
    memset(sdom, 0, sizeof(*sdom));

    /* Initialize credit and weight */
    INIT_LIST_HEAD(&sdom->active_vcpu);
    sdom->active_vcpu_count = 0;
    INIT_LIST_HEAD(&sdom->active_sdom_elem);
    sdom->dom = dom;
    sdom->weight = CSCHED_DEFAULT_WEIGHT;
    sdom->cap = 0U;
#ifdef HETERO_VISOR
    sdom->scap = 0U;
    sdom->fcap = 0U;
	sdom->fast_vcpu_count = 0;
	sdom->hetero_sched_done = 0;
	sdom->estate = 0;
	sdom->eweight = sdom->weight;
	sdom->elastic_speed=100;
	sdom->guest_speed=100;
	sdom->epriority = 1;
	sdom->vcpu_count = 1;
    INIT_LIST_HEAD(&sdom->fast_vcpu);
    INIT_LIST_HEAD(&sdom->hetero_vcpu);
#endif

    return (void *)sdom;
}

static int
csched_dom_init(const struct scheduler *ops, struct domain *dom)
{
    struct csched_dom *sdom;

    CSCHED_STAT_CRANK(dom_init);

    if ( is_idle_domain(dom) )
        return 0;

    sdom = csched_alloc_domdata(ops, dom);
    if ( sdom == NULL )
        return -ENOMEM;

    dom->sched_priv = sdom;

    return 0;
}

static void
csched_free_domdata(const struct scheduler *ops, void *data)
{
    xfree(data);
}

static void
csched_dom_destroy(const struct scheduler *ops, struct domain *dom)
{
    CSCHED_STAT_CRANK(dom_destroy);
    csched_free_domdata(ops, CSCHED_DOM(dom));
}

/*
 * This is a O(n) optimized sort of the runq.
 *
 * Time-share VCPUs can only be one of two priorities, UNDER or OVER. We walk
 * through the runq and move up any UNDERs that are preceded by OVERS. We
 * remember the last UNDER to make the move up operation O(1).
 */
static void
csched_runq_sort(struct csched_private *prv, unsigned int cpu)
{
    struct csched_pcpu * const spc = CSCHED_PCPU(cpu);
    struct list_head *runq, *elem, *next, *last_under;
    struct csched_vcpu *svc_elem;
    unsigned long flags;
    int sort_epoch;

    sort_epoch = prv->runq_sort;
    if ( sort_epoch == spc->runq_sort_last )
        return;

    spc->runq_sort_last = sort_epoch;

    pcpu_schedule_lock_irqsave(cpu, flags);

    runq = &spc->runq;
    elem = runq->next;
    last_under = runq;

    while ( elem != runq )
    {
        next = elem->next;
        svc_elem = __runq_elem(elem);

        if ( svc_elem->pri >= CSCHED_PRI_TS_UNDER )
        {
            /* does elem need to move up the runq? */
            if ( elem->prev != last_under )
            {
                list_del(elem);
                list_add(elem, last_under);
            }
            last_under = elem;
        }

        elem = next;
    }

    pcpu_schedule_unlock_irqrestore(cpu, flags);
}

#ifdef HETERO_VISOR
static inline void list_rotate_left(struct list_head *head)
{
        struct list_head *first;

        if (!list_empty(head)) {
                first = head->next;
                list_move_tail(first, head);
        }
}

void hetero_sched_balance(void){
	struct domain *d;
	/*struct vcpu *v;*/
	struct csched_vcpu *svc = NULL;
	struct csched_dom *sdom;
	uint64_t mytime, mysec;
	cpumask_t coremask;
	/*int fast_vcpu_count = 0;*/
	struct list_head *iter_vcpu;

	rdtscll(mytime);
	mysec = tsc_ticks2ns(mytime)/1000000;

	if(hetero_sched_active){
	for_each_domain( d )
	{
		sdom = CSCHED_DOM(d);
		if (d->domain_id > 0)
		{
			//initialize
			if(!sdom->hetero_sched_done) 
				fast_vcpu_list(d,1,0);

			//remove first vcpu from fast vcpu list
			if(sdom->fast_vcpu_count < sdom->vcpu_count)//check if all vcpus are fast vcpus
			{
			list_for_each( iter_vcpu, &sdom->hetero_vcpu)
			{
				svc = list_entry(iter_vcpu, struct csched_vcpu,hetero_vcpu_elem);

				//this vcpu should not be already on fast vcpu list
				if(!list_empty(&svc->fast_vcpu_elem))
					printk("BUG %s %d\n",__FILE__,__LINE__);
				BUG_ON(!list_empty(&svc->fast_vcpu_elem));
				break;
			}
			if(svc){
				coremask = bigcore_mask;
				svc->core_type = BIG;
				hetero_vcpu_migrate(svc->vcpu, &coremask);
				list_add_tail(&svc->fast_vcpu_elem, &sdom->fast_vcpu);

				//rotate hetero vcpu list for added vcpu
				list_rotate_left(&sdom->hetero_vcpu);
			}
			/*if(hetero_debug_level >= 1)*/
			/*printk("add:%d ",svc->vcpu->vcpu_id);*/

			//add first cpu from hetero vcpu list to fast vcpu list
			list_for_each( iter_vcpu, &sdom->fast_vcpu)
			{
				svc = list_entry(iter_vcpu, struct csched_vcpu, fast_vcpu_elem);
				break;
			}

			if(svc){
				coremask = smallcore_mask;
				svc->core_type = SMALL;
				hetero_vcpu_migrate(svc->vcpu, &coremask);
				list_del_init(&svc->fast_vcpu_elem);
			}
			/*if(hetero_debug_level >= 1)*/
			/*printk("del:%d\n",svc->vcpu->vcpu_id);*/
			}

			if(hetero_debug_level >= 1){
				printk("%lu fast vcpu list:",mysec);
				list_for_each( iter_vcpu,&sdom->fast_vcpu)
				{
					svc = list_entry(iter_vcpu, struct csched_vcpu,fast_vcpu_elem);
					printk("%d ",svc->vcpu->vcpu_id);
				}
				printk("\n");
			}
		}
	}
	}
}

void update_priority_list(void){
	int cpu = 0;
	struct domain *d;
	struct csched_dom *sdom;
	struct csched_private *prv = CSCHED_PRIV(per_cpu(scheduler, cpu));
	struct csched_dom *qsdom;
	struct list_head *iter_sdom;

	INIT_LIST_HEAD(&prv->dom_priority_list);

	for_each_domain( d )
	{
		if(d->domain_id > 0){
		sdom = CSCHED_DOM(d);
		INIT_LIST_HEAD(&sdom->dom_priority_elem);

		if(!list_empty(&prv->dom_priority_list)){
			list_for_each( iter_sdom, &prv->dom_priority_list)
			{
				qsdom = list_entry(iter_sdom, struct csched_dom, dom_priority_elem);
				if(sdom->epriority >= qsdom->epriority){ 
					break;
				}
			}
			list_add_tail(&sdom->dom_priority_elem, iter_sdom);
			/*printk(" Adding %d before %d\n",sdom->dom->domain_id,qsdom->dom->domain_id);*/
		}
		else{
			/*printk(" Adding to empty list %d\n",sdom->dom->domain_id);*/
			list_add(&sdom->dom_priority_elem, &prv->dom_priority_list);
		}
		}
	}

	if(hetero_debug_level >= 0){
		printk("Priority dom list:");
		list_for_each( iter_sdom, &prv->dom_priority_list)
		{
			sdom = list_entry(iter_sdom, struct csched_dom, dom_priority_elem);
			printk(" %d",sdom->dom->domain_id);
		}
		printk("\n");
	}
}

/*//redistribute hetero credits */
void redist_hcredits(void){
	struct domain *d;
	/*struct vcpu *v;*/
	/*struct csched_vcpu *svc;*/
	struct csched_dom *sdom;
	uint64_t mytime, mysec;
	int scredits_left = TOTAL_SCREDITS;
	int fcredits_left = TOTAL_FCREDITS;
	int cpu = 0;
	struct csched_private *prv = CSCHED_PRIV(per_cpu(scheduler, cpu));
	struct list_head *iter_sdom;
	uint32_t pspeed = 0;
	uint16_t fcount = 0;
	uint16_t num_small_cores = num_active_cpus - big_core_count;

	rdtscll(mytime);
	mysec = tsc_ticks2ns(mytime)/1000000;

	if(hetero_hcredit_policy == 1){
		prv->eweight = 0;
		list_for_each( iter_sdom, &prv->dom_priority_list)
		{
			sdom = list_entry(iter_sdom, struct csched_dom, dom_priority_elem);

			if(sdom->dom->domain_id > 0)
			{
				fcount = sdom->fast_vcpu_count;

				if(num_small_cores >= sdom->vcpu_count){
				//only small cores needed
				if(sdom->guest_speed <= 100)
				{
					sdom->fcap = 0U;
					sdom->scap = sdom->guest_speed;
					sdom->scap = sdom->vcpu_count *sdom->guest_speed;
					sdom->fast_vcpu_count = 0;
					/*sdom->scap =  min(SCREDITS_MAX, sdom->scap);*/
					/*sdom->scap =  min(scredits_left, sdom->scap);*/
					/*sdom->scap =  max(HCREDITS_MIN, sdom->scap);*/
				}
				else//use big cores + small cores
				{
					BUG_ON(big_core_count == 0);
					//TODO VG fix this
					//(v * (p - 1) + normalization)/(S-1) <= n_f
					pspeed = ((sdom->vcpu_count * (sdom->guest_speed - 100))+(100*(hetero_speed_ratio-1)-1));
					sdom->fast_vcpu_count = pspeed/(100*(hetero_speed_ratio-1));

					WARN_ON(sdom->fast_vcpu_count > big_core_count);

					if(sdom->fast_vcpu_count > big_core_count)
					{
						sdom->fast_vcpu_count = big_core_count;
					}
				
					// uf = (v (p -1 ) + nf)/ S* nf
					sdom->fcap = ((sdom->vcpu_count * (sdom->guest_speed - 100))+100*sdom->fast_vcpu_count)/(hetero_speed_ratio*sdom->fast_vcpu_count);
					sdom->fcap = sdom->fcap*sdom->fast_vcpu_count;

					sdom->scap = 100;//unlimited cap on small cores
					sdom->scap = 100*(sdom->vcpu_count - sdom->fast_vcpu_count);//unlimited cap on small cores
				}
			}
			else{
				if(sdom->guest_speed <= (100*num_small_cores)/sdom->vcpu_count)
				{
					sdom->fcap = 0U;
					sdom->scap = (sdom->guest_speed*sdom->vcpu_count)/num_small_cores;
					sdom->scap = sdom->vcpu_count *sdom->guest_speed;
					sdom->fast_vcpu_count = 0;
				}
				else
				{
					BUG_ON(big_core_count == 0);

					sdom->fast_vcpu_count = sdom->vcpu_count - num_small_cores;
					//(v * (p - 1) + normalization)/(S-1) <= n_f
					pspeed = ((sdom->vcpu_count * sdom->guest_speed - 100*num_small_cores))+(100*(hetero_speed_ratio)-1);
					sdom->fast_vcpu_count = pspeed/(100*(hetero_speed_ratio));
					/*sdom->fast_vcpu_count = sdom->vcpu_count - num_small_cores;*/

					WARN_ON(sdom->fast_vcpu_count > big_core_count);

					if(sdom->fast_vcpu_count > big_core_count)
					{
						sdom->fast_vcpu_count = big_core_count;
					}
				

					/*pspeed = ((sdom->vcpu_count * (sdom->guest_speed - 100))+(100*(hetero_speed_ratio-1)-1));*/
					pspeed = ((sdom->vcpu_count * sdom->guest_speed - 100*num_small_cores));
					sdom->fcap = pspeed/(hetero_speed_ratio);
					/*sdom->fcap = 	((sdom->vcpu_count * sdom->guest_speed)  - (100 * num_small_cores))/(hetero_speed_ratio*sdom->fast_vcpu_count);*/
					/*sdom->fcap = sdom->fcap*sdom->fast_vcpu_count;*/

					/*sdom->scap = 100;//unlimited cap on small cores*/
					sdom->scap = (num_small_cores*100);//unlimited cap on small cores
				}
						
				}
					sdom->scap =  min(scredits_left, sdom->scap);
					sdom->fcap =  min(fcredits_left, sdom->fcap);
					scredits_left -= sdom->scap;
					fcredits_left -= sdom->fcap;
					sdom->elastic_speed = sdom->guest_speed;//TODO VG fix this


				//update fast vcpu list if change in number of fast cores
				if(fcount != sdom->fast_vcpu_count)
					fast_vcpu_list(sdom->dom,0,fcount);

				prv->eweight += sdom->eweight;
			}

		}
	}
	if(hetero_debug_level >= 1)
	{
		printk("%lu [redist_hcredit]:",mysec);
		for_each_domain( d )
		{
			sdom = CSCHED_DOM(d);
			printk("Dom:%d %d %d %d %d ",sdom->dom->domain_id,sdom->elastic_speed,sdom->fast_vcpu_count,sdom->scap,sdom->fcap);
		}
		printk("\n");
	}
}

uint64_t perfctr_update = 0;
//reset perf counters if no activitiy
static void reset_perf_counters(void){
	struct domain *d;
	struct vcpu *v;
	struct csched_vcpu * svc;
	uint64_t mytime, diff_tsc;

	rdtscll(mytime);
	diff_tsc = mytime - perfctr_update;
	/*if(tsc_ticks2ns(diff_tsc)/1000000>= PCTR_TICK_COUNT*CSCHED_MSECS_PER_TSLICE)*/
	{
	for_each_domain( d )
	{
		if(d->domain_id > 0){
		for_each_vcpu( d, v )
		{
				svc = CSCHED_VCPU(v);

				//set counters periodically
				svc->pctr->instns = svc->ctr->dinst;
				/*svc->pctr->util = calc_pct_metric(svc->ctr->dmperf,(diff_tsc));*/
				svc->pctr->active = svc->ctr->dmperf;
				svc->pctr->lmisses = svc->ctr->dlmisses*1000;
				svc->pctr->rmisses = svc->ctr->drmisses;
				svc->pctr->cycles = diff_tsc;
				/*if(svc->pctr->cycles == 0)*/
				/*svc->pctr->cycles  = 1;*/
				svc->pctr->core_type = svc->core_type;
				/*printk("%lu %lu Updating counters:%d %d %d %d %lu %lu %hu %hu\n",mytime,svc->last_update,svc->vcpu->vcpu_id,svc->vcpu->domain->domain_id,snext->vcpu->vcpu_id,svc->vcpu->domain->domain_id,svc->dmperf,svc->dinst,svc->ipc,svc->util);*/

				//reset_counters
				svc->ctr->dinst = 0;
				svc->ctr->dcycles = 0;
				svc->ctr->dlmisses = 0;
				svc->ctr->drmisses = 0;
				svc->ctr->dmperf = 0;
				svc->ctr->dtsc = 0;
				rdtscll(perfctr_update);
		}
		}
	}
	}
}

static void print_heartbeat_msg(void){
	struct csched_dom * sdom;
	struct csched_vcpu * svc;
	struct domain *d;
	struct vcpu *v;
	/*uint16_t cpu;*/
	uint64_t mytime, mysec;
	rdtscll(mytime);
	mysec = tsc_ticks2ns(mytime)/1000000;

	if(hetero_debug_level >= 0)
		printk("%lu [het_vis] ",mysec);

	if(hetero_debug_level >= 0)
	{
	for_each_domain( d )
	{
			if(d->domain_id > 0)
			{
				sdom = CSCHED_DOM(d);
				printk("Dom:%d %d %d %d %d %d %d ",d->domain_id,sdom->guest_speed,sdom->elastic_speed,sdom->scap, sdom->fcap,sdom->vcpu_count,sdom->fast_vcpu_count);
			}

	}
	printk("\n");
	}
	if(hetero_debug_level >= 1)
	{
		for_each_domain( d )
		{
			if(d->domain_id > 0)
			{
				sdom = CSCHED_DOM(d);
				/*printk("Dom:%d Weight:%d cap:%d act:%d\n",d->domain_id,sdom->weight,sdom->cap,sdom->active_vcpu_count);*/
				printk("%lu DOM %d ",mysec,d->domain_id);
				for_each_vcpu( d, v )
				{
					svc = CSCHED_VCPU(v);
					/*printk("id:%d %d %d %lu %lu %lu %lu ",v->vcpu_id,svc->ipc, svc->util, svc->dinst,svc->dcycles,svc->dmperf,svc->dcycles);*/
					printk("id:%d %lu %lu %lu %lu ",v->vcpu_id,svc->pctr->instns, svc->pctr->active,svc->pctr->lmisses,svc->pctr->cycles);
				}
				printk("\n");
			}
		}

		/*svc = CSCHED_VCPU(per_cpu(schedule_data, cpu).curr);*/
		/*printk(KERN_INFO "HET: %ld %d %d CTR ",mysec,svc->vcpu->vcpu_id,svc->vcpu->domain->domain_id);*/

		/*printk(KERN_INFO "%lu [HV] ",mysec);*/
		/*for(cpu=0;cpu<num_present_cpus();cpu++)*/
		/*printk(KERN_INFO "%u %hu %hu:", cpu,per_cpu(core_ipc,cpu),per_cpu(core_c0,cpu));*/
		/*printk(KERN_INFO "\n");*/
	}
}

void update_perf_ctrs(struct csched_vcpu *scurr)
{
	uint64_t mytime, diff_tsc;

	if(!is_idle_vcpu(scurr->vcpu))
	{
		//update the counters
		update_counters_cpu(NULL);

		//update the per vcpu counters
		if(__get_cpu_var(core_type) == 0)//big/small
			scurr->ctr->dmperf += __get_cpu_var(dmperf) * hetero_speed_ratio;
		else
			scurr->ctr->dmperf += __get_cpu_var(dmperf);

		scurr->ctr->dtsc += __get_cpu_var(dtsc);
		scurr->ctr->dinst += __get_cpu_var(dinst);
		scurr->ctr->dcycles += __get_cpu_var(dcycles);
		scurr->ctr->dlmisses += __get_cpu_var(dlmisses);
		scurr->ctr->drmisses += __get_cpu_var(drmisses);
	}
}
#endif
static void
csched_acct(void* dummy)
{
    struct csched_private *prv = dummy;
    unsigned long flags;
    struct list_head *iter_vcpu, *next_vcpu;
    struct list_head *iter_sdom, *next_sdom;
    struct csched_vcpu *svc;
    struct csched_dom *sdom;
    uint32_t credit_total;
    uint32_t weight_total;
    uint32_t weight_left;
    uint32_t credit_fair;
    uint32_t credit_peak;
    uint32_t credit_cap;
    int credit_balance;
    int credit_xtra;
    int credit;

#ifdef HETERO_VISOR
	/*struct domain *d;*/
	/*struct vcpu *v;*/
	uint32_t scredit_fair = 0, fcredit_fair = 0;
	uint32_t scredit_cap = 0, fcredit_cap = 0;
    int scredit = 0, fcredit = 0;
	uint16_t fast_vcpu_count = 0, slow_vcpu_count = 0;

	uint64_t mytime, mysec;
	rdtscll(mytime);
	mysec = tsc_ticks2ns(mytime)/1000000;

	hetero_hcredit_tick++;
	hetero_sched_tick++;
	hetero_debug_tick++;

	if(hetero_hcredit_tick >= HCREDIT_TICK_COUNT && hetero_visor_active){
		redist_hcredits();
		hetero_hcredit_tick = 0;
	}

	if(hetero_sched_tick >= SCHED_TICK_COUNT && hetero_visor_active){
		reset_perf_counters();
		hetero_sched_balance();
		hetero_sched_tick = 0 ;
	}

	if(hetero_debug_tick >= DEBUG_TICK_COUNT && hetero_visor_active){
		print_heartbeat_msg();
		hetero_debug_tick = 0 ;
	}

#endif

    spin_lock_irqsave(&prv->lock, flags);

    weight_total = prv->weight;
    credit_total = prv->credit;

    /* Converge balance towards 0 when it drops negative */
    if ( prv->credit_balance < 0 )
    {
        credit_total -= prv->credit_balance;
        CSCHED_STAT_CRANK(acct_balance);
    }

    if ( unlikely(weight_total == 0) )
    {
        prv->credit_balance = 0;
        spin_unlock_irqrestore(&prv->lock, flags);
        CSCHED_STAT_CRANK(acct_no_work);
        goto out;
    }

    CSCHED_STAT_CRANK(acct_run);

    weight_left = weight_total;
    credit_balance = 0;
    credit_xtra = 0;
    credit_cap = 0U;

    list_for_each_safe( iter_sdom, next_sdom, &prv->active_sdom )
    {
        sdom = list_entry(iter_sdom, struct csched_dom, active_sdom_elem);

        BUG_ON( is_idle_domain(sdom->dom) );
        BUG_ON( sdom->active_vcpu_count == 0 );
        BUG_ON( sdom->weight == 0 );
        BUG_ON( (sdom->weight * sdom->active_vcpu_count) > weight_left );

        weight_left -= ( sdom->weight * sdom->active_vcpu_count );

        /*
         * A domain's fair share is computed using its weight in competition
         * with that of all other active domains.
         *
         * At most, a domain can use credits to run all its active VCPUs
         * for one full accounting period. We allow a domain to earn more
         * only when the system-wide credit balance is negative.
         */
        credit_peak = sdom->active_vcpu_count * CSCHED_CREDITS_PER_ACCT;
        if ( prv->credit_balance < 0 )
        {
            credit_peak += ( ( -prv->credit_balance
                               * sdom->weight
                               * sdom->active_vcpu_count) +
                             (weight_total - 1)
                           ) / weight_total;
        }

        if ( sdom->cap != 0U )
        {
            credit_cap = ((sdom->cap * CSCHED_CREDITS_PER_ACCT) + 99) / 100;
            if ( credit_cap < credit_peak )
                credit_peak = credit_cap;

            /* FIXME -- set cap per-vcpu as well...? */
            credit_cap = ( credit_cap + ( sdom->active_vcpu_count - 1 )
                         ) / sdom->active_vcpu_count;
        }

        credit_fair = ( ( credit_total
                          * sdom->weight
                          * sdom->active_vcpu_count )
                        + (weight_total - 1)
                      ) / weight_total;

        if ( credit_fair < credit_peak )
        {
            credit_xtra = 1;
        }
        else
        {
            if ( weight_left != 0U )
            {
                /* Give other domains a chance at unused credits */
                credit_total += ( ( ( credit_fair - credit_peak
                                    ) * weight_total
                                  ) + ( weight_left - 1 )
                                ) / weight_left;
            }

            if ( credit_xtra )
            {
                /*
                 * Lazily keep domains with extra credits at the head of
                 * the queue to give others a chance at them in future
                 * accounting periods.
                 */
                CSCHED_STAT_CRANK(acct_reorder);
                list_del(&sdom->active_sdom_elem);
                list_add(&sdom->active_sdom_elem, &prv->active_sdom);
            }

            credit_fair = credit_peak;
        }

        /* Compute fair share per VCPU */
        credit_fair = ( credit_fair + ( sdom->active_vcpu_count - 1 )
                      ) / sdom->active_vcpu_count;

#ifdef HETERO_VISOR
		if(hetero_visor_active){
			fast_vcpu_count = sdom->fast_vcpu_count;
			slow_vcpu_count = sdom->vcpu_count - fast_vcpu_count;
			//calculate small and big core credits based on caps
			if ( sdom->scap != 0U && slow_vcpu_count > 0) {
				scredit_cap = ((sdom->scap * CSCHED_CREDITS_PER_ACCT) + 99) / 100;
				scredit_fair = ( scredit_cap + ( slow_vcpu_count - 1 )
						  ) / slow_vcpu_count;
				scredit_cap = ( scredit_cap + ( slow_vcpu_count - 1 )
							 ) / slow_vcpu_count;
			}
			else {
				scredit_cap = 0;
				scredit_fair = 0;
			}
			if ( sdom->fcap != 0U && fast_vcpu_count > 0) {
				fcredit_cap = ((sdom->fcap * CSCHED_CREDITS_PER_ACCT) + 99) / 100;
				fcredit_fair = ( fcredit_cap + ( fast_vcpu_count - 1 )
						  ) / fast_vcpu_count;
				fcredit_cap = ( fcredit_cap + ( fast_vcpu_count - 1 )
							 ) / fast_vcpu_count;
			}
			else {
				fcredit_cap = 0;
				fcredit_fair = 0;

			}
			if(hetero_debug_level >= 2)
				printk("%lu [domain_acct]: %d %d %d\n",mysec,sdom->dom->domain_id,scredit_fair,fcredit_fair);
		}
#endif

        list_for_each_safe( iter_vcpu, next_vcpu, &sdom->active_vcpu )
        {
            svc = list_entry(iter_vcpu, struct csched_vcpu, active_vcpu_elem);
            BUG_ON( sdom != svc->sdom );

            /* Increment credit */
            atomic_add(credit_fair, &svc->credit);
            credit = atomic_read(&svc->credit);

#ifdef HETERO_VISOR
			if(hetero_visor_active && sdom->dom->domain_id > 0){ 
			//cap/uncap small cores
			if(svc->core_type == SMALL && scredit_cap > 0 ){
				atomic_add(scredit_fair, &svc->scredit);
				scredit = atomic_read(&svc->scredit);
				if(scredit < 0)
				{
					svc->pri = CSCHED_PRI_TS_OVER;

					/* Park running VCPUs of capped-out domains */
					if ( sdom->scap != 0U &&
						 scredit < -scredit_cap &&
						 !(svc->flags & CSCHED_FLAG_VCPU_PARKED) )
					{
						CSCHED_STAT_CRANK(vcpu_park);
						vcpu_pause_nosync(svc->vcpu);
						svc->flags |= CSCHED_FLAG_VCPU_PARKED;
						if(hetero_debug_level >= 2)
							printk("%lu Pausing SML vcpu id:%d %d cap:%d %d\n",mysec,sdom->dom->domain_id,svc->vcpu->vcpu_id,scredit,fcredit);
					}

					/* Lower bound on credits */
					if ( scredit < -CSCHED_CREDITS_PER_TSLICE )
					{
						CSCHED_STAT_CRANK(acct_min_credit);
						scredit = -CSCHED_CREDITS_PER_TSLICE;
						atomic_set(&svc->scredit, scredit);
					}
				}
				else
				{
					svc->pri = CSCHED_PRI_TS_UNDER;

					/* Unpark any capped domains whose credits go positive */
					if ( svc->flags & CSCHED_FLAG_VCPU_PARKED)
					{
						/*
						 * It's important to unset the flag AFTER the unpause()
						 * call to make sure the VCPU's priority is not boosted
						 * if it is woken up here.
						 */
						CSCHED_STAT_CRANK(vcpu_unpark);
						vcpu_unpause(svc->vcpu);
						svc->flags &= ~CSCHED_FLAG_VCPU_PARKED;
						if(hetero_debug_level >= 2)
							printk("%lu Unpausing SML vcpu id:%d %d cap:%d %d\n",mysec,sdom->dom->domain_id,svc->vcpu->vcpu_id,scredit,fcredit);
					}

					/* Upper bound on credits means VCPU stops earning */
					if ( scredit > CSCHED_CREDITS_PER_TSLICE )
					{
						__csched_vcpu_acct_stop_locked(prv, svc); //TODO VG this does not get called. active_vcpu list never goes down
						/* Divide credits in half, so that when it starts
						 * accounting again, it starts a little bit "ahead" */
						scredit /= 2;
						atomic_set(&svc->scredit, scredit);
					}
				}

			}
			else if(svc->core_type == BIG && fcredit_cap > 0 ){//cap/uncap big cores
				atomic_add(fcredit_fair, &svc->fcredit);
				fcredit = atomic_read(&svc->fcredit);
				if(fcredit < 0)
				{
					svc->pri = CSCHED_PRI_TS_OVER;

					/* Park running VCPUs of capped-out domains */
					if ( sdom->fcap != 0U &&
						 fcredit < -fcredit_cap &&
						 !(svc->flags & CSCHED_FLAG_VCPU_PARKED) )
					{
						CSCHED_STAT_CRANK(vcpu_park);
						vcpu_pause_nosync(svc->vcpu);
						svc->flags |= CSCHED_FLAG_VCPU_PARKED;
						if(hetero_debug_level >= 2)
							printk("%lu Pausing BIG vcpu id:%d %d cap:%d %d\n",mysec,sdom->dom->domain_id,svc->vcpu->vcpu_id,scredit,fcredit);
					}

					/* Lower bound on credits */
					if ( fcredit < -CSCHED_CREDITS_PER_TSLICE )
					{
						CSCHED_STAT_CRANK(acct_min_credit);
						fcredit = -CSCHED_CREDITS_PER_TSLICE;
						atomic_set(&svc->fcredit, fcredit);
					}
				}
				else
				{
					svc->pri = CSCHED_PRI_TS_UNDER;

					/* Unpark any capped domains whose credits go positive */
					if ( svc->flags & CSCHED_FLAG_VCPU_PARKED)
					{
						/*
						 * It's important to unset the flag AFTER the unpause()
						 * call to make sure the VCPU's priority is not boosted
						 * if it is woken up here.
						 */
						CSCHED_STAT_CRANK(vcpu_unpark);
						vcpu_unpause(svc->vcpu);
						svc->flags &= ~CSCHED_FLAG_VCPU_PARKED;
						if(hetero_debug_level >= 2)
							printk("%lu Unpausing BIG vcpu id:%d %d cap:%d %d\n",mysec,sdom->dom->domain_id,svc->vcpu->vcpu_id,scredit,fcredit);
					}

					/* Upper bound on credits means VCPU stops earning */
					if ( fcredit > CSCHED_CREDITS_PER_TSLICE )
					{
						__csched_vcpu_acct_stop_locked(prv, svc);
						/* Divide credits in half, so that when it starts
						 * accounting again, it starts a little bit "ahead" */
						fcredit /= 2;
						atomic_set(&svc->fcredit, fcredit);
					}
				}
			}

			}
			else //if !hetero_visor_active (normal execution path)
			{
#endif
            /*
             * Recompute priority or, if VCPU is idling, remove it from
             * the active list.
             */
            if ( credit < 0 )
            {
                svc->pri = CSCHED_PRI_TS_OVER;

                /* Park running VCPUs of capped-out domains */
                if ( sdom->cap != 0U &&
                     credit < -credit_cap &&
                     !(svc->flags & CSCHED_FLAG_VCPU_PARKED) )
                {
                    CSCHED_STAT_CRANK(vcpu_park);
                    vcpu_pause_nosync(svc->vcpu);
                    svc->flags |= CSCHED_FLAG_VCPU_PARKED;
                }

                /* Lower bound on credits */
                if ( credit < -CSCHED_CREDITS_PER_TSLICE )
                {
                    CSCHED_STAT_CRANK(acct_min_credit);
                    credit = -CSCHED_CREDITS_PER_TSLICE;
                    atomic_set(&svc->credit, credit);
                }
            }
            else
            {
                svc->pri = CSCHED_PRI_TS_UNDER;

                /* Unpark any capped domains whose credits go positive */
                if ( svc->flags & CSCHED_FLAG_VCPU_PARKED)
                {
                    /*
                     * It's important to unset the flag AFTER the unpause()
                     * call to make sure the VCPU's priority is not boosted
                     * if it is woken up here.
                     */
                    CSCHED_STAT_CRANK(vcpu_unpark);
                    vcpu_unpause(svc->vcpu);
                    svc->flags &= ~CSCHED_FLAG_VCPU_PARKED;
                }

                /* Upper bound on credits means VCPU stops earning */
                if ( credit > CSCHED_CREDITS_PER_TSLICE )
                {
                    __csched_vcpu_acct_stop_locked(prv, svc);
                    /* Divide credits in half, so that when it starts
                     * accounting again, it starts a little bit "ahead" */
                    credit /= 2;
                    atomic_set(&svc->credit, credit);
                }
            }

#ifdef HETERO_VISOR
}//if hetero_visor_active
#endif
            CSCHED_VCPU_STAT_SET(svc, credit_last, credit);
            CSCHED_VCPU_STAT_SET(svc, credit_incr, credit_fair);
            credit_balance += credit;
        }
    }

    prv->credit_balance = credit_balance;

    spin_unlock_irqrestore(&prv->lock, flags);

    /* Inform each CPU that its runq needs to be sorted */
    prv->runq_sort++;

out:
    set_timer( &prv->master_ticker, NOW() +
            MILLISECS(CSCHED_MSECS_PER_TICK) * CSCHED_TICKS_PER_ACCT );
}

#ifdef ENABLE_PCPU_STAT
void pcpu_stat(void)
{
	struct csched_pcpu *spc;
	s_time_t t;
	int cpu;
	myprintk("[ ");
	for_each_online_cpu ( cpu )
	{
		// race to sched_time is possible, but ignore..
		spc = CSCHED_PCPU(cpu);
		t = spc->sched_time;
		spc->sched_time = 0;
		printk("%lld ", t/1000000ULL);
	}
	printk("ms]\n");
}
#else
void pcpu_stat(void) {}
#endif

#ifdef ENABLE_BINPACKING
// don't check mini_activated before calling this..
int strategy_point(s_time_t now, int num)
{
	s_time_t cosched = this_cpu(cosched_flagtime);
	if (!cosched)
		return 0;
	if (!mini_activated) {
		clear_flagtime();
		return 0;
	}
	s_time_t diff = now - cosched;
	if (diff > MILLISECS(100)) {	// impossible.
//		printk("WARN! too big! diff = %lld\n", diff);
		diff = 1;	// almost 0.
	}
//	printk("diff@%d = %lldus ..", num, diff/1000ULL);
	if (num == 1)	// If scheduler called me.
		return 1;
	// TODO: call scheduler. can I call scheduler from other points??
	return 1;
}

int clear_flagtime(void)
{
#ifdef DEBUG_WARN
	if (this_cpu(cosched_flagtime) == 0)
		myprintk("WARN! already zero\n");
#endif
	this_cpu(cosched_flagtime) = 0;
}
#endif
static void
csched_tick(void *_cpu)
{
    unsigned int cpu = (unsigned long)_cpu;
    struct csched_pcpu *spc = CSCHED_PCPU(cpu);
    struct csched_private *prv = CSCHED_PRIV(per_cpu(scheduler, cpu));

    spc->tick++;

    /*
     * Accounting for running VCPU
     */
    if ( !is_idle_vcpu(current) )
        csched_vcpu_acct(prv, cpu);

#define MY_MASTER	1

	if ( (spc->tick % 100) == 0 ) {	// 1sec
#ifdef ENABLE_PCPU_STAT
		s_time_t now = NOW();
		s_time_t passed = now - spc->start_time;
		spc->start_time = now;
		if ( !is_idle_vcpu(current) ) {
			spc->sched_time += passed;
	        }
	if(hetero_visor_mem){
		if (MY_MASTER == cpu) {
#ifdef HETEROPERF
#else
			pcpu_stat();
#endif
		}
	}
#endif
	if(hetero_visor_mem){
		if (MY_MASTER == cpu) {
#ifdef HETEROPERF
#else
		heartbeat();
#endif

		}
	}
	}


#ifdef ENABLE_PGD
    if ( (MY_MASTER == cpu) && mini_activated ) {
	atomic_inc(&mini_count);
	atomic_inc(&mini_place[9]);
	if ( (spc->tick % 100) == 0 ) {	// 1sec
//		printx_cache(0);
//		printx_each_vcpu();
//		print_pcpu();		// print binpacking
	}
#ifdef ENABLE_HOT_PAGES
	if ( (spc->tick % 50 ) == 0 ) {	// 500ms
        s_time_t now = NOW();
        shrink_hot_pages(now);
	}
#endif
#ifdef ENABLE_CACHE_BALANCE
	if ( (spc->tick % 10 ) == 0 ) {	// 100ms
		do_balance(0);
	}
#endif
#ifdef ENABLE_BINPACKING_PRINTX
	if ( (spc->tick % 3 ) == 0 ) {	// 30ms
		printx_pcpu(NOW());
	}
#endif
	atomic_dec(&mini_place[9]);
	atomic_dec(&mini_count);
    }

#ifdef ENABLE_CACHEMAN1
	if (mini_activated && (spc->tick % 10 ) == 0 ) {	// 100ms
//		shrink_cacheman(proc2intcache[cpu], NOW());
	}
#endif

#ifdef ENABLE_CLOCK
	if (mini_activated && current->current_pgd) {
		atomic_inc(&mini_count);
		atomic_inc(&mini_place[10]);
		do_clock(CLOCK_EVENT_TIMER, current->current_pgd, NOW());
		atomic_dec(&mini_place[10]);
		atomic_dec(&mini_count);
	}
#endif

#ifdef ENABLE_BINPACKING
	// strategy point #2 - tick
	if (strategy_point(NOW(), 2))
		clear_flagtime();
#endif

#ifdef ENABLE_PER_CACHE_PT
	if (mini_activated && current->current_pgd) {
		MYASSERT(cr3_is_shadow(0));
	}
#endif
#endif



    /*
     * Check if runq needs to be sorted
     *
     * Every physical CPU resorts the runq after the accounting master has
     * modified priorities. This is a special O(n) sort and runs at most
     * once per accounting period (currently 30 milliseconds).
     */
    csched_runq_sort(prv, cpu);

    set_timer(&spc->ticker, NOW() + MILLISECS(CSCHED_MSECS_PER_TICK));
}

static struct csched_vcpu *
csched_runq_steal(int peer_cpu, int cpu, int pri)
{
    const struct csched_pcpu * const peer_pcpu = CSCHED_PCPU(peer_cpu);
    const struct vcpu * const peer_vcpu = per_cpu(schedule_data, peer_cpu).curr;
    struct csched_vcpu *speer;
    struct list_head *iter;
    struct vcpu *vc;
#if 0 // def ENABLE_PAGE_TOUCH
	if (proc2intcache[peer_cpu] != proc2intcache[cpu]) {	// if different cache, disable
		// TODO:
		return NULL;
	}
#endif
    /*
     * Don't steal from an idle CPU's runq because it's about to
     * pick up work from it itself.
     */
    if ( peer_pcpu != NULL && !is_idle_vcpu(peer_vcpu) )
    {
        list_for_each( iter, &peer_pcpu->runq )
        {
            speer = __runq_elem(iter);

            /*
             * If next available VCPU here is not of strictly higher
             * priority than ours, this PCPU is useless to us.
             */
            if ( speer->pri <= pri )
                break;

            /* Is this VCPU is runnable on our PCPU? */
            vc = speer->vcpu;
            BUG_ON( is_idle_vcpu(vc) );

            if (__csched_vcpu_is_migrateable(vc, cpu))
#ifdef ENABLE_PAGE_TOUCH
		if (
//		(proc2intcache[cpu] == proc2intcache[peer_cpu]) || // only same-cach
		( !vc->run_count || proc2intcache[cpu]==vc->run_cache )	// pick up only zero run_count or same-cache
		)
#endif
            {
                /* We got a candidate. Grab it! */
                CSCHED_VCPU_STAT_CRANK(speer, migrate_q);
                CSCHED_STAT_CRANK(migrate_queued);
                WARN_ON(vc->is_urgent);
                __runq_remove(speer);
                vc->processor = cpu;
                return speer;
            }
        }
    }

    CSCHED_STAT_CRANK(steal_peer_idle);
    return NULL;
}

static struct csched_vcpu *
csched_load_balance(struct csched_private *prv, int cpu,
    struct csched_vcpu *snext, bool_t *stolen)
{
    struct csched_vcpu *speer;
    cpumask_t workers;
    cpumask_t *online;
    int peer_cpu;

    BUG_ON( cpu != snext->vcpu->processor );
    online = CSCHED_CPUONLINE(per_cpu(cpupool, cpu));

    /* If this CPU is going offline we shouldn't steal work. */
    if ( unlikely(!cpu_isset(cpu, *online)) )
        goto out;

    if ( snext->pri == CSCHED_PRI_IDLE )
        CSCHED_STAT_CRANK(load_balance_idle);
    else if ( snext->pri == CSCHED_PRI_TS_OVER )
        CSCHED_STAT_CRANK(load_balance_over);
    else
        CSCHED_STAT_CRANK(load_balance_other);

    /*
     * Peek at non-idling CPUs in the system, starting with our
     * immediate neighbour.
     */
    cpus_andnot(workers, *online, prv->idlers);
    cpu_clear(cpu, workers);
    peer_cpu = cpu;

    while ( !cpus_empty(workers) )
    {
        peer_cpu = cycle_cpu(peer_cpu, workers);
        cpu_clear(peer_cpu, workers);

        /*
         * Get ahold of the scheduler lock for this peer CPU.
         *
         * Note: We don't spin on this lock but simply try it. Spinning could
         * cause a deadlock if the peer CPU is also load balancing and trying
         * to lock this CPU.
         */
        if ( !pcpu_schedule_trylock(peer_cpu) )
        {
            CSCHED_STAT_CRANK(steal_trylock_failed);
            continue;
        }

        /*
         * Any work over there to steal?
         */
        speer = cpu_isset(peer_cpu, *online) ?
            csched_runq_steal(peer_cpu, cpu, snext->pri) : NULL;
        pcpu_schedule_unlock(peer_cpu);
        if ( speer != NULL )
        {
            *stolen = 1;
            return speer;
        }
    }

 out:
    /* Failed to find more important work elsewhere... */
    __runq_remove(snext);
    return snext;
}


#if 0
#define MYARRAY_SIZE	32
void print_pcpu(s_time_t now)
{
	unsigned long array[MYARRAY_SIZE];
	int count, i, active;
	int cpu;
	struct csched_vcpu *svc;
	for(i=0;i<MAX_CACHE;i++) {
		array[i] = 0;
	}
	array[i++] = now/1000000ULL;	// to ms
	count = i;
	for_each_online_cpu ( cpu )
	{
		/* current VCPU */
		svc = CSCHED_VCPU(per_cpu(schedule_data, cpu).curr);
		if (!svc) {
			printk("svc == NULL??\n");
		}
#ifdef ENABLE_PGD
		if (is_idle_vcpu(svc->vcpu) || !svc->vcpu->current_pgd) {
//			array[count++] = 0;	// active = 0
		} else {
//			array[count++] = cpu;
//			array[count++] = svc->vcpu->domain->domain_id;
//			array[count++] = svc->vcpu->vcpu_id;
//			array[count++] = svc->vcpu->current_pgd->pgd_id;
			active = 0; // TODO ACTIVE_FRAMES_PGD(svc->vcpu->current_pgd, svc->vcpu->current_pgd->current_cache);
//			array[count++] = active;
//			array[svc->vcpu->current_pgd->current_cache]+=active;
			array[proc2intcache[cpu]]+=active;
		}
#endif
	}
	if (count >= MYARRAY_SIZE) {
		mypanic("BUG!!!");
	}
	myprintk("binpacking: ");
	for(i=0;i<count;i++)
		printk("%d ", array[i]);
	printk("\n");
}
void printx_pcpu(s_time_t now)
{
	if ((TRC_MIN_BINPACKING & TRC_ALL) != TRC_MIN) {
		return;
	}
	unsigned long array[MYARRAY_SIZE];
	int count, i, active;
	int cpu;
	struct csched_vcpu *svc;
	for(i=0;i<MAX_CACHE;i++) {
		array[i] = 0;
	}
	array[i++] = now/1000000ULL;	// to ms
	count = i;
	for_each_online_cpu ( cpu )
	{
		/* current VCPU */
		svc = CSCHED_VCPU(per_cpu(schedule_data, cpu).curr);
		if (!svc) {
			printk("svc == NULL??\n");
		}
#ifdef ENABLE_PGD
		if (is_idle_vcpu(svc->vcpu) || !svc->vcpu->current_pgd) { //  idle or..
//			array[count++] = 0;	// active = 0
		} else {
//			array[count++] = cpu;
//			array[count++] = svc->vcpu->domain->domain_id;
//			array[count++] = svc->vcpu->vcpu_id;
//			array[count++] = svc->vcpu->current_pgd->pgd_id;
			active = 0; // TODO ACTIVE_FRAMES_PGD(svc->vcpu->current_pgd, svc->vcpu->current_pgd->current_cache);
//			array[count++] = active;
//			array[svc->vcpu->current_pgd->current_cache]+=active;
			array[proc2intcache[cpu]]+=active;
		}
#endif
	}
	if (count >= MYARRAY_SIZE) {
		mypanic("BUG!!!");
	}
	MYXTRACE(TRC_MIN_BINPACKING, count, array);
}

#ifdef ENABLE_BINPACKING
static struct cosched_vcpu *
cosched_simple(int cpu, struct csched_vcpu *scurr, int active)
{
	const struct csched_pcpu * const spc = CSCHED_PCPU(cpu);
	struct csched_vcpu *svc, *svc_candidate = NULL;
	struct list_head *iter;
	int diff_candidate = INT_MAX;
	BUG_ON( cpu != scurr->vcpu->processor );

        list_for_each( iter, &spc->runq )
        {
		svc = __runq_elem(iter);

		if (svc->pri < scurr->pri || svc->pri == CSCHED_PRI_IDLE )
			break;
		if (svc && svc->vcpu->current_pgd ) {
			int diff = cacheman[proc2intcache[cpu]].size/4 - (active + ACTIVE_FRAMES_PGD(svc->vcpu->current_pgd, 0));// TODO: which cache?
			if (diff < 0)
				diff = -diff;
			if (diff < diff_candidate) {
				svc_candidate = svc;
				diff_candidate = diff;
			}
		}
	}
	if (svc_candidate) {
		printk("diffc:%d ", diff_candidate);
		__runq_remove(svc_candidate);
    		if ( svc_candidate->pri == CSCHED_PRI_IDLE )
			mypanic("_simple!! idle ??\n");
	} else {
		printk("Nodiffc ");
	}
	return svc_candidate;
}

//#define VERBOSE_BINPACKING

static struct cosched_vcpu *
cosched_runq_steal(int peer_cpu, int cpu, int pri, int active, int target)
{
    const struct csched_pcpu * const peer_pcpu = CSCHED_PCPU(peer_cpu);
    const struct vcpu * const peer_vcpu = per_cpu(schedule_data, peer_cpu).curr;
    struct csched_vcpu *speer = NULL;
    struct list_head *iter;
    struct vcpu *vc;

    /*
     * Don't steal from an idle CPU's runq because it's about to
     * pick up work from it itself.
     */
    if ( peer_pcpu != NULL && !is_idle_vcpu(peer_vcpu) )
    {
        list_for_each( iter, &peer_pcpu->runq )
        {
            speer = __runq_elem(iter);
#ifdef VERBOSE_BINPACKING
	    myprintk("peer's cpu:%d pri:%d\n", peer_cpu, speer->pri);
#endif
            if ( speer->pri < pri || speer->pri == CSCHED_PRI_IDLE )	// if lower priority, don't steal.
                break;
            /* Is this VCPU is runnable on our PCPU? */
            vc = speer->vcpu;
            BUG_ON( is_idle_vcpu(vc) );

            if (__csched_vcpu_is_migrateable(vc, cpu) && vc->current_pgd)
            {
		int diff = cacheman[proc2intcache[cpu]].size/4 - (active + ACTIVE_FRAMES_PGD(vc->current_pgd, 0));// TODO: which cache?
		if (diff < 0)
			diff = -diff;
		if (diff <= target) {
	                __runq_remove(speer);
	                vc->processor = cpu;
//			myprintk("Cosched succeed\n");
	                return speer;
		}
            }
        }
    }
    return NULL;
}
static struct csched_vcpu *
cosched_load_balance(int cpu, struct csched_vcpu *scurr, int active)
{
    struct csched_vcpu *speer;
    cpumask_t workers;
    int peer_cpu, peer_cpu_candidate;

    BUG_ON( cpu != scurr->vcpu->processor );

    /*
     * Peek at non-idling CPUs in the system, starting with myself
     */
    cpus_andnot(workers, cpu_online_map, csched_priv.idlers);
    peer_cpu = cpu;

    while ( !cpus_empty(workers) )
    {
        peer_cpu = __cycle_cpu(peer_cpu, &workers);
        cpu_clear(peer_cpu, workers);

        /*
         * Get ahold of the scheduler lock for this peer CPU.
         *
         * Note: We don't spin on this lock but simply try it. Spinning could
         * cause a deadlock if the peer CPU is also load balancing and trying
         * to lock this CPU.
         */
        if ( peer_cpu!=cpu && !spin_trylock(&per_cpu(schedule_data, peer_cpu).schedule_lock) )
        {
#ifdef VERBOSE_BINPACKING
	    myprintk("me:%d peer:%d (skip) \n", cpu, peer_cpu);
#endif
            continue;
        }

#ifdef VERBOSE_BINPACKING
	myprintk("me:%d peer:%d \n", cpu, peer_cpu);
#endif
        /*
         * Any work over there to steal?
         */
        speer = cosched_runq_steal(peer_cpu, cpu, scurr->pri, active, cacheman[proc2intcache[cpu]].size/4/8);
	if (peer_cpu!=cpu)
	        spin_unlock(&per_cpu(schedule_data, peer_cpu).schedule_lock);
	if (speer)
		return speer;
    }
    return NULL;
}
static struct csched_vcpu *
do_cosched(int cpu, struct csched_vcpu *scurr)
{
	// scurr could be sleeping(not on runqueue) now..
	int i;
	int active = 0;
	struct page_dir *expected;
	struct sched_vcpu *snext;

	cpumask_t already, check;
	cpus_clear(already);
	for_each_cpu_mask(i, cache2cpumask[proc2intcache[cpu]]) {
		if (per_cpu(cosched_flagtime, i))
			continue;
		cpu_set(i, already);
		expected = per_cpu(cosched_expected,i);
		if (expected) {
		//	active += ACTIVE_FRAMES_PGD( expected , expected->current_cache /*TODO:which cache it should be?? */);
			active += ACTIVE_FRAMES_PGD( expected , 0 );
		} else {
			myprintk("expected==0 ?\n");
		}
	}
#ifdef VERBOSE_BINPACKING
	myprintk("already mask0x%x, active:%d\n", already.bits[0], active);
#endif
	snext = cosched_load_balance(cpu, scurr, active);
//	snext = cosched_simple(cpu, scurr, active);
	cpus_clear(check);
	for_each_cpu_mask(i, cache2cpumask[proc2intcache[cpu]]) {
		if (!per_cpu(cosched_flagtime, i)) {
			cpu_set(i, check);
		}
	}
	if (!cpus_equal(check, already))
		myprintk("TODO: check != already\n");
	return snext;
}
#endif
#ifdef ENABLE_MEASURE_UNBALANCE
int would_be_idle(int from , int to)
{
	MYASSERT(from != to);
	return (atomic_read(&cacheman[to].vcpu_count) >= CPU_PER_CACHE && atomic_read(&cacheman[from].vcpu_count) <= CPU_PER_CACHE );
}

void has_core_unbalance(int *f, int *t)
{
	// assuming two caches
	int c1, c2, v1, v2;
	c1 = 0;
	c2 = 1;
	if ( (v1=atomic_read(&cacheman[c1].vcpu_count)) > CPU_PER_CACHE && (v2=atomic_read(&cacheman[c2].vcpu_count)) < CPU_PER_CACHE) {
		*f = c1;
		*t = c2;
//		myprintk("$%d=%dvcpus, $%d=%dvcpus\n", c1, v1, c2, v2);
		return;
	}
	c1 = 1;
	c2 = 0;
	if ( (v1=atomic_read(&cacheman[c1].vcpu_count)) > CPU_PER_CACHE && (v2=atomic_read(&cacheman[c2].vcpu_count)) < CPU_PER_CACHE) {
		*f = c1;
		*t = c2;
//		myprintk("$%d=%dvcpus, $%d=%dvcpus\n", c1, v1, c2, v2);
		return;
	}
	return;
}
#endif
#endif

/*
 * This function is in the critical path. It is designed to be simple and
 * fast for the common case.
 */
static struct task_slice
csched_schedule(
    const struct scheduler *ops, s_time_t now, bool_t tasklet_work_scheduled)
{
    const int cpu = smp_processor_id();
    struct list_head * const runq = RUNQ(cpu);
    struct csched_vcpu * const scurr = CSCHED_VCPU(current);
    struct csched_private *prv = CSCHED_PRIV(ops);
    struct csched_vcpu *snext;
    struct task_slice ret;

#ifdef ENABLE_PCPU_STAT
	struct csched_pcpu * const spc = CSCHED_PCPU(cpu);
	s_time_t passed = now - spc->start_time;
	spc->start_time = now;
	if ( !is_idle_vcpu(scurr->vcpu) ) {
		spc->sched_time += passed;
	}
//	int is_cosched;
#endif

    CSCHED_STAT_CRANK(schedule);
    CSCHED_VCPU_CHECK(current);

    if ( !is_idle_vcpu(scurr->vcpu) )
    {
        /* Update credits of a non-idle VCPU. */
        burn_credits(scurr, now);
        scurr->start_time -= now;
    }
    else
    {
        /* Re-instate a boosted idle VCPU as normal-idle. */
        scurr->pri = CSCHED_PRI_IDLE;
    }

#ifdef ENABLE_BINPACKING
	scurr->diff_passed += passed - scurr->last_passed;
	scurr->count_passed++;
	scurr->last_passed = passed;
cosched_again:
	// strategy point #1 - scheduler
	is_cosched = strategy_point(now, 1);
/*
        if (is_cosched && scurr->pri == CSCHED_PRI_IDLE ) {
                printk("WARN! idling cpu received cosched....probably we can't do __runq_elem(runq ->next).. because it's empty queue\n");
        }
*/
#endif

    /*
     * Select next runnable local VCPU (ie top of local runq)
     */
    if ( vcpu_runnable(current) )
        __runq_insert(cpu, scurr);
    else
        BUG_ON( is_idle_vcpu(current) || list_empty(runq) );

    snext = __runq_elem(runq->next);
    ret.migrated = 0;

    /* Tasklet work (which runs in idle VCPU context) overrides all else. */
    if ( tasklet_work_scheduled )
    {
        snext = CSCHED_VCPU(idle_vcpu[cpu]);
        snext->pri = CSCHED_PRI_TS_BOOST;
    }

    /*
     * Clear YIELD flag before scheduling out
     */
    if ( scurr->flags & CSCHED_FLAG_VCPU_YIELD )
        scurr->flags &= ~(CSCHED_FLAG_VCPU_YIELD);

    /*
     * SMP Load balance:
     *
     * If the next highest priority local runnable VCPU has already eaten
     * through its credits, look on other PCPUs to see if we have more
     * urgent work... If not, csched_load_balance() will return snext, but
     * already removed from the runq.
     */
#ifdef ENABLE_BINPACKING
	if (!is_cosched)
		goto fallback;
	struct csched_vcpu *mynext;
	if (!mini_activated)
		myprintk("WARN! cosched with no activation\n");
	// TODO: if do_cosched returns null.. we might want to keep running current task rather than context switching???? However, if it's sleeping(not in runqueue).... we should choose some task to run anyway..even idle one.
	mynext = do_cosched(cpu, scurr);
	if (mynext) {
		snext = mynext;
	} else {	// Couldn't find mynext, so.. fallback..
		// TODO: if I don't have candidate, should I ignore this cosched for low overhead ??
		goto fallback;
	}
	goto skip_fallback;
fallback:
#endif

    if ( snext->pri > CSCHED_PRI_TS_OVER )
        __runq_remove(snext);
    else
        snext = csched_load_balance(prv, cpu, snext, &ret.migrated);

#ifdef ENABLE_BINPACKING
skip_fallback:
	if (is_cosched) {
		this_cpu(cosched_expected) = snext->vcpu->current_pgd;
		clear_flagtime();
	} else {
/*		if (this_cpu(cosched_flagtime)) {	// go back and take this cosched signal
			if ( !vcpu_runnable(snext) )
				mypanic("not-runnable snext?");
			__runq_insert(cpu, snext);	// TODO: insert into original spot??
			goto cosched_again;
		}
*/
	}
#endif
    /*
     * Update idlers mask if necessary. When we're idling, other CPUs
     * will tickle us when they get extra work.
     */
    if ( snext->pri == CSCHED_PRI_IDLE )
    {
        if ( !cpu_isset(cpu, prv->idlers) )
            cpu_set(cpu, prv->idlers);
    }
    else if ( cpu_isset(cpu, prv->idlers) )
    {
        cpu_clear(cpu, prv->idlers);
    }

    if ( !is_idle_vcpu(snext->vcpu) )
        snext->start_time += now;

#ifdef HETERO_VISOR
	if(hetero_visor_active)
		update_perf_ctrs(scurr);
#endif
    /*
     * Return task to run next...
     */
    ret.time = (is_idle_vcpu(snext->vcpu) ?
                -1 : MILLISECS(CSCHED_MSECS_PER_TSLICE));
    ret.task = snext->vcpu;

#ifdef ENABLE_BINPACKING
	// TODO: when we're going to idle??
	if (snext->last_passed > MILLISECS(5) && !is_cosched && snext->pri != CSCHED_PRI_IDLE && mini_activated) {
		if (this_cpu(cosched_flagtime)) {
			printk("again received cosched signal?\n");
		}
		// TODO: clear cosched_expected when this pgd dies..
		this_cpu(cosched_expected) = ret.task->current_pgd;
#ifdef DEBUG_WARN
		if (!ret.task->current_pgd)
			printk("null-expected ? ");
#endif
		snext->count_cosched++;
		cpumask_t peers = cache2cpumask[proc2intcache[cpu]];
		cpu_clear(cpu, peers);
		int i;
#ifdef VERBOSE_BINPACKING
		myprintk("send cosched to mask0x%x\n", peers.bits[0]);
#endif
		for_each_cpu_mask(i, peers) {
			per_cpu(cosched_flagtime, i) = now;
		}
		cpumask_raise_softirq(peers, SCHEDULE_SOFTIRQ);
	}
#endif
#ifdef ENABLE_CLOCK
	if (mini_activated && ret.task != current) {
		struct page_dir *pgd = current->current_pgd;
		atomic_inc(&mini_count);
		if (pgd) {
			pgd->clock_residue += now - pgd->clock_prev_now;
			pgd->clock_prev_now = now;	// in fact, don't need this
			do_clock(CLOCK_EVENT_SCHEDULE, pgd, now);
		}
		if (ret.task->current_pgd) {
			ret.task->current_pgd->clock_prev_now = now;	// update
#ifdef ENABLE_REGIONING2
			regioning_resume(ret.task->current_pgd, CLOCK_EVENT_SCHEDULE);
#endif
		}
		atomic_dec(&mini_count);
	}
#endif

#if 1
	if (snext->vcpu->run_count) {
		int run_cache = snext->vcpu->run_cache;
		snext->vcpu->run_count--;
		if (!snext->vcpu->run_count)
			snext->vcpu->run_cache = -1;
		if (run_cache == proc2intcache[cpu]) {
#ifdef VERBOSE_USCHED_DETAIL
			if (usched_print-- > 0)
			myprintk("actually scheduled on %d$%d (%d remain)\n", cpu, run_cache, snext->vcpu->run_count);
#endif
		} else {
			myprintk("WARN!! run_cache:%d but scheduled to cpu:%d$%d)\n", run_cache, cpu, proc2intcache[cpu]);
			mypanic("usched failed?\n");
		}
	}
#endif
    CSCHED_VCPU_CHECK(ret.task);
    return ret;
}

static void
csched_dump_vcpu(struct csched_vcpu *svc)
{
    struct csched_dom * const sdom = svc->sdom;

    printk("[%i.%i] pri=%i flags=%x cpu=%i",
            svc->vcpu->domain->domain_id,
            svc->vcpu->vcpu_id,
            svc->pri,
            svc->flags,
            svc->vcpu->processor);

    if ( sdom )
    {
        printk(" credit=%i [w=%u]", atomic_read(&svc->credit), sdom->weight);
#ifdef CSCHED_STATS
        printk(" (%d+%u) {a/i=%u/%u m=%u+%u}",
                svc->stats.credit_last,
                svc->stats.credit_incr,
                svc->stats.state_active,
                svc->stats.state_idle,
                svc->stats.migrate_q,
                svc->stats.migrate_r);
#endif
    }

    printk("\n");
}

static void
csched_dump_pcpu(const struct scheduler *ops, int cpu)
{
    struct list_head *runq, *iter;
    struct csched_pcpu *spc;
    struct csched_vcpu *svc;
    int loop;
#define cpustr keyhandler_scratch

    spc = CSCHED_PCPU(cpu);
    runq = &spc->runq;

    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_sibling_map, cpu));
    printk(" sort=%d, sibling=%s, ", spc->runq_sort_last, cpustr);
    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_core_map, cpu));
    printk("core=%s\n", cpustr);

    /* current VCPU */
    svc = CSCHED_VCPU(per_cpu(schedule_data, cpu).curr);
    if ( svc )
    {
        printk("\trun: ");
        csched_dump_vcpu(svc);
    }

    loop = 0;
    list_for_each( iter, runq )
    {
        svc = __runq_elem(iter);
        if ( svc )
        {
            printk("\t%3d: ", ++loop);
            csched_dump_vcpu(svc);
        }
    }
#undef cpustr
}

static void
csched_dump(const struct scheduler *ops)
{
    struct list_head *iter_sdom, *iter_svc;
    struct csched_private *prv = CSCHED_PRIV(ops);
    int loop;
#define idlers_buf keyhandler_scratch

    printk("info:\n"
           "\tncpus              = %u\n"
           "\tmaster             = %u\n"
           "\tcredit             = %u\n"
           "\tcredit balance     = %d\n"
           "\tweight             = %u\n"
           "\trunq_sort          = %u\n"
           "\tdefault-weight     = %d\n"
           "\tmsecs per tick     = %dms\n"
           "\tcredits per msec   = %d\n"
           "\tticks per tslice   = %d\n"
           "\tticks per acct     = %d\n"
           "\tmigration delay    = %uus\n",
           prv->ncpus,
           prv->master,
           prv->credit,
           prv->credit_balance,
           prv->weight,
           prv->runq_sort,
           CSCHED_DEFAULT_WEIGHT,
           CSCHED_MSECS_PER_TICK,
           CSCHED_CREDITS_PER_MSEC,
           CSCHED_TICKS_PER_TSLICE,
           CSCHED_TICKS_PER_ACCT,
           vcpu_migration_delay);

    cpumask_scnprintf(idlers_buf, sizeof(idlers_buf), prv->idlers);
    printk("idlers: %s\n", idlers_buf);

    printk("active vcpus:\n");
    loop = 0;
    list_for_each( iter_sdom, &prv->active_sdom )
    {
        struct csched_dom *sdom;
        sdom = list_entry(iter_sdom, struct csched_dom, active_sdom_elem);

        list_for_each( iter_svc, &sdom->active_vcpu )
        {
            struct csched_vcpu *svc;
            svc = list_entry(iter_svc, struct csched_vcpu, active_vcpu_elem);

            printk("\t%3d: ", ++loop);
            csched_dump_vcpu(svc);
        }
    }
#undef idlers_buf
}
#ifdef HETERO_VISOR
//create per dom vcpu list
void hetero_vcpu_list(void){
	struct domain *d;
	struct csched_dom *sdom;
	struct vcpu *v;
	struct csched_vcpu *svc;
	cpumask_t coremask;

	for_each_domain( d )
	{
		if(d->domain_id > 0){
		sdom = CSCHED_DOM(d);
		INIT_LIST_HEAD(&sdom->hetero_vcpu);
		sdom->vcpu_count = 0;
		for_each_vcpu(d, v){
			svc = CSCHED_VCPU(v);
			INIT_LIST_HEAD(&svc->hetero_vcpu_elem);
			list_add_tail(&(svc->hetero_vcpu_elem), &sdom->hetero_vcpu);
			sdom->vcpu_count++;
			coremask = smallcore_mask;
			hetero_vcpu_migrate(svc->vcpu, &coremask);
			svc->core_type = SMALL;
		}
		sdom->hetero_sched_done = 0;
		}
	}
}

//initialize hetero core configuration
void setup_hetero_cores(void){
	struct csched_pcpu *spc;
	int cpu = 0, socket =0, i;
	char cpumask_big_buf[16], cpumask_small_buf[16];
	uint16_t num_small_cores = num_active_cpus - big_core_count;
	uint16_t cores_per_socket = num_active_cpus/num_sockets;
	uint16_t big_cores_per_socket = big_core_count/num_sockets;
	uint16_t small_cores_per_socket = cores_per_socket - big_cores_per_socket;
	big_core_count = big_cores_per_socket * num_sockets;

	WARN_ON(big_core_count < 0);

	//TODO VG
	TOTAL_FCREDITS = big_core_count * HCREDITS_PER_TICK;
	TOTAL_SCREDITS =  num_small_cores * HCREDITS_PER_TICK;
	cpus_clear(bigcore_mask);
	cpus_clear(smallcore_mask);

	for(socket=0;socket<num_sockets;socket++){
		for(i=0;i<cores_per_socket;i++)
		{
			cpu = socket*cores_per_socket + i;

			spc = CSCHED_PCPU(cpu);

			if(i >= small_cores_per_socket){
				per_cpu(core_type,cpu) = BIG;
				cpu_set(cpu,bigcore_mask);
				hetero_nb_cores++;
			}
			else{
				per_cpu(core_type,cpu) = SMALL;
				cpu_set(cpu,smallcore_mask);
				hetero_ns_cores++;
			}

		}
	}
	cpulist_scnprintf(cpumask_small_buf, 16, smallcore_mask);
	cpulist_scnprintf(cpumask_big_buf, 16, bigcore_mask);

	if(hetero_debug_level >= 0)
		printk("Hetero Core Map: BIG:%s SML:%s\n",cpumask_big_buf,cpumask_small_buf);

	hetero_vcpu_list();
}

//update fast vcpu list (add or remove vcpus)
void fast_vcpu_list(struct domain *d, int empty, int old_count){
	struct csched_dom *sdom;
	struct csched_vcpu *svc = NULL;
	struct list_head *iter_vcpu;
	int16_t fcount ;
	cpumask_t coremask;
	sdom = CSCHED_DOM(d);
	//vcpu count difference
	fcount = sdom->fast_vcpu_count - old_count;

	if(empty)//initialization
	{
		INIT_LIST_HEAD(&sdom->fast_vcpu);
		list_for_each( iter_vcpu, &sdom->hetero_vcpu)
		{
		svc = list_entry(iter_vcpu, struct csched_vcpu, hetero_vcpu_elem);
		if(svc)
			INIT_LIST_HEAD(&svc->fast_vcpu_elem);
		}
	}
	else
	{
	//add vcpus
	if(fcount > 0)
	{
		list_for_each( iter_vcpu, &sdom->hetero_vcpu)
		{
			if(fcount == 0)
				break;
			svc = list_entry(iter_vcpu, struct csched_vcpu, hetero_vcpu_elem);

			if(svc){

				coremask = bigcore_mask;
				list_add_tail(&(svc->fast_vcpu_elem), &sdom->fast_vcpu);
				/*sdom->fast_vcpu_count++;*/
				hetero_vcpu_migrate(svc->vcpu, &coremask);
				svc->core_type = BIG;
				fcount--;
			}
		}
		
		//rotate hetero vcpu list for added vcpus
		fcount = sdom->fast_vcpu_count - old_count;
		while(fcount != 0){
				list_rotate_left(&sdom->hetero_vcpu);
				fcount--;
		}
	}
	else if(fcount < 0) //delete vcpus
	{
		while(fcount != 0)
		{
			list_for_each( iter_vcpu, &sdom->fast_vcpu)
			{
				svc = list_entry(iter_vcpu, struct csched_vcpu, fast_vcpu_elem);
				break;
			}
			if(svc){
				coremask = smallcore_mask;
				hetero_vcpu_migrate(svc->vcpu, &coremask);
				svc->core_type = SMALL;
				/*printk("fvcpu %d %d\n",fcount,svc->vcpu->vcpu_id);*/
				list_del_init(&svc->fast_vcpu_elem);
				fcount++;
			}
		}
	}
	}

	if(hetero_debug_level >= 1){
		printk("fvcpu list:%d %d ",old_count,sdom->fast_vcpu_count);
		list_for_each( iter_vcpu,&sdom->fast_vcpu)
		{
			svc = list_entry(iter_vcpu, struct csched_vcpu,fast_vcpu_elem);
			printk("%d ",svc->vcpu->vcpu_id);
		}
		printk("\n");
	}
	sdom->hetero_sched_done = 1;
}

//reset credits/caps
void reset_hcredits(void){
	struct domain *d;
	struct vcpu *v;
	struct csched_vcpu *svc;
	struct csched_dom *sdom;

	for_each_domain( d )
	{
		sdom = CSCHED_DOM(d);

		for_each_vcpu(d, v){
			svc = CSCHED_VCPU(v);
			atomic_set(&svc->scredit,0);
			atomic_set(&svc->fcredit,0);
		}

		sdom->scap = 0U;
		sdom->fcap = 0U;
	}
}

//change dom configuration
void change_dom_config(int dom, int config, int val, int val2)
{
	struct domain *d;
	struct csched_dom *sdom;
	int cpu = 0;
	struct csched_private *prv = CSCHED_PRIV(per_cpu(scheduler, cpu));

	for_each_domain( d )
	{
		sdom = CSCHED_DOM(d);
		if(d->domain_id == dom){
			if(config == 1){//change dom weights
				prv->eweight -= sdom->eweight;
				sdom->eweight = val;
				prv->eweight += sdom->eweight;
			}
			else if(config == 2){//update speeds
				/*sdom->elastic_speed = val;*/
				sdom->epriority = val;
				update_priority_list();
			}
			else if(config == 3){//update caps
				sdom->scap= val;
				sdom->fcap= val2;
			}
			else if(config == 4){//update caps
				espeed_step = val;
				espeed_min = val;
			}
			if (hetero_visor_active){
				if(hetero_debug_level >= 0)
					printk(KERN_INFO "config change %d %d %d\n",dom,val,val2);
			}
			break;
		}
	}
}

void change_hetero_config(int config, int arg, int arg2, int arg3)
{
	if(config == 1){//update big core count
		if(arg >= 0 && arg3 > 0 && arg2 > 0){
			num_active_cpus = arg3;
			big_core_count = arg;
			num_sockets = arg2;
			setup_hetero_cores();
		}
		WARN_ON(arg < 0 || arg3 <= 0 || arg2 <= 0);
	}
	else if(config == 2){
		hetero_sched_active = arg;//enable hetero scheduling
		hetero_hcredit_policy = arg2;//enable hcredit distribtuion 
	}
	else if(config == 3){
		hetero_speed_ratio = arg;
	}

	if(hetero_debug_level >= 0)
		printk(KERN_INFO "hetero config change %d %d %d\n",config,arg,arg2);
}

//change dom config based on Q-state change
uint16_t change_estate(int resource, int state, XEN_GUEST_HANDLE(void) cap)
{
	struct vcpu *v = current;
	struct csched_dom *sdom = CSCHED_DOM(v->domain);
	uint64_t mytime, mysec;
	struct ecap caps;
	uint16_t num_small_cores = num_active_cpus - big_core_count;
	int max_speed = 100;
	rdtscll(mytime);
	mysec = tsc_ticks2ns(mytime)/1000000;

	if(hetero_visor_active){
	sdom->estate = state;

	if(resource == 0)//cpu
	{
		if(sdom->vcpu_count > 0)
			max_speed = (100*(big_core_count * hetero_speed_ratio + min(num_small_cores,max(0, sdom->vcpu_count - big_core_count))))/sdom->vcpu_count;
		else
			max_speed = 100;

		if(state == EUP)
		{
			sdom->guest_speed += espeed_step;
			if(sdom->guest_speed > max_speed) 
				sdom->guest_speed = max_speed;
		}
		else if(state == EDN)
		{
			sdom->guest_speed -= espeed_step;
			if(sdom->guest_speed < espeed_min)
				sdom->guest_speed = espeed_min;
		}
		else if(state == ENC)
		{
		}
		if(hetero_debug_level >= 1)
			printk(KERN_INFO "%lu estate %d %d %d\n",mysec,v->domain->domain_id,state,sdom->guest_speed);

		caps.scap = sdom->scap;
		caps.fcap = sdom->fcap;
		__copy_to_guest(cap,&caps,1);
		return sdom->elastic_speed;
	}
	}
	if(hetero_visor_mem){
		if(state == EUP)
		{
			hetero_pages_vm_limit[sdom->dom->domain_id] += EMEM_STEP;
			if(hetero_pages_vm_limit[sdom->dom->domain_id] > EMEM_MAX)
				hetero_pages_vm_limit[sdom->dom->domain_id] = EMEM_MAX;
		}
		else if(state == EDN)
		{
			hetero_pages_vm_limit[sdom->dom->domain_id] -= EMEM_STEP;
			if(hetero_pages_vm_limit[sdom->dom->domain_id] < EMEM_MIN)
				hetero_pages_vm_limit[sdom->dom->domain_id] = EMEM_MIN;
		}
		else if(state == ENC)
		{
		}
		if(hetero_debug_level >= 1)
			printk(KERN_INFO "%lu estate %d %d %d\n",mysec,v->domain->domain_id,state);

		__copy_to_guest(cap,&caps,1);
		return hetero_pages_vm_limit[sdom->dom->domain_id];
	}
	return 0;
}

long read_perfctr(XEN_GUEST_HANDLE(void) arg){
	struct vcpu * v = current;
	struct domain *d = current->domain;
	struct perf_ctrs p[MAX_VCPUS];
	int id = 0;
	struct csched_vcpu *svc;

	for_each_vcpu( d, v )
	{
		if(id < MAX_VCPUS){	
		svc = CSCHED_VCPU(v);
		/*memcpy(&c.p[id],&(svc->pctr),sizeof(struct perf_ctrs));*/
		p[id] = *(svc->pctr);
		id++;
		}
		else
			printk("MAX_VCPUS violation\n");
	}

	/*for(id = 0; id < MAX_VCPUS; id++)*/
	/*printk("%lu %lu %lu ",p[id].active,p[id].instns,p[id].cycles);  */
	/*printk("\n");*/

	/*__copy_to_guest(arg,&c,1);*/
	__copy_to_guest(arg,p,MAX_VCPUS);
	return 0;
}

//update debug level
void change_debug_level(int arg){
	hetero_debug_level = arg;
}

//System-wide flag: disables/enables everything hetero
void enable_hetero_visor(int arg, int arg2){
	/*if(!hetero_init)*/
	 csched_hetero_init(0, 0 , 0);
	hetero_visor_active = arg;
	hetero_visor_mem = arg2;
}

//system initialization function
void csched_hetero_init(int arg1, int arg2, int arg3) {

	/*hetero_hcredit_policy = arg1;*/
	/*hetero_sched_active = arg2;*/

	setup_hetero_cores();
	update_priority_list();
	/*reset_hcredits();*/

	hetero_init = 1;

	printk(KERN_INFO "Initialized setup\n");
}
#endif

static int
csched_init(struct scheduler *ops)
{
    struct csched_private *prv;

    prv = xmalloc(struct csched_private);
    if ( prv == NULL )
        return -ENOMEM;

    memset(prv, 0, sizeof(*prv));
    ops->sched_data = prv;
    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->active_sdom);
    prv->master = UINT_MAX;

    return 0;
}

static void
csched_deinit(const struct scheduler *ops)
{
    struct csched_private *prv;

    prv = CSCHED_PRIV(ops);
    if ( prv != NULL )
        xfree(prv);
}

static void csched_tick_suspend(const struct scheduler *ops, unsigned int cpu)
{
    struct csched_pcpu *spc;

    spc = CSCHED_PCPU(cpu);

    stop_timer(&spc->ticker);
}

static void csched_tick_resume(const struct scheduler *ops, unsigned int cpu)
{
    struct csched_pcpu *spc;
    uint64_t now = NOW();

    spc = CSCHED_PCPU(cpu);

    set_timer(&spc->ticker, now + MILLISECS(CSCHED_MSECS_PER_TICK)
            - now % MILLISECS(CSCHED_MSECS_PER_TICK) );
}

static struct csched_private _csched_priv;

const struct scheduler sched_credit_def = {
    .name           = "SMP Credit Scheduler",
    .opt_name       = "credit",
    .sched_id       = XEN_SCHEDULER_CREDIT,
    .sched_data     = &_csched_priv,

    .init_domain    = csched_dom_init,
    .destroy_domain = csched_dom_destroy,

    .insert_vcpu    = csched_vcpu_insert,
    .remove_vcpu    = csched_vcpu_remove,

    .sleep          = csched_vcpu_sleep,
    .wake           = csched_vcpu_wake,
    .yield          = csched_vcpu_yield,

    .adjust         = csched_dom_cntl,

    .pick_cpu       = csched_cpu_pick,
    .do_schedule    = csched_schedule,

    .dump_cpu_state = csched_dump_pcpu,
    .dump_settings  = csched_dump,
    .init           = csched_init,
    .deinit         = csched_deinit,
    .alloc_vdata    = csched_alloc_vdata,
    .free_vdata     = csched_free_vdata,
    .alloc_pdata    = csched_alloc_pdata,
    .free_pdata     = csched_free_pdata,
    .alloc_domdata  = csched_alloc_domdata,
    .free_domdata   = csched_free_domdata,

    .tick_suspend   = csched_tick_suspend,
    .tick_resume    = csched_tick_resume,
};
