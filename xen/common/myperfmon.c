/*#include <xen/init.h>*/
/*#include <xen/config.h>*/
/*#include <xen/lib.h>*/
#include <xen/sched.h>
/*#include <xen/domain.h>*/
/*#include <xen/sched-if.h>*/
#include <xen/heterovisor.h>

DEFINE_PER_CPU(bool_t, setup_perfmon) = 0;

#define EVENT_LLC_MISS 0x2E
#define UMASK_LLC_MISS (0x41 << 8) /* LLC miss */ 

#define EVENT_LLC_REF 0x2E
#define UMASK_LLC_REF (0x4F << 8) /* LLC ref */ 

/*#define EVENT_L2_LINES_IN 0x24*/
/*#define UMASK_L2_LINES_IN (0xD0 << 8) *//* LLC miss  */ 

#define EVENT_L2_LINES_IN 0x2E
#define UMASK_L2_LINES_IN (0x41 << 8) /*  */ 

#define EVENT_L2_RQSTS 0x2E
#define UMASK_L2_RQSTS (0x7f << 8) /* LLC ref */ 

/*#define EVENT_L2_LD 0x29*/
/*#define UMASK_L2_LD (0x7f << 8) *//*  */ 

/*#define EVENT_BUS_TRANS_MEM 0x6F*/
/*#define UMASK_BUS_TRANS_MEM (0x80 << 8) *//*  */ 

#define EVENT_BRCH_RETIRED 0xC4
#define UMASK_BRCH_RETIRED (0x00 << 8) /*  */ 

#define EVENT_BRCH_MISSP_RETIRED 0xC5
#define UMASK_BRCH_MISSP_RETIRED (0x00 << 8) /*  */ 

/*#define EVENT_MEM_LOAD_RETIRED 0xCB*/
/*#define UMASK_L2_HIT (0x01 << 8) *//*  */ 

/*#define EVENT_MEM_LOAD_RETIRED 0xCB*/
/*#define UMASK_L2_MISS (0x02 << 8) *//*  */ 

#define EVENT_OFFCORE_RESP 0xB7
#define UMASK_OFFCORE_RESP (0x01 << 8) /*  */ 

#define PERFMON_ALL_RINGS (3 << 16)
#define CCCR_ENABLE_P6_CTR  ( 1 << 22 )

#define EVT_PCTR0 UMASK_LLC_MISS | EVENT_LLC_MISS | PERFMON_ALL_RINGS | CCCR_ENABLE_P6_CTR;
/*#define EVT_PCTR1 UMASK_L2_RQSTS | EVENT_L2_RQSTS | PERFMON_ALL_RINGS | CCCR_ENABLE_P6_CTR;*/
/*#define EVT_PCTR1 UMASK_LLC_REF | EVENT_LLC_REF | PERFMON_ALL_RINGS | CCCR_ENABLE_P6_CTR;*/
#define EVT_PCTR1 UMASK_OFFCORE_RESP | EVENT_OFFCORE_RESP | PERFMON_ALL_RINGS | CCCR_ENABLE_P6_CTR;

/*
 * ipc
 */

DEFINE_PER_CPU(u64, tsc_prev);
DEFINE_PER_CPU(u64, mperf_prev);
DEFINE_PER_CPU(u64, retired_prev);
DEFINE_PER_CPU(u64, unhalted_prev);
/*DEFINE_PER_CPU(u64, unhalted_ref_prev);*/
DEFINE_PER_CPU(u64, pctr1_prev);
DEFINE_PER_CPU(u64, pctr0_prev);

DEFINE_PER_CPU(u64, dmperf);
DEFINE_PER_CPU(u64, dtsc);
DEFINE_PER_CPU(u64, dinst);
DEFINE_PER_CPU(u64, dcycles);
DEFINE_PER_CPU(u64, dlmisses);
DEFINE_PER_CPU(u64, drmisses);

#define CTR_MASK 0xffffffffffffffff /* 64 bits */
#define CTR_EXTEND 0xffffffffffffffff /* 64 bits */

//ipc projection constants
uint16_t perf_alpha[2] = {151,64 };
uint16_t perf_beta[2] = { 88,105};

static void init_perf_ctrs(void)
{
	u64 fixed, global, evt_pctr0, evt_pctr1;
	u64 u;
	/*int cpu = smp_processor_id();*/

	preempt_disable();

	rdmsrl(MSR_CORE_PERF_FIXED_CTR_CTRL, fixed);
	// fix ctr 0 inst and fix ctr 1 unhalted  and fix ctr 2 unhalted ref
	fixed = fixed |3 | ((3<<4) | (3<<8));
	wrmsrl(MSR_CORE_PERF_FIXED_CTR_CTRL, fixed);

	rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, global);
	global = global | (7UL<<32);
	wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, global);

	evt_pctr0 = EVT_PCTR0;
	evt_pctr1 = EVT_PCTR1;

	wrmsrl(MSR_P6_EVNTSEL0,evt_pctr0);

	rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL,evt_pctr0);
	evt_pctr0 |= 1;
	wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL,evt_pctr0);

	wrmsrl(MSR_P6_EVNTSEL1,evt_pctr1);

	rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL,evt_pctr1);
	evt_pctr1 |= 2;
	wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL,evt_pctr1);

	/* initialize the counters */
	rdtscll(__get_cpu_var(tsc_prev));

	rdmsrl(MSR_IA32_MPERF, u);
	__get_cpu_var(mperf_prev) = u;

	rdmsrl(MSR_CORE_PERF_FIXED_CTR0, u);
	__get_cpu_var(retired_prev) = u;

	rdmsrl(MSR_CORE_PERF_FIXED_CTR1, u);
	__get_cpu_var(unhalted_prev) = u;

	/*rdmsrl(MSR_CORE_PERF_FIXED_CTR2, u);*/
	/*__get_cpu_var(unhalted_ref_prev) = u;*/

	rdmsrl(MSR_P6_PERFCTR0, u);
	__get_cpu_var(pctr0_prev) = u;

	rdmsrl(MSR_P6_PERFCTR1, u);
	__get_cpu_var(pctr1_prev) = u;

	__get_cpu_var(setup_perfmon)=1;
	preempt_enable();
}

static inline s64 read_retired(void)
{
	u64 u;

	rdmsrl(MSR_CORE_PERF_FIXED_CTR0, u);
	return u;
}

static inline s64 read_unhalted(void)
{
	u64 u;

	rdmsrl(MSR_CORE_PERF_FIXED_CTR1, u);
	return u;
}

static inline s64 read_unhalted_ref(void)
{
	u64 u;

	rdmsrl(MSR_CORE_PERF_FIXED_CTR2, u);
	return u;
}

static inline s64 read_tsc(void)
{
	u64 u;
	rdtscll(u);
	return u;
}

static inline s64 read_mperf(void)
{
	u64 u;
	rdmsrl(MSR_IA32_MPERF,u);
	return u;
}

static inline s64 read_pctr1(void)
{
	s64 v;
	rdmsrl(MSR_P6_PERFCTR1,v);
   return v;
}

static inline s64 read_pctr0(void)
{
	s64 v;
	rdmsrl(MSR_P6_PERFCTR0,v);
   return v;
}

s64 subtract(s64 a, s64 b)
{
	if (a>b)
		return a-b;
	else
		return 0;
}

s64 calc_pct_metric(s64 dtop, s64 dbottom) 
{
	if (dbottom>10000)
		dbottom /= 100;
	else
		dtop *= 100;
	/* avoid division by zero */
	if (!dbottom)
		dbottom=1;
		dtop /= dbottom;
	return dtop;
}

/*static void update_counters_cpu(void *data)*/
void update_counters_cpu(void *data)
{
	u64 tsc, unhalted, retired, pctr1, pctr0, mperf;
	s64 d_tsc, d_unhalted, d_retired, d_pctr1, d_pctr0, d_mperf;
	/*u64 max_cycles;*/

	int cpu = smp_processor_id(); 
	/*uint16_t history_pointer = __get_cpu_var(history_buffer_pointer);*/

	//setup msrs for counters
	if (!__get_cpu_var(setup_perfmon)) 
		init_perf_ctrs();

	preempt_disable();

	/* read the counters */
	tsc = read_tsc();
	mperf = read_mperf();
	retired = read_retired();
	unhalted = read_unhalted();
	/*unhalted_ref = read_unhalted_ref();*/
	pctr1 = read_pctr1();
	pctr0 = read_pctr0();

	/* calculate the diffs */
	d_tsc = tsc - __get_cpu_var(tsc_prev);

	d_mperf = mperf - __get_cpu_var(mperf_prev);

	d_retired = retired - __get_cpu_var(retired_prev);
	if (d_retired < 0) /* handles counter wrap */
		d_retired += CTR_EXTEND;

	d_unhalted = unhalted - __get_cpu_var(unhalted_prev);
	if (d_unhalted < 0) /* handles counter wrap */
		d_unhalted += CTR_EXTEND;

	d_pctr1 = pctr1 - __get_cpu_var(pctr1_prev);
	if (d_pctr1 < 0) /* handles counter wrap */
		d_pctr1 += CTR_EXTEND;

	d_pctr0 = pctr0 - __get_cpu_var(pctr0_prev);
	if (d_pctr0 < 0) /* handles counter wrap */
		d_pctr0 += CTR_EXTEND;

	/* and update the previous counter values */
	__get_cpu_var(tsc_prev) = tsc;
	__get_cpu_var(mperf_prev) = mperf;
	__get_cpu_var(retired_prev) = retired;
	__get_cpu_var(unhalted_prev) = unhalted;
	/*__get_cpu_var(unhalted_ref_prev) = unhalted_ref;*/
	__get_cpu_var(pctr1_prev) = pctr1;
	__get_cpu_var(pctr0_prev) = pctr0;

	__get_cpu_var(dmperf) = d_mperf;
	__get_cpu_var(dtsc) = d_tsc;
	__get_cpu_var(dinst) = d_retired;
	__get_cpu_var(dcycles) = d_unhalted;
	__get_cpu_var(dlmisses) = d_pctr0;
	__get_cpu_var(drmisses) = d_pctr1;

	if(hetero_debug_level >= 3)
			printk("cpu %d tsc %ld mperf %ld inst %ld cycle %ld pctr0 %ld pctr1 %ld\n",cpu,d_tsc/1000,d_mperf/1000,d_retired/1000,d_unhalted/1000,d_pctr0/1000,d_pctr1/1000);
	preempt_enable();
}
