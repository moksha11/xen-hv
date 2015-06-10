#ifndef HETEROVISOR_H
#define HETEROVISOR_H

#define HETERO_VISOR
#define HETERO_VISOR_STATS

/*#define BIG_CORE_COUNT 2 */
#define SCHED_TICK_COUNT 10
#define DEBUG_TICK_COUNT 33
#define PCTR_TICK_COUNT 33
#define HCREDIT_TICK_COUNT 10
#define HWCNTRS_PRINT_TICKS 100
/*#define TOTAL_SCREDITS 3000*/
/*#define TOTAL_FCREDITS 3000*/
#define HCREDITS_PER_TICK 300
#define HCREDITS_MIN 300
#define HCREDITS_MAX 2400
#define HCREDITS_STEP 300
#define HCREDITS_THRESHOLD 150
#define HCREDITS_NILL 0
#define MIN_HCREDITS 0
#define MIG_COUNT 3

#define MAX_VCPUS 12

/*#define LOCAL 0*/
/*#define REMOTE 1*/

#define SMALL 0
#define BIG 1

#define EMEM_MIN  1
#define EMEM_MAX 32768 
#define EMEM_STEP 1024

enum ESTATE{
EUP = 2,
ENC = 1,
EDN = 0,
};

struct ecap{
	uint16_t scap;
	uint16_t fcap;
};

//per-vcpu counters
struct perf_ctrs{
	uint64_t instns;
	uint64_t active;
	uint64_t lmisses;
	uint64_t rmisses;
	uint64_t cycles;
	bool_t core_type;
};

struct counters{
	uint64_t dinst;
	uint64_t dcycles;
	uint64_t dlmisses;
	uint64_t drmisses;
	uint64_t dmperf;
	uint64_t dtsc;
	uint64_t last_update;
};

/*struct dom_ctrs{*/
/*struct perf_ctrs p[MAX_VCPUS];*/
/*};*/

extern bool_t hetero_sched_active;
extern uint16_t hetero_debug_level;
extern uint16_t hetero_sched_mode;
extern uint16_t hetero_power_tick;
extern uint16_t hetero_debug_tick;
extern uint16_t hetero_pcredit_policy;

DECLARE_PER_CPU(uint64_t,dmperf);
DECLARE_PER_CPU(uint64_t,dtsc);
DECLARE_PER_CPU(uint64_t,dinst);
DECLARE_PER_CPU(uint64_t,dcycles);
DECLARE_PER_CPU(uint64_t,dlmisses);
DECLARE_PER_CPU(uint64_t,drmisses);

extern s64 calc_pct_metric(s64 dtop, s64 dbottom);
void fast_vcpu_list(struct domain *d,int update, int count);
int hetero_vcpu_migrate(struct vcpu *, cpumask_t *);
unsigned long get_core_power(void);
unsigned long get_mem_power(void);
void update_counters_cpu(void *);
void change_dom_config(int dom, int config, int val, int val2);
void csched_hetero_init(int arg1, int arg2, int arg3);
uint16_t change_estate(int resource, int state, XEN_GUEST_HANDLE(void) ecap);
void change_debug_level(int arg);
void change_hetero_config(int arg, int arg2, int arg3, int arg4);
void enable_hetero_visor(int arg, int arg2);
long read_perfctr(int op, XEN_GUEST_HANDLE(void) arg);
int hsm_trylock();
int hsm_unlock();

#endif

