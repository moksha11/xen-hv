#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <linux/kernel_stat.h>
#include <linux/mm.h>

#include <linux/tick.h>
#include <linux/time.h>

#include <xen/xen.h>
#include <xen/interface/xen.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>

#define PROCFS_MAX_SIZE 100
#define PROCFS_NAME "qos"
#define TIMER 1000

#define ECODE 0

enum ESTATE{
	EUP = 2,
	ENC = 1,
	EDN = 0,
};

struct ecap cap;

#define NUM_ESTATES 3

#define LOAD 0
#define QOS 1

#define HIST_COUNTER 2

int espeed = 100;
int enable = 0;
int counter[NUM_ESTATES] = {0};
int qos_metric = 0, load_metric = 0;

//qos
int qos_max = 50;
int qos_min = 30;

//load
int metric = QOS;
int load_max = 90;
int load_min = 60;

module_param(enable, int, 0);
module_param(metric, int, 0);
/*module_param(metric_max, int, 0);*/
/*module_param(metric_min, int, 0);*/

static struct timer_list my_timer;

static char proc_data[PROCFS_MAX_SIZE];

static struct proc_dir_entry *proc_write_entry;

uint16_t calc_pct_metric(s64 dtop, s64 dbottom) 
{
	if (dbottom>10000)
		dbottom /= 100;
	else
		dtop *= 100;
	/* avoid division by zero */
	if (!dbottom)
		return 0;
		/*dbottom=1;*/
	dtop /= dbottom;
	return dtop;
}

DEFINE_PER_CPU(s64, idle_previous) = 0;
DEFINE_PER_CPU(s64, total_previous) = 0;

#ifndef arch_idle_time
#define arch_idle_time(cpu) 0
#endif
u64 nsecs_to_jiffies64(u64 n)
{
#if (NSEC_PER_SEC % HZ) == 0
	/* Common case, HZ = 100, 128, 200, 250, 256, 500, 512, 1000 etc. */
	return div_u64(n, NSEC_PER_SEC / HZ);
#elif (HZ % 512) == 0
	/* overflow after 292 years if HZ = 1024 */
	return div_u64(n * HZ / 512, NSEC_PER_SEC / 512);
#else
	/*
	 * Generic case - optimized for cases where HZ is a multiple of 3.
	 * overflow after 64.99 years, exact for HZ = 60, 72, 90, 120 etc.
	 */
	return div_u64(n * 9, (9ull * NSEC_PER_SEC + HZ / 2) / HZ);
#endif
}

static u64 get_idle_time(int cpu)
{
	u64 idle, idle_time = get_cpu_idle_time_us(cpu, NULL);

	if (idle_time == -1ULL) {
		/* !NO_HZ so we can rely on cpustat.idle */
		idle = kcpustat_cpu(cpu).cpustat[CPUTIME_IDLE];
		idle += arch_idle_time(cpu);
	} else
		idle = usecs_to_cputime64(idle_time);

	return idle;
}

static u64 get_iowait_time(int cpu)
{
	u64 iowait, iowait_time = get_cpu_iowait_time_us(cpu, NULL);

	if (iowait_time == -1ULL)
		/* !NO_HZ so we can rely on cpustat.iowait */
		iowait = kcpustat_cpu(cpu).cpustat[CPUTIME_IOWAIT];
	else
		iowait = usecs_to_cputime64(iowait_time);

	return iowait;
}

int get_load(int cpu)
{
	int i = cpu;
	u64 user, nice, system, idle, iowait, irq, softirq, steal;
	u64 guest, guest_nice;
	u64 sum = 0;
	s64 total_current, idle_current, idle_last, total_last;
	s64 load;

	user = kcpustat_cpu(i).cpustat[CPUTIME_USER];
	nice = kcpustat_cpu(i).cpustat[CPUTIME_NICE];
	system = kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
	idle = get_idle_time(i);
	iowait = get_iowait_time(i);
	irq = kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
	softirq = kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
	steal = kcpustat_cpu(i).cpustat[CPUTIME_STEAL];
	guest = kcpustat_cpu(i).cpustat[CPUTIME_GUEST];
	guest_nice = kcpustat_cpu(i).cpustat[CPUTIME_GUEST_NICE];

	user = cputime64_to_clock_t(user);
	nice = cputime64_to_clock_t(nice);
	system = cputime64_to_clock_t(system);
	idle = cputime64_to_clock_t(idle);
	iowait = cputime64_to_clock_t(iowait);
	irq = cputime64_to_clock_t(irq);
	softirq = cputime64_to_clock_t(softirq);
	steal = cputime64_to_clock_t(steal);
	guest = cputime64_to_clock_t(guest);
	guest_nice = cputime64_to_clock_t(guest_nice);

	sum =  user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;

	idle_last = per_cpu(idle_previous,cpu);
	total_last = per_cpu(total_previous,cpu);

	idle_current = idle - idle_last;
	total_current = sum - total_last;

	load = calc_pct_metric(total_current - idle_current,total_current);

	per_cpu(total_previous,cpu) = sum;
	per_cpu(idle_previous,cpu) = idle;

	return load;
}
static inline s64 read_tsc(void)
{
	s64 v;
	rdtscll(v);
	return v;
}

/*static inline s64 read_total_cpustat(int cpu)*/
/*{*/
/*struct kernel_cpustat *c = &kcpustat_cpu(cpu);*/
/*s64 total = c->cpustat[CPUTIME_USER] + c->cpustat[CPUTIME_NICE] + c->cpustat[CPUTIME_SYSTEM] + c->cpustat[CPUTIME_SOFTIRQ] +  c->cpustat[CPUTIME_IRQ] + c->cpustat[CPUTIME_IOWAIT] + c->cpustat[CPUTIME_STEAL] + c->cpustat[CPUTIME_GUEST] + c->cpustat[CPUTIME_IDLE];*/
/*return total;*/
/*}*/

int read_proc(char *buf,char **start,off_t offset,int count,int *eof,void *data )
{
	int len=0;
	len = sprintf(buf,"%s",proc_data);
	return len;
}

uint64_t instns[MAX_VCPUS], active[MAX_VCPUS], lmisses[MAX_VCPUS], rmisses[MAX_VCPUS], cycles[MAX_VCPUS];
bool type[MAX_VCPUS];
int load[MAX_VCPUS];

int read_perf_ctrs(void)
{
	int cpu;
	int rc, op = 0;
	struct perf_ctrs arg[MAX_VCPUS];
	int load_s = 0, load_f = 0;
	uint16_t core_f = 0, core_s = 0;
	uint64_t mem_free = global_page_state(NR_FREE_PAGES);
	load_metric = 0;

	sscanf(proc_data,"%d",&qos_metric);

	rc = HYPERVISOR_perfctr_op(op,arg);

	printk("PCTRS ");
	for_each_online_cpu(cpu){
		instns[cpu] = arg[cpu].instns;
		active[cpu] = arg[cpu].active;
		lmisses[cpu] = arg[cpu].lmisses;
		rmisses[cpu] = arg[cpu].rmisses;
		cycles[cpu] = arg[cpu].cycles;
		type[cpu] = arg[cpu].core_type;
		/*load[cpu] = get_load(cpu);*/
		load[cpu] = max(0,calc_pct_metric(active[cpu],cycles[cpu]) -1); 

		if(type[cpu] == 0){
			load_s += load[cpu];
			core_s++;
		}
		else{
			load_f += load[cpu];
			core_f++;
		}
		/*printk("[%d] %llu %llu %llu %llu %d ",cpu, instns[cpu],active[cpu],lmisses[cpu],cycles[cpu],load[cpu]);*/
		printk("%d ",load[cpu]);
	}
	load_metric += core_s*calc_pct_metric(load_s, cap.scap);
	load_metric += core_f*calc_pct_metric(load_f, cap.fcap);
	load_metric /= num_online_cpus();

	printk(" ld:%d (%d %d) qos %d f %d es %d cap %d %d  em %llu\n",load_metric,load_s,load_f,qos_metric,core_f,espeed,cap.scap,cap.fcap,(mem_free*4)/1024);
	return load_metric; 
}

int get_estate(void)
{
	int estate = 1;
	int i;

	if (!xen_domain())
		return 0;

	load_metric = read_perf_ctrs();

	if(enable){
		if(metric == QOS){
			/*if( qos_metric >= qos_max || load_metric >= load_max)*/
			if( qos_metric >= qos_max )
				estate = EUP;	
			else if(qos_metric <= qos_min && load_metric <= load_min)
				/*else if(qos_metric <= qos_min )*/
				estate = EDN;	
			else 
				estate = ENC;	
		}
		else if(metric == LOAD){
			if(load_metric >= load_max)
				estate = EUP;	
			else if( load_metric <= load_min)
				estate = EDN;	
			else 
				estate = ENC;	
		}
	}
	else 
		estate = ENC;
	for(i=0;i<NUM_ESTATES;i++){
		if(i == estate){
			counter[i]++;
			if(counter[i] > HIST_COUNTER)
				counter[i] = 1;
		}
		else
			counter[i]= 0;
	}

	return estate;
}

struct timespec now, last = {0,0};
int write_proc(struct file *file,const char *buf,unsigned long count,void *data )
{
	/*long timediff;*/
	/*if(count > MAX_PROC_SIZE)*/
	/*count = MAX_PROC_SIZE;*/

	if(copy_from_user(proc_data, buf, count))
		return -EFAULT;

	/*printk("writing to proc file %s",proc_data);*/

	/*now = current_kernel_time();*/
	/*timediff = (timespec_to_ns(&now) - timespec_to_ns(&last)) / NSEC_PER_MSEC;*/
	/*if ((timediff<TIMER) && (timediff>=0)) {*/
	/*return count;*/
	/*}*/
	/*last = now;*/

	return count;
}

void create_new_proc_entry(void) {
	proc_write_entry = create_proc_entry(PROCFS_NAME,0666,NULL);
	if(!proc_write_entry)
		printk(KERN_INFO "Error creating proc entry");
	else{
		proc_write_entry->read_proc = read_proc ;
		proc_write_entry->write_proc = write_proc;
		printk(KERN_INFO "Estate-driver init\n");
	}

}

void update_estate( unsigned long data ){
	int estate;

	estate = get_estate();

	if(counter[estate] == HIST_COUNTER){
		espeed = HYPERVISOR_estate_op(ECODE,estate,&cap);
		printk("Estate %d qos %d (%d %d) load %d (%d %d) \n",estate,qos_metric,qos_min,qos_max,load_metric,load_min,load_max);
	}

	/*printk("return speed:%d",espeed);*/
	mod_timer( &my_timer, jiffies + msecs_to_jiffies(TIMER) );
}

int estate_init (void) {
	int ret =0;

	if(num_online_cpus() > MAX_VCPUS)
		printk("Fix CPU count\n");

	setup_timer( &my_timer, update_estate , 0 );
	ret = mod_timer( &my_timer, jiffies + msecs_to_jiffies(TIMER) );

	create_new_proc_entry();
	return ret;
}

void estate_cleanup(void) {
	int ret;
	printk(KERN_INFO "Estate-driver unload\n");

	ret = del_timer( &my_timer );
	remove_proc_entry(PROCFS_NAME,NULL);
}

MODULE_LICENSE("GPL");   
module_init(estate_init);
module_exit(estate_cleanup);
