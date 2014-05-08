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

#ifdef ENABLE_TIMESTAMP
//#define ENABLE_TIMESTAMP_CYCLE
DEFINE_PER_CPU(struct timestamp_t, timestamp);

void init_timestamp(struct timestamp_t *timestamp)
{
	int i, j;
	for(i=0;i<MAX_TIMESTAMP_ID;i++) {
		timestamp->runs[i] = timestamp->unfinished[i] = 0;
		for(j=0;j<MAX_TIMESTAMP_LOC;j++) {
			timestamp->time[i][j] = timestamp->sum[i][j] = 0;
			timestamp->count[i][j] = 0;
		}
	}
}

void _timestamp(struct timestamp_t *ts, int id, int loc)
{
	MYASSERT(loc > 0 && loc < MAX_TIMESTAMP_LOC );	// can't be 0
	MYASSERT(id >= 0 && id  < MAX_TIMESTAMP_ID  );
#ifdef ENABLE_TIMESTAMP_CYCLE
	rdtscll(ts->time[id][loc]);
#else
//	if (ts->time[id][loc-1])	// only when it passed last point
		ts->time[id][loc] = NOW();
#endif
}

void _timestamp_start(struct timestamp_t *ts, int id)
{
	int i;
	if (ts->time[id][0]) {
		ts->unfinished[id]++;
	}
	ts->runs[id]++;
	for(i=1;i<MAX_TIMESTAMP_LOC;i++) {
		ts->time[id][i] = 0;
	}
#ifdef ENABLE_TIMESTAMP_CYCLE
	rdtscll(ts->time[id][0]);
#else
	ts->time[id][0] = NOW();
#endif
}

void _timestamp_end(struct timestamp_t *ts, int id, int loc)
{
	int i;
	s_time_t start = ts->time[id][0];
	for(i=0;i<MAX_TIMESTAMP_LOC;i++) {
		if (i>=loc && ts->time[id][i])
			mypanic("bug\n");
		if (i<loc && ts->time[id][i] == 0) {
		//	myprintk("INFO: dropped incomplete path\n");
			ts->time[id][0] = 0;
			return;
		}
	}
	for(i=1;i<loc;i++) {
		s_time_t diff;
		MYASSERT(ts->time[id][i] >= ts->time[id][i-1]);	// this might not be true for vtimestamp because of skew, right?
		diff = ts->time[id][i] - start;
		ts->sum[id][i] += diff;
		ts->count[id][i]++;
		ts->time[id][i] = 0;
//		if (id == 0) {
//			myprintk("diff:%4lldus\n", diff/1000ULL);
//		}
	}
	ts->time[id][0] = 0;
}
inline void timestamp(int id, int loc) {
	_timestamp(&this_cpu(timestamp), id, loc);
}
inline void timestamp_start(int id) {
	_timestamp_start(&this_cpu(timestamp), id);
}
inline void timestamp_end(int id, int loc) {
	_timestamp_end(&this_cpu(timestamp), id, loc);
}

inline void vtimestamp(int id, int loc) {
	_timestamp(&current->timestamp, id, loc);
}
inline void vtimestamp_start(int id) {
	_timestamp_start(&current->timestamp, id);
}
inline void vtimestamp_end(int id, int loc) {
	_timestamp_end(&current->timestamp, id, loc);
}




void _print_timestamp(struct timestamp_t *ts, char *s)
{
	int i, id;

	for(id=0;id<MAX_TIMESTAMP_ID;id++) {
	if (ts->runs[id] == 0)
		continue;
	myprintk("%s [%s] runs:%d (has unfi:%d)\n",s, timestamp_name[id], ts->runs[id], ts->unfinished[id]);
	for(i=0;i<MAX_TIMESTAMP_LOC;i++) {
		if (ts->sum[id][i] == 0)
			continue;
#ifdef ENABLE_TIMESTAMP_CYCLE
#define TIMESTAMP_UNIT "Kcycle"
#else
#define TIMESTAMP_UNIT "us"
#endif
		myprintk("%2d: %lld " TIMESTAMP_UNIT " / %d = ", i, ts->sum[id][i]/1000ULL , ts->count[id][i] );
		if (ts->count[id][i]) {
			printk("%lld\n", (ts->sum[id][i]/ts->count[id][i])/1000ULL );
		} else {
			printk("Nan\n");
		}
	}
	}
}
void print_timestamp(void)
{
	int i,j;
	myprintk("--- timestamp ---\n");
	char temp[32];
	for(j=0;j<max_proc;j++) {
		snprintf(temp, 32, "P%d", j);
		_print_timestamp(&per_cpu(timestamp, j), temp);
	}

	struct vcpu *v;
	struct domain *d;
	rcu_read_lock(&domlist_read_lock);
	for_each_domain_vcpu(d,v) {
		snprintf(temp, 32, "d%dv%d", d->domain_id, v->vcpu_id);
		_print_timestamp(&v->timestamp, temp);
	}
	rcu_read_unlock(&domlist_read_lock);
}
#endif
