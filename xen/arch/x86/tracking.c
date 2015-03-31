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

#ifdef ENABLE_TRACK_SPINLOCK
s_time_t track_spinlock_time[MAX_TRACK_SPINLOCK];
int track_spinlock[MAX_TRACK_SPINLOCK];
int track_spinlock_total[MAX_TRACK_SPINLOCK];

extern void mydump_registers(void);
void myspin_lock(spinlock_t *_lock, int loc) {

#ifdef SUD_DISABLE_SPINLOCK
	if (spin_trylock(_lock)) {
		return;
	}
#else

try_lock:
	if (!spin_trylock(_lock)) {
		int i = 0, count = 0;
		s_time_t prev=NOW();
		track_spinlock[loc]++;
		while(1) {
			if (spin_trylock(_lock))
				break;
			i++;


			if (i>=5000000) {
				myprintk("WARN deadlock? %d@%d waiting. holder:%d@%d\n", loc, smp_processor_id(), (_lock)->location, (_lock)->proc);
				i=0;
				count++;

				if (count > 100){
					 myprintk("WARN deadlock? %d@%d waiting. holder:%d@%d\n", loc, smp_processor_id(), (_lock)->location, (_lock)->proc);
					 spin_unlock(_lock);
					 //goto try_lock;
				}

				if (count > 100) {
					//mypanic("spinlock limit hit\n");
				}
			}

		}
		track_spinlock_time[loc] += (NOW()-prev);
	}
	track_spinlock_total[loc]++;
	(_lock)->location = loc;
	(_lock)->proc = smp_processor_id();
#endif
}

void spinlock_report(void)
{
	int i;

	myprintk("--track_spinlock report--.\n");
	for(i=0;i<MAX_TRACK_SPINLOCK;i++) {
		if (track_spinlock_time[i]/1000000ULL) {
			myprintk("spinlock[%d]=%4lldms@%d/%d\n", i, track_spinlock_time[i]/1000000ULL, track_spinlock[i], track_spinlock_total[i]);
		}
	}
	myprintk("--End of track_spinlock--\n");
}

void init_track_spinlock(void)
{
	int i;
	for(i=0;i<MAX_TRACK_SPINLOCK;i++) {
		track_spinlock_time[i] = 0ULL;
		track_spinlock_total[i] = track_spinlock[i] = 0;
	}
}
#endif


#ifdef ENABLE_TRACK_MEMLEAK
atomic_t track_memleak[MAX_TRACK_MEMLEAK];
int track_memleak_size[MAX_TRACK_MEMLEAK];	// size of each type

void memleak_report(void)
{
	int i, temp;
	int total = 0;

	myprintk("--Memleak report--"
#ifdef ENABLE_VREGIONS
		", %d free_vr\n", vregions_free_count
#else
		"\n"
#endif
		);
	for(i=0;i<MAX_TRACK_MEMLEAK;i++) {
		if (atomic_read(&track_memleak[i])) {
			temp = atomic_read(&track_memleak[i])*track_memleak_size[i];
			myprintk("memleak[%d]=%d * size=%d => %d\n", i, atomic_read(&track_memleak[i]), track_memleak_size[i], temp);
			total += temp;
		}
	}
	myprintk("--End of memleak, total=%d --\n", total);
}

/* Return size, increased to alignment with align. */
static inline size_t align_up(size_t size, size_t align)
{
    return (size + align - 1) & ~(align - 1);
}
struct xmalloc_hdr
{
    /* Size is total including this header. */
    size_t size;
    struct list_head freelist;
} __cacheline_aligned;

void init_track_memleak(void)
{
	int i;
	for(i=0;i<MAX_TRACK_MEMLEAK;i++) {
		atomic_set(&track_memleak[i], 0);
		track_memleak_size[i] = 0;
	}
}
void init_track_memleak_size(void)
{
	int i;
	track_memleak_size[1] = sizeof(struct rmap_set)+MAX_RMAP_ENTRIES_IN_SET*sizeof(unsigned long);
	track_memleak_size[2] = sizeof(struct vregion_t);
	track_memleak_size[3] = sizeof(struct page_table);
	track_memleak_size[4] = sizeof(struct page_dir);
	track_memleak_size[5] = sizeof(struct vregion_t *) * max_page;
	track_memleak_size[6] = sizeof(struct vregion_t)*num_vregions_per_1mb;
//	track_memleak_size[7] = sizeof(struct task);
	track_memleak_size[8] = sizeof(struct l1e_struct);
	track_memleak_size[9] = PAGE_SIZE;

	for(i=0;i<MAX_TRACK_MEMLEAK;i++) {
		int size = track_memleak_size[i];
		myprintk("original memleak[%d]=%d, alignof=%d\n", i, track_memleak_size[i], __alignof__(struct xmalloc_hdr) );
		size += sizeof(struct xmalloc_hdr);
		size = align_up(size, __alignof__(struct xmalloc_hdr));
		track_memleak_size[i] = size;
	}
}
#endif

