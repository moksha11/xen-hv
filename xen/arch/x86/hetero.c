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

#define HETERO_SYNC1	// first try
#define HETERO_SYNC2

#ifdef ENABLE_HETERO
atomic_t hetero_pages_count;
atomic_t hetero_pages_vm[MAX_HETERO_VM];
int hetero_pages_vm_limit[MAX_HETERO_VM];
int hetero_pages_vm_expect[MAX_HETERO_VM];
int vm_tot_pages[MAX_HETERO_VM];
static spinlock_t hetero_lock;

atomic_t hot_pages_vm[MAX_HETERO_VM];

#ifdef HETERO_SYNC1
static atomic_t simple_barrier;
static void hetero_wait(void *unused)
{
	atomic_dec(&simple_barrier);
	flush_tlb_local();
//	myprintk("hetero_wait\n");
	myspin_lock(&hetero_lock, 63);
	spin_unlock(&hetero_lock);
}
#endif

void hetero_adjust_limit(int domid, int delta)
{
	hetero_pages_vm_limit[domid] += delta;
}

void hetero_initialize(void)
{
	int i;
	for(i=0;i<max_page;i++) {
		FTABLE_HETERO(i) = 0;
	}
	atomic_set(&hetero_pages_count, 0);
	for(i=0;i<MAX_HETERO_VM;i++) {
		atomic_set(&hetero_pages_vm[i], 0);
		hetero_pages_vm_limit[i] = 0;	// initially no limit
		hetero_pages_vm_expect[i] = 0;
		vm_tot_pages[i] = 0;
		atomic_set(&hot_pages_vm[i], 0);
	}
#if 0	// for test
hetero_pages_vm_limit[0] = 64;
hetero_pages_vm_limit[1] = 2048;
hetero_pages_vm_limit[2] = 2048;
hetero_pages_vm_limit[3] = 2048;
#endif
	spin_lock_init(&hetero_lock);
}

/*
void hetero_free(unsigned long mfn)
{
	// TODO: synchronize.. and ordering.. compare to alloc part..
	unsigned int hetero_mfn = FTABLE_HETERO(mfn);
	if (hetero_mfn) {
		atomic_dec(&hetero_pages_count);
TODO		atomic_dec(&hetero_pages_vm); or vm_limit
		MYASSERT(FTABLE_HETERO(mfn) != 0);
		FTABLE_HETERO(mfn) = 0;
		myfree_xenheap_page(mfn_to_virt(hetero_mfn), 10);
	}
}
*/

int less_than_limit(int mfn)
{
		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				if (hetero_pages_vm_limit[vm_id] == 0)
					return 1;
				if (hetero_pages_vm_expect[vm_id] == 0)
					hetero_pages_vm_expect[vm_id] = atomic_read(&hetero_pages_vm[vm_id]);
				if (hetero_pages_vm_expect[vm_id] == hetero_pages_vm_limit[vm_id])
					return -1;
				if (hetero_pages_vm_expect[vm_id] < hetero_pages_vm_limit[vm_id]) {
					hetero_pages_vm_expect[vm_id]++;
					return 1;
				} else {
					hetero_pages_vm_expect[vm_id]--;
					return 0;
				}
			} else {
				myprintk("WARN invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("WARN null owner..mfn:%lx\n", mfn);
		}
		return 0;
}

// vr->lock is held when called.
static int hetero(unsigned int mfn, int add /* 1 for add, 0 for del */)
{
	struct rmap_set *rms;
	int i,j;
	struct page_table *pt;
	int pti;
	int rmap_count = 0;
	struct rmaps_builtin *r;

	r = &FTABLE_RMAPS(mfn, RMAPS_USER);
#if 1	// just in case that rmap_count is huge...
	if (r->rmap_count > 200) {
		myprintk("skip %d rmaps..\n", r->rmap_count);
		return 0;
	}
#endif
	unsigned long new_mfn;
	if (add) {
		void *p;
#ifdef ENABLE_MULTI_NODE
		p = alloc_xenheap_pages(0,MEMF_node(FAST_MEMORY_NODE));
#else
		p = myalloc_xenheap_page(10);
#endif
		MYASSERT(p);
		new_mfn = virt_to_mfn(p);
		memcpy(p, mfn_to_virt(mfn), PAGE_SIZE);

		atomic_inc(&hetero_pages_count);

		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				vm_tot_pages[vm_id] = vm->tot_pages;
				atomic_inc(&hetero_pages_vm[vm_id]);
			} else {
				myprintk("WARN invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("WARN null owner..mfn:%lx\n", mfn);
		}

		MYASSERT(FTABLE_HETERO(mfn) == 0);
		FTABLE_HETERO(mfn) = new_mfn;	// TODO: synchronize
	} else {
		new_mfn = mfn;
	}

	list_for_each_entry(rms, &r->rmaps_list, list) {
		for(i=0;i<rms->size;i++) {
			pt = rme_pt(rms->rmaps[i]);
			pti = rme_pti(rms->rmaps[i]);
			if (!pt)
				continue;
			for(j=0;j<max_cache;j++) {
			l1_pgentry_t *l1t = (l1_pgentry_t *)pt->shadow[j];
#ifdef DEBUG_ASSERT
//			unsigned long l1_mfn = l1e_get_pfn(l1t[pti]);
//			MYASSERT(l1_mfn == mfn);
			rmap_count++;
#endif
			l1t[pti] = l1e_from_pfn(new_mfn , l1e_get_flags(l1t[pti]));
//			myprintk("(vr:%p up_pt:%p ptmfn:%lx pti:%3x mfn:%3lx ) va:%lx\n", vr, pt->up_pt, pt->mfn, pti, l1_mfn, get_va(pt, pti) );
			
			}
		}
	}

	if (!add) {
		unsigned int hetero_mfn = FTABLE_HETERO(mfn);
		MYASSERT(hetero_mfn != 0);
		atomic_dec(&hetero_pages_count);
		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				vm_tot_pages[vm_id] = vm->tot_pages;
				atomic_dec(&hetero_pages_vm[vm_id]);
			} else {
				myprintk("WARN dec invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("WARN dec null owner..mfn:%lx\n", mfn);
		}

		FTABLE_HETERO(mfn) = 0;

		void *p;
		p = mfn_to_virt(hetero_mfn);
		memcpy(mfn_to_virt(mfn), p, PAGE_SIZE);
		myfree_xenheap_page(mfn_to_virt(hetero_mfn), 10);
	}
	return rmap_count;
}

#endif

#define MAX_SCAN	2048	// scan up to this number of pages..
#define MAX_TEMP_MFNS	1024
#define TIME_WINDOW	3000	// in millisec
// vr->lock is held when called.
static int scan_hot_pages(s_time_t now, struct vregion_t *vr, unsigned int *mfns, char *flag, int *migrate)
{
#ifdef DEBUG_ASSERT
	if (!spin_is_locked(&vr->lock))
		mypanic("scan_hot_pages:grep vr->lock first!");
#endif
	int frame_count = 0;
	*migrate = 0;
	if (vr->head == -1)
		return 0;
	int start = FTABLE_PREV(vr->head);	// reverse looping
	int cur = start;

	s_time_t time;
	int ret = 0;
#define HETERO_PAGE_VM_LIMITS
#ifdef HETERO_PAGE_VM_LIMITS
	int within_limit;
#endif
	do {
	frame_count++;
	time = ((unsigned long)FTABLE_TIME(cur) << 20);
#ifdef HETERO_PAGE_VM_LIMITS
	within_limit = less_than_limit(cur);
#endif
	// TODO: refcnt?
	if (time + MILLISECS(TIME_WINDOW) < now) {
		flag[ret] = 0;
		mfns[ret++] = cur;
#ifdef ENABLE_HETERO
		if (FTABLE_HETERO(cur))
			*migrate = 1;
#endif
	}
#ifdef ENABLE_HETERO
	else {
		if (!FTABLE_HETERO(cur)) {
#ifdef HETERO_PAGE_VM_LIMITS
			if (within_limit == 1) {
#endif
			flag[ret] = 1;
			mfns[ret++] = cur;
			*migrate = 1;
#ifdef HETERO_PAGE_VM_LIMITS
			}
#endif
		} else {
#ifdef HETERO_PAGE_VM_LIMITS
			if (within_limit == 0) {
				flag[ret] = 0;
				mfns[ret++] = cur;
				*migrate = 1;
			}
#endif
		}
	}
#endif
	cur = FTABLE_PREV(cur);	// reverse looping
	if (ret >= MAX_TEMP_MFNS || frame_count >= MAX_SCAN) {	// note that clear_abit() keeps adding to list..
		vr->head = cur;	// set head
		break;
	}
	} while(cur != start);
//	if (frame_count)
//		myprintk("%d hot pages scanned, mig=%d\n", frame_count, *migrate);
	return ret;
}

DEFINE_PER_CPU(unsigned int [MAX_TEMP_MFNS], mfns_from_hot_list);
DEFINE_PER_CPU(char [MAX_TEMP_MFNS], flag_from_hot_list);

void shrink_hot_pages(s_time_t now)
{
	unsigned int *mfns = per_cpu(mfns_from_hot_list, smp_processor_id());
	char *flag = per_cpu(flag_from_hot_list, smp_processor_id());
//	unsigned int (*mfns)[MAX_TEMP_MFNS] = &(per_cpu(mfns_from_hot_list, smp_processor_id()));
//	char (*flag)[MAX_TEMP_MFNS] = &(per_cpu(flag_from_hot_list, smp_processor_id()));
	int i, ret, migrate;
#ifdef HETERO_PAGE_VM_LIMITS
	for(i=0;i<MAX_HETERO_VM;i++) {
		hetero_pages_vm_expect[i] = 0;
	}
#endif
	myspin_lock(&seed_user_hot->lock, 29);
	ret = scan_hot_pages(now, seed_user_hot, mfns, flag, &migrate);
#ifdef ENABLE_HETERO
	if (migrate)	// true if any copy is necessary..
	{
#ifdef ENABLE_TIMESTAMP
	timestamp_start(TIMESTAMP_PAGE_MIGRATE);
#endif
#ifdef HETERO_SYNC1
	atomic_set(&simple_barrier, max_proc-1);
	if (!myspin_trylock(&hetero_lock, 34)) {
		mypanic("TODO skip hetero() call to avoid deadlock..\n");
		return;
	}
	smp_call_function(hetero_wait, NULL, 0);
#ifdef HETERO_SYNC2
	for(;atomic_read(&simple_barrier););	// wait for others
#endif
//	myprintk("all reached here\n");
#endif
	int copy_count = 0;
	int rmap_count = 0;
	for(i=0;i<ret;i++) {
		if (!flag[i]) {
			if (FTABLE_HETERO(mfns[i])) {
				rmap_count += hetero(mfns[i], 0);
				copy_count++;
			}
		} else {
			MYASSERT(FTABLE_HETERO(mfns[i]) == 0);
			rmap_count += hetero(mfns[i], 1);
			copy_count++;
		}
	}
#ifdef HETERO_SYNC1
	spin_unlock(&hetero_lock);
#endif
	flush_tlb_local();	// TODO: or global? where is correct location?
//	if (copy_count)
//		myprintk("%d(%d rmap) hot pages moved\n", copy_count, rmap_count);
#ifdef ENABLE_TIMESTAMP
	timestamp(TIMESTAMP_PAGE_MIGRATE, 1);
	timestamp_end(TIMESTAMP_PAGE_MIGRATE, 2);
#endif
	}
#endif
	spin_unlock(&seed_user_hot->lock);	// TODO determine where this goes..
	for(i=0;i<ret;i++) {
#ifdef ENABLE_HETERO
		if (flag[i])
			continue;
		MYASSERT(FTABLE_HETERO(mfns[i])==0);
#endif
		vrt_set(mfns[i], NULL, VRT_SET_LOCK_SYNC);	// TODO: check old value.. should be seed_user_hot
		// reset: TODO: needs lock??
		FTABLE_TIME(mfns[i]) = 0;
		FTABLE_ABIT(mfns[i]) = 0;
	}
}
