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

#ifdef ENABLE_CLOCK
// we're doing clock on pgd basis
void do_clock(int event_nr, struct page_dir *pgd, s_time_t now)
{
	MYASSERT(pgd==current->current_pgd);	// so we can eliminate  'pgd' parameter of do_clock

	// TODO: maybe lock needed to protect clock_residue and diff ?
	s_time_t diff = (pgd->clock_residue + now - pgd->clock_prev_now);
	if (now < pgd->clock_prev_now) {	// sometimes happens
		diff = pgd->clock_residue;
	}
	pgd->clock_prev_now = now;

	if (diff < MILLISECS(clock_period_ms))
	{
		pgd->clock_residue = diff;
//		myprintk("pgdmfn:%x (%dnewcr3/%dtick/%dsched/%4lldms) \n", pgd->pt->mfn, pgd->clock_cr3_changes, pgd->clock_timer, pgd->clock_schedule,  diff/1000000ULL);
	} else {
		// probably we don't need pgd->lock here..
#ifdef ENABLE_REGIONING2
		if (!(pgd->current_region && pgd->regioning_cpu == smp_processor_id())) 
#endif
		{
#ifdef ENABLE_TIMESTAMP
			timestamp_start(TIMESTAMP_CLEAR_ABIT);
#endif
			pgd->clock_residue = 0;		// diff contains it, so clear it.

#if 0 // def VERBOSE_CLOCK
			myprintk("pgdmfn:%x (%dnewcr3/%dtick/%dsched/%4lldms) ", pgd->pt->mfn, pgd->clock_cr3_changes, pgd->clock_timer, pgd->clock_schedule,  diff/1000000ULL);
			print_openbit_count(pgd);
			printk("\n");
#endif
#ifdef ENABLE_ABIT
			clear_abit(pgd, now);
#endif
			pgd->clock_cr3_changes = 0;
			pgd->clock_timer = 0;
			pgd->clock_schedule = 0;

#ifdef ENABLE_TIMESTAMP
			timestamp(TIMESTAMP_CLEAR_ABIT, 1);
			timestamp_end(TIMESTAMP_CLEAR_ABIT, 2);
#endif
		}
	}

	if (event_nr == CLOCK_EVENT_NEW_CR3) {
		pgd->clock_cr3_changes++;
#ifdef ENABLE_REGIONING2
		if (pgd->current_region) {
//			regioning_stop(CLOCK_EVENT_NEW_CR3,NULL);	// call this before setting current_pgd
			regioning_pause(CLOCK_EVENT_NEW_CR3, now);
		}
#endif
	} else if (event_nr == CLOCK_EVENT_TIMER) {
		pgd->clock_timer++;
#ifdef ENABLE_REGIONING2
		regioning_each_tick(pgd);
		regioning_clean_pauses(now);
#endif
	} else if (event_nr == CLOCK_EVENT_SCHEDULE) {
		pgd->clock_schedule++;
#ifdef ENABLE_REGIONING2
		if (pgd->current_region) {
//			regioning_stop(CLOCK_EVENT_SCHEDULE,NULL);
			regioning_pause(CLOCK_EVENT_SCHEDULE, now);
		}
#endif
	} else {
		mypanic("Unknown clock event?");
	}
}
#endif

#ifdef ENABLE_BITMAP_BASIC
// first lock pt->lock, call this func, and modify page table, then release it.
void close_bitmap(struct page_table *pt, int ptindex, int dest_cache)
{
	int old;
#ifdef DEBUG_ASSERT
#ifdef ENABLE_BITMAP_VRT
	if (ptindex > L4_PAGETABLE_ENTRIES)
		mypanic("close_bitmap:pti>L4_PAGETABLE_ENTRIES");
	if (dest_cache >= MAX_CACHE)
		mypanic("close_bitmap:dest_cache >= MAX_CACHE");
	if (dest_cache < -1)
		mypanic("close_bitmap:dest_cache<-1");
#else
	MYASSERT(dest_cache == -1);
#endif
//	if (!spin_is_locked(&pt->lock))
//		mypanic("close_bitmap:lock pt->lock first!");
	MYASSERT(pt->level == 1);
#endif
	old = test_and_clear_bit(ptindex, ((struct l1e_struct *)pt->aux)->bitmap[dest_cache+1]);
//	pt->pgd->openbit_count[dest_cache]--;	// need lock?TODO make it atomic
	MYASSERT(old && "close_bitmap(): already clear??");
#ifdef VERBOSE_BITMAP_CHANGE
	myprintk("$%d, pg:%x(%d) pt:%x(%d)\n", dest_cache, pt->pgd->mfn, pt->up_index, pt->mfn, ptindex );
#endif
}

// first lock pt->lock, call this func, and modify page table, then release it.
void open_bitmap(struct page_table *pt, int ptindex, int dest_cache)
{
	int old;
#ifdef DEBUG_ASSERT
#ifdef ENABLE_BITMAP_VRT
	if (ptindex > L4_PAGETABLE_ENTRIES)
		mypanic("open_bitmap:pti>L4_PAGETABLE_ENTEIES");
	if (dest_cache >= MAX_CACHE)
		mypanic("open_bitmap:dest_cache>=MAX_CACHE");
	if (dest_cache < -1)
		mypanic("open_bitmap:dest_cache<-1");
	MYASSERT(pt->level == 1);
#else
	MYASSERT(dest_cache == -1);
#endif
//	if (!spin_is_locked(&pt->lock))
//		mypanic("open_bitmap:lock pt->lock first!");
#endif
	old = test_and_set_bit(ptindex, ((struct l1e_struct *)pt->aux)->bitmap[dest_cache+1]);
//	pt->pgd->openbit_count[dest_cache]++;	// need lock?TODO make it atomic
	MYASSERT(!old && "open_bitmap(): already open??");
#ifdef VERBOSE_BITMAP_CHANGE
	myprintk("$%d, pg:%x(%d) pt:%x(%d)\n", dest_cache, pt->pgd->mfn, pt->up_index, pt->mfn, ptindex);
#endif
}

// first lock pt->lock
int test_bitmap(struct page_table *pt, int ptindex, int dest_cache)
{
	MYASSERT(pt->level == 1);
//	MYASSERT(spin_is_locked(&pt->lock) && "open_bitmap:lock pt->lock first!");
	return test_bit(ptindex, ((struct l1e_struct *)pt->aux)->bitmap[dest_cache+1]);
}

#ifdef DEBUG_CHECK_BITMAP
static int panic_count = 20;

// TODO: review or remove..
// lock pt->lock
int check_pt_bitmap(struct page_table *pt, unsigned long pgd_mfn, int loc)
{
	int cache = pt->cache;
	l1_pgentry_t *l1t;
	l1t = map_domain_page(pt->mfn);
	int i, count = 0;

	for( i=0;i<1024;i++) {
		if ( test_bitmap(pt, i, cache) ) {
			count++;
			if (!l1e_is_open(l1t[i])) {	// includes nonpresent
				myprintk("Nonpresent or closed(should be open) " "pgdmfn=%x, ptmfn=%x$%d, pgdi=%d, ptei=%d,l1e=%x, loc=%d, init=%d\n", pgd_mfn, pt->mfn, cache, pt->pgd_index, i, l1t[i], loc, pt->init);
				panic_count--;
				if (panic_count < 0)
					mypanic("check_bitmap()");
			}
		} else {
			if (l1e_is_open(l1t[i])) {
				myprintk("Open(should be not-open) " "pgdmfn=%x, ptmfn=%x$%d, pgdi=%d, ptei=%d,l1e=%x, loc=%d, init=%d\n", pgd_mfn, pt->mfn, cache, pt->pgd_index, i, l1t[i], loc, pt->init);
				panic_count--;
				if (panic_count < 0)
					mypanic("check_bitmap()");
			}
		}
	}
	unmap_domain_page(l1t);
	return count;
}

#else
void check_bitmap(struct page_dir *pgd) {}
#endif

void print_bitmap(struct page_dir *pgd)
{
#ifdef VERBOSE_BITMAP_PRINT
	TODO: review
	struct page_table *pt;
	char buff[1024];
	int cache,len,i;
	if (!pgd)
		mypanic("pgd==0??");
	for(cache=0;cache<MAX_CACHE;cache++) {
		myprintk("");
		print_openbit_count(pgd);
		printk("$%d ", cache);
		list_for_each_entry(pt, &pgd->pt_list, list) {
			// TODO: pt->lock
			len = bitmap_scnprintf(buff, 1024, pt->bitmap_open[cache] , 1024);
			for(i=0;i<len;i++)
				if (buff[i] == '0')
					buff[i] = '.';
			buff[len] = 0;
			printk("up_index:%3d %s ", pt->up_index, buff);
		}
		printk("\n");
	}
#endif
}
#endif

#ifdef ENABLE_ABIT
DEFINE_PER_CPU(unsigned long [BITS_TO_LONGS(L4_PAGETABLE_ENTRIES)], abits);
//unsigned long abits[BITS_TO_LONGS(L4_PAGETABLE_ENTRIES)];
#if defined(ENABLE_BITMAP_VRT)
#define BITMAP_INDEX (cache+1)
#elif defined(ENABLE_BITMAP_BASIC)
#define BITMAP_INDEX (0)
#else
#error bitmap_basic or bitmap_vrt ?
#endif

int clear_abit_leaf(struct page_table *pt, s_time_t now)
{
	int count = 0;
	int cache;
	l1_pgentry_t *l1t;
	unsigned int pos;
//	struct vregion_t *vr;
	struct l1e_struct *aux = pt->aux;
	MYASSERT(aux);

	unsigned long (*abits)[BITS_TO_LONGS(L4_PAGETABLE_ENTRIES)];
	abits = &(per_cpu(abits, smp_processor_id()));
	memset(abits, 0, sizeof(*abits));
	for (cache = 0; cache < max_cache; cache++) {
	l1t = pt->shadow[cache];
	for ( pos = find_first_bit(aux->bitmap[BITMAP_INDEX], L4_PAGETABLE_ENTRIES);
		pos < L4_PAGETABLE_ENTRIES;
		pos = find_next_bit(aux->bitmap[BITMAP_INDEX], L4_PAGETABLE_ENTRIES, pos+1) )
	{
		if (unlikely(test_and_clear_bit( 5, &l1t[pos].l1))) {	// _PAGE_ACCESSED
			set_bit(pos, abits);
		}
	}
	}
#ifdef ENABLE_HETERO
	// set l1t to original pt of guests. So abit will be attibuted to the original page, not hetero page.
	l1t = mfn_to_virt(pt->mfn);
#else
	// l1t is last one from previous loop
#endif
	unsigned long mfn;
	for ( pos = find_first_bit(aux->bitmap[0], L4_PAGETABLE_ENTRIES);
		pos < L4_PAGETABLE_ENTRIES;
		pos = find_next_bit(aux->bitmap[0], L4_PAGETABLE_ENTRIES, pos+1) )
	{
		mfn = l1e_get_pfn(l1t[pos]);
#ifdef ENABLE_HOT_PAGES
		int hotness_prev = bitcount(FTABLE_ABIT(mfn));
#endif
		if (test_bit(pos, abits)) {
			count++;
#ifdef ENABLE_HISTOGRAM
//			myspin_lock(&vr->count_lock, 46);
			int bits = bitcount(FTABLE_ABIT(mfn));	// might be redundant?
			if (!(FTABLE_ABIT(mfn) & 1UL)) {
#ifdef DEBUG_ASSERT
				if (bits==32)	mypanic("can't be 32!\n");
#endif
				vr_move_density(vr, density, density+1, cache);
			}
#endif
			FTABLE_ABIT(mfn) >>= 1;
			FTABLE_ABIT(mfn) |= (1UL<<31);
//			ABIT_HISTORY(mfn, cache) >>= 1;
//			ABIT_HISTORY(mfn, cache) |= (1UL<<31);
/*
			if (vr->last_abit_update != pt->pgd->clock_prev_now) {
				// we grep vr's lock before cacheman's
				myspin_lock(&cacheman[cache].lock, 43);
				// touch cache
				list_del_init(&vr->list[cache]);
				list_add(&vr->list[cache], &cacheman[cache].vregions_list);// add to head
				spin_unlock(&cacheman[cache].lock);
			}
*/
#ifdef ENABLE_HISTOGRAM
//			spin_unlock(&vr->count_lock);
#endif
		} else {
                     // TODO: in case of shared vr, it may experience much faster
                     // aging because we're scanning more than one address space..so..
#ifdef ENABLE_HISTOGRAM
//			myspin_lock(&vr->count_lock, 56);
			int bits = bitcount(FTABLE_ABIT(mfn));
			if ((FTABLE_ABIT(mfn) & 1UL)) {
#ifdef DEBUG_ASSERT
				if (!bits)	mypanic("can't be zero!\n");
#endif
				vr_move_density(vr, density, density-1, cache);
			}
#endif
			FTABLE_ABIT(mfn) >>= 1;
//			ABIT_HISTORY(mfn, cache) >>= 1;
#ifdef ENABLE_HISTOGRAM
//			spin_unlock(&vr->count_lock);
#endif
		}
		// roughly in millisec
		FTABLE_TIME(mfn) = (now >> 20);	// TODO: wrap up??
//		myspin_lock(&vr->count_lock, 53);
/*		if (vr->last_abit_update != pt->pgd->clock_prev_now) {
			vr->last_abit_update = pt->pgd->clock_prev_now;
		}*/
//		spin_unlock(&vr->count_lock);
#ifdef ENABLE_HOT_PAGES
#define THRESHOLD_HOT	2
		int hotness = bitcount(FTABLE_ABIT(mfn));
		if (hotness_prev < THRESHOLD_HOT && hotness >= THRESHOLD_HOT) {	// this throttles # of pages entering hot list..
			//printk("Adding mfn to hotlist \n");
			vrt_set(mfn, seed_user_hot, VRT_SET_LOCK_SYNC | VRT_SET_MAYBE_SAME);	// may be set to same..
		}
#endif
	}
	return count;
}

int clear_abit_pt(struct page_table *up_pt, s_time_t now)
{
	int count = 0;
	struct page_table *pt;
	// TODO: need pt->lock?
	list_for_each_entry(pt, &up_pt->pt_list, list) {
	//print_pt(pt);
		myspin_lock_pt(pt, 124);
		if (pt->level == 1) {
			count += clear_abit_leaf(pt, now);
		} else {
			count += clear_abit_pt(pt, now);
		}
		spin_unlock_pt(pt, 124);
	}
	return count;
}

int printx_abit_leaf(struct page_table *pt)
{
	int count = 0;
	l1_pgentry_t *l1t;
	unsigned int pos;
	unsigned long mfn;
	struct l1e_struct *aux = pt->aux;
	MYASSERT(aux);

	l1t = pt->shadow[0];
	for ( pos = find_first_bit(aux->bitmap[BITMAP_INDEX], L4_PAGETABLE_ENTRIES);
		pos < L4_PAGETABLE_ENTRIES;
		pos = find_next_bit(aux->bitmap[BITMAP_INDEX], L4_PAGETABLE_ENTRIES, pos+1) )
	{
		mfn = l1e_get_pfn(l1t[pos]);
		TRACE_2D(TRC_MIN_ABIT, pos, FTABLE_ABIT(mfn) /* , (vr->flags << 16)*/ );
//		TRACE_2D(TRC_MIN_ABIT, pos, FTABLE_TIME(mfn) /* , (vr->flags << 16)*/ );
		count++;
	}
	return count;
}

int printx_abit_pt(struct page_table *up_pt)
{
	int count = 0;
	struct page_table *pt;
	// TODO: need pt->lock?
	list_for_each_entry(pt, &up_pt->pt_list, list) {
	//print_pt(pt);
		TRACE_4D(TRC_MIN_ABIT_PT, pt->mfn, pt->level, pt->up_pt->mfn, pt->up_index);
		myspin_lock_pt(pt, 169);
		if (pt->level == 1) {
			count += printx_abit_leaf(pt);
		} else {
			count += printx_abit_pt(pt);
		}
		spin_unlock_pt(pt, 169);
	}
	return count;
}

void clear_abit(struct page_dir *pgd, s_time_t now)
{
	int count;
	MYASSERT(!test_bit(PGD_KERNEL, &pgd->flag));
#if 0	// output abits to xentrace
	pgd->clear_abit_count++;
	if (pgd->clear_abit_count >= 32) {
		// TODO: change it to s_time_t
		unsigned long now_ms = now/1000000ULL;
		int count;
		pgd->clear_abit_count = 0;
		// we record before calling clear_abit_pt()/setting mempat so that mempat is old data just before updating
		if ((TRC_MIN_ABIT & TRC_ALL) == TRC_MIN) {
			TRACE_2D(TRC_MIN_ABIT_PGD, now_ms, pgd->pt->mfn);
			TRACE_4D(TRC_MIN_ABIT_PT, pgd->pt->mfn, pgd->pt->level, -1, pgd->pt->up_index);
			count = printx_abit_pt(pgd->pt);
			myprintk("pgdmfn:%x , trace output %d abits..\n", pgd->pt->mfn, count);
		}
	}
#endif
	//print_pt(pgd->pt);
	count = clear_abit_pt(pgd->pt, now);
	pcount[COUNT_CLEAR_ABIT]++;
#ifdef VERBOSE_CLOCK
	myprintk("pgdmfn:%x , %d pages got a-bit set\n", pgd->pt->mfn, count);
#endif
	// this seems to be OK because of long timeslice (100ms)
	flush_tlb_local();	// TODO: (1) use invlpg for small regions  (2) need TLBshootdown??
}

#endif
