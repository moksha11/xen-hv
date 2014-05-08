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

#ifdef ENABLE_MARK_VREGION

#ifdef VERBOSE_PAGE_TABLE_MARKING
int unmark_pt_success;
int unmark_pt_notfound;
#endif

// don't use check_bitmap() in l1e_mark(), since our page table is currently has
// all-open-entries (when called from add_pt()), we're in the middle of
// closing these entries, i.e. we're not ready yet to call check_bitmap()
void l1e_mark(l1_pgentry_t *l1t, int i, struct page_table *pt, int ptindex)
{
	unsigned int value;
	unsigned long mfn;

#ifdef DEBUG_ASSERT
	if (!(l1e_get_flags(l1t[i]) & _PAGE_PRESENT))		mypanic("l1e_mark: Nonpresent!");
	if (!this_cpu(locked_pt))
		mypanic("lock_pt before l1e_mark!");
	if (!spin_is_locked((spinlock_t *)this_cpu(locked_pt)))
		mypanic("huh l1e_mark!");
#endif

#ifdef ENABLE_BITMAP_VRT
#ifdef DEBUG_WARN
	{
		int j;
		myspin_lock_pt(pt, 107);
		for(j=0;j<MAX_CACHE;j++) {
			if (test_bitmap(pt, ptindex, j))
				myprintk("BUG! test_bitmap()=true??");
		}
		spin_unlock_pt(pt, 107);
	}
#endif
#endif
//	TRACE_5D(TRC_MIN_L1EMARK, l1t, i, pt, pt->mfn, ptindex);
	struct vregion_t *vr;
#ifdef ENABLE_VREGIONS
	// here it goes to vregion.
	mfn = l1e_get_pfn(l1t[i]);
	vr = vrt_get(mfn, VR_REFCNT_RMAP, 0);
	// vr is locked in vrt_get
#ifdef ENABLE_RANGE
	{
		struct vregion_t *vr2, *old;
		struct page_dir *pgd = get_pgd(pt);
		long vfn = (get_va(pt, ptindex) >> 12U);
		if (vr2 = check_range(pgd, vfn)) {	// TODO: reference count,, also optimize
			spin_unlock(&vr->lock);
			vr_put(vr, VR_REFCNT_RMAP, 0);

			if (vr2->frame_count >= MAX_PAGES_IN_VREGION) {
				myprintk("TODO..range region full..vfn:0x%x vr:0x%x\n", vfn, vr2);
				mypanic("range region full");
			}
			if (!test_bit(VR_POOL, &vr->flags)) {
				mypanic("TODO:...non-pool & range\n");
			}

			old = vrt_set(mfn, vr2, VRT_SET_RETURN_OLD|VRT_SET_LOCK_SYNC|VRT_SET_SKIP_UNLOCK_VR2);	// 100 skips unlocking vr2
			MYASSERT(old == vr);
			if (old)
				vr_put(old, VR_REFCNT_VRT_TEMP, 2);
			vr_get(vr2, VR_REFCNT_RMAP);	// as if we called vrt_get()
		}
	}
#endif

#ifdef ENABLE_RMAP
	if (!vr) {
		myprintk("mfn %x, chain [%d,%d], try again.\n", mfn, FTABLE_NEXT(mfn), FTABLE_PREV(mfn));
		mypanic("NULL vr !\n");
	}
	if (FTABLE_NEXT(mfn) == -1 || FTABLE_PREV(mfn) == -1) {
		myprintk("mfn %x, chain [%d,%d], try again.\n", mfn, FTABLE_NEXT(mfn), FTABLE_PREV(mfn));
		print_vregion(vr, VRPRINT_RMAP);
		spin_unlock(&vr->lock);
		vr_put(vr, VR_REFCNT_RMAP, 2);
		vr = NULL;
		mypanic("should've had mfn..\n");
	}

	// determine rampi based on l1t, because l1t[i] is already updated, so has valid entry
	int rmapi = (l1e_get_flags(l1t[i])&_PAGE_GUEST_KERNEL) ? RMAPS_KERNEL : RMAPS_USER ;
#if 0
#ifdef ENABLE_KERNEL_SHADOW
	if (get_va(pt, ptindex) >= USERLAND_END) {
		MYASSERT(rmapi == RMAPS_KERNEL);
	} else
		MYASSERT(rmapi == RMAPS_USER);
#else
	MYASSERT(rmapi == RMAPS_USER);
#endif
#endif

#ifdef ENABLE_VR_USER
	if (rmapi == RMAPS_USER && test_bit(VR_KERNEL, &vr->flags)) {
		struct rmaps_builtin *r;
		r = &FTABLE_RMAPS(mfn, rmapi);
		if (r->rmap_count == 0) {			// user 0-->1
			spin_unlock(&vr->lock);
			vr_put(vr, VR_REFCNT_RMAP, 0);

			struct vregion_t *vr2, *old;
			vr2 = get_seed_user();
			old = vrt_set(mfn, vr2,VRT_RETURN_OLD|VRT_SET_LOCK_SYNC|VRT_SET_SKIP_UNLOCK_VR2);	// 100 skips unlocking vr2
			MYASSERT(old == vr);
			if (old)
				vr_put(old, VR_REFCNT_VRT_TEMP, 2);
			vr_get(vr2, VR_REFCNT_RMAP);	// as if we called vrt_get()
			vr = vr2;
		}
	}
#endif
#ifdef ENABLE_VR_KERNEL	// kenel vr
	if (rmapi == RMAPS_KERNEL && test_bit(VR_XEN, &vr->flags)) {
		struct rmaps_builtin *r;
		r = &FTABLE_RMAPS(mfn, rmapi);
		if (r->rmap_count == 0) {			// kernel 0-->1
			spin_unlock(&vr->lock);
			vr_put(vr, VR_REFCNT_RMAP, 0);

			struct vregion_t *vr2, *old;
			vr2 = get_seed_kernel();
			old = vrt_set(mfn, vr2,VRT_SET_RETURN_OLD|VRT_SET_LOCK_SYNC|VRT_SET_SKIP_UNLOCK_VR2);	// 100 skips unlocking vr2
			MYASSERT(old == vr);
			if (old)
				vr_put(old, VR_REFCNT_VRT_TEMP, 2);
			vr_get(vr2, VR_REFCNT_RMAP);	// as if we called vrt_get()
			vr = vr2;
		}
	}
#endif

	add_rmap(vr, pt, ptindex, mfn, rmapi);
#endif
	unsigned int bitmap = vr->flags;
	spin_unlock(&vr->lock);
#endif
	// TODO: vr should be unlocked after add_shadow ??
#ifdef ENABLE_PER_CACHE_PT	// light-weight cache switch
	add_shadow(pt, ptindex, l1e_get_intpte(l1t[i]), bitmap, !!test_bit(VR_NO_REGIONING, &vr->flags) /* if flaged, */
#ifdef ENABLE_REGIONING_NOKERNEL	// TODO: remove this
								|| rmapi == RMAPS_KERNEL		/* or kernel space, it goes open for regioning */
#endif
								);
#endif
	vr_put(vr, VR_REFCNT_RMAP, 0);
	pcount[COUNT_L1E_MARK]++;
}

void l1e_unmark(l1_pgentry_t *l1t, int i, struct page_table *pt, int ptindex, unsigned long mfn)
{
	unsigned long mark;

#ifdef DEBUG_ASSERT
	if (!this_cpu(locked_pt))
		mypanic("lock_pt before l1e_unmark!");
	if (!spin_is_locked((spinlock_t *)this_cpu(locked_pt)))
		mypanic("huh l1e_unmark!");
#endif
#if 0
	{
	l1_pgentry_t *l1t;
	int j;
	for(j=0;j<MAX_CACHE;j++) {
		l1t = pt->shadow[j];
//	if (l1e_state(l1t[i]))
	if (l1e_is_closed(l1t[i])) {
		myprintk("unmarking closed l1e..opening it.\n");
		// this is normal case.
		l1e_open(l1t, i);
	}
	}
	}
#endif

//	TRACE_5D(TRC_MIN_L1EUNMARK, l1t, i, pt, pt->mfn, ptindex);

	// rmapi is determined based on pt->shadow , beccause l1t[i] is already updated, so invalid..
	l1_pgentry_t *temp = pt->shadow[0];
	int rmapi = (l1e_get_flags(temp[ptindex])&_PAGE_GUEST_KERNEL) ? RMAPS_KERNEL : RMAPS_USER ;
#if 0
#ifdef ENABLE_KERNEL_SHADOW
	if (get_va(pt, ptindex) >= USERLAND_END) {
		MYASSERT(rmapi == RMAPS_KERNEL);
	} else
		MYASSERT(rmapi == RMAPS_USER);
#else
	MYASSERT(rmapi == RMAPS_USER);
#endif
#endif
	// here it goes to vregion
#ifdef ENABLE_RMAP
	if (del_rmap(pt, ptindex, mfn, rmapi)) 
#endif
	{
#ifdef ENABLE_PER_CACHE_PT	// light-weight cache switch
		del_shadow(pt, ptindex, mfn);
#endif
#ifdef VERBOSE_PAGE_TABLE_MARKING
		unmark_pt_success++;
#endif
		pcount[COUNT_L1E_UNMARK]++;
		return;
	}
	if (!mini_activated)	// if failed because of racing when disabling..
		return;
#ifdef DEBUG_ASSERT
	myprintk("[NOT!ptmfn=%x,pti=%d,mfn=%x,vr=xx] \n", pt->mfn, ptindex, mfn /*, vrt_get(mfn) */);
	print_pt(pt);
//	print_vregion(vrt_get(mfn),VRPRINT_RMAP);
//	TRACE_5D(TRC_MIN_TEMP, NULL, 0 , pt, pt->mfn, ptindex);
#endif
#ifdef VERBOSE_PAGE_TABLE_MARKING
	unmark_pt_notfound++;
#endif
}

void unmark_pt(struct page_table *pt)
{
	unsigned long mymfn;
	int i,j;
#ifdef DEBUG_WARN
	int count=0;
#endif
#ifdef VERBOSE_PAGE_TABLE_MARKING
	unmark_pt_success = unmark_pt_notfound = 0;
	myprintk("->unmark_pt(%x)\n", pt->mfn);
#endif
	l1_pgentry_t l1e, *l1t;
	mfn_check(pt->mfn);
	MYASSERT(pt->level == 1);
	l1t = map_domain_page(pt->mfn);
	for(j=0;j<L1_PAGETABLE_ENTRIES;j++) {
		if (!(l1e_get_flags(l1t[j]) & _PAGE_PRESENT)) {
			continue;
		}

		mymfn = l1e_get_pfn(l1t[j]);
		mfn_check(mymfn);
		l1e_unmark(l1t, j, pt, j , l1e_get_pfn(l1t[j]));
#ifdef DEBUG_WARN
		count++;
#endif
	}
	unmap_domain_page(l1t);
	// Do I need this?
//	flush_all(FLUSH_TLB);
//	flush_tlb_local();	// probably I don't need this here??
#ifdef VERBOSE_PAGE_TABLE_MARKING
	myprintk("count:%d suc:%d notfound:%d remain_rm:%d tot_rm_shared:%d\n",count ,unmark_pt_success ,unmark_pt_notfound , check_pt_rmap_shared(pt), total_rmap_shared() );
#endif
	return;
}

void mark_pt(struct page_table *pt)
{
	l1_pgentry_t l1e, *l1t;
	int count = 0, i, j;

	mfn_check(pt->mfn);
	MYASSERT(pt->level == 1);
	l1t = map_domain_page(pt->mfn);
	for(j=0;j<L1_PAGETABLE_ENTRIES;j++) {
		if (!(l1e_get_flags(l1t[j]) & _PAGE_PRESENT))
			continue;
		l1e_mark(l1t, j, pt, j);// bitmap_open is already zeroed in add_pt()
		count++;
#ifdef VERBOSE_PAGE_TABLE_MARKING_L1E
		myprintk("nl1e:%x\n", l1t[j].l1);
#endif
	}
	unmap_domain_page(l1t);
#ifdef VERBOSE_PAGE_TABLE_MARKING
	myprintk("%d marked for %x[%d]%x.\n", count, pt->up_pt->mfn, pt->up_index, pt->mfn);
#endif
	return;
}

// Xen disallows PAT/PSE , PCD, PWT, GLOBAL   --> BASE_DISALLOW_MASK in include/asm/x86_64/page.h
void l1e_open(l1_pgentry_t *l1t, int i)
{
#ifdef ENABLE_PROTECTION_BIT
	int bit = 2;	// user/supervisor bit
#else
	int bit = 0;
#endif
	MYASSERT(l1e_get_pfn(l1t[i]));

	if (test_and_set_bit(bit, &l1t[i].l1))
		mypanic("l1e_close: already open ?? new_marking");
}
void l1e_close(l1_pgentry_t *l1t, int i)
{
#ifdef ENABLE_PROTECTION_BIT
	int bit = 2;	// user/supervisor bit
#else
	int bit = 0;
#endif
	MYASSERT(l1e_get_pfn(l1t[i]));

	if (!test_and_clear_bit(bit, &l1t[i].l1))
		mypanic("l1e_close: already closed ?? new_marking");
}

#endif
