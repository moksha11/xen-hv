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


#ifdef ENABLE_RMAP

#define RME_MASK	0xFFFF000000000000
#define RME_MASK_PTI	0x0FFF000000000000
#define RME_MASK_FLAG	0xF000000000000000
#define RME_PTI_SHIFT	48
#define RME_FLAG_SHIFT	60
inline struct page_table *rme_pt(unsigned long ptr)
{
	if ((~RME_MASK)&ptr == 0)
		return NULL;
	return RME_MASK|ptr;
}

inline int rme_pti(unsigned long ptr)
{
	int ret = (RME_MASK_PTI&ptr)>>RME_PTI_SHIFT;
	MYASSERT(ret>=0 && ret<L4_PAGETABLE_ENTRIES);
	return ret;
}

inline void rme_set(unsigned long *ptr, struct page_table *pt, int pti)
{
	MYASSERT(pti>=0 && pti<L4_PAGETABLE_ENTRIES);
	*ptr = ((~RME_MASK) & ((unsigned long)pt)) | ((((unsigned long)pti)<<RME_PTI_SHIFT) & RME_MASK_PTI);
}

// TODO: remove this
inline void rme_set_flag(unsigned long *ptr, int f)
{
	*ptr = ((~RME_MASK_FLAG) & (*ptr)) | ((((unsigned long)f)<<RME_FLAG_SHIFT) & RME_MASK_FLAG);
}

void print_rmaps(struct vregion_t *vr)
{
	struct rmap_set *rms;
	struct page_table *pt;
	int pti;
	int i;
	if (vr->rmap_count[0] > 20) {
		myprintk("rmap skip...\n");
		return;
	}
	if (vr->head == -1) {
		myprintk("vr->head == -1\n");
		return;
	}
//	myspin_lock(&vr->lock, 68);
	struct rmaps_builtin *r;
	int start = vr->head;
	int cur = start;
	int z;
	do {
	for(z=0;z<RMAPS_MAX;z++) {
	r = &FTABLE_RMAPS(cur, z);
	myprintk("mfn:%x [%d] count:%d\n", cur, z, r->rmap_count);
	list_for_each_entry(rms, &r->rmaps_list, list) {
		myprintk("(rms:%d/%d/%d)\n", rms->flag_count, rms->entry_count, rms->size);
		for(i=0;i<rms->size;i++) {
			pt = rme_pt(rms->rmaps[i]);
			pti = rme_pti(rms->rmaps[i]);
			if (!pt)
				continue;
			l1_pgentry_t *l1t = pt->shadow[0];
			unsigned long l1_mfn = l1e_get_intpte(l1t[pti]);	// print whole l1e
			myprintk("(vr:%p up_pt:%p ptmfn:%lx pti:%3x mfn:%3lx ) va:%lx\n", vr, pt->up_pt, pt->mfn, pti, l1_mfn, get_va(pt, pti) );
		}
	}
	}
	cur = FTABLE_NEXT(cur);
	} while(cur != start);
//	spin_unlock(&vr->lock);
}


int is_rmaps_empty(struct vregion_t *vr)
{
	int i, count;
	struct rmap_set *rms;

	if (vr->head == -1)
		return 1;

	struct rmaps_builtin *r;
	int start = vr->head;
	int cur = start;
	do {
	r = &FTABLE_RMAPS(cur, RMAPS_USER);
	count = 0;
	MYASSERT(!list_empty(&r->rmaps_list));	// rmaps never becomes empty
	list_for_each_entry(rms, &r->rmaps_list, list) {
	if (rms != &r->default_rmaps)
		return 0;
	count++;
	for(i=0;i<rms->size;i++) {
		if (rme_pt(rms->rmaps[i])) {
			return 0;
		}
	}
	}
	if (count != 1)
		return 0;

	cur = FTABLE_NEXT(cur);
	} while(cur != start);
	return 1;
}

void init_rmaps(struct rmap_set *rms, short int size) {
	int i;
	for(i=0;i<size;i++) {
		rms->rmaps[i] = 0;
	}
	rms->entry_count = 0;
	rms->flag_count = 0;
	rms->size = size;
	INIT_LIST_HEAD(&rms->list);
}

// 1==success, 0==fail
int add_rmap_entry(struct rmap_set *rms, struct page_table *pt, int ptindex, unsigned long mfn)
{
	int i;
	for(i=0;i<rms->size;i++) {
		if (rme_pt(rms->rmaps[i]) == 0) {
			rme_set(&rms->rmaps[i] , pt, ptindex);
			return 1;
		}
	}
	return 0;
}

// grep vr->lock before calling this
static void add_rmap_common(struct vregion_t *vr, struct page_table *pt, int ptindex, unsigned long mfn, int rmapi)
{
	struct rmap_set *rms;
	struct rmaps_builtin *r;
	r = &FTABLE_RMAPS(mfn, rmapi);
#ifdef ENABLE_KERNEL_SHADOW
#ifdef ENABLE_DEBUG
	if (rmapi == RMAPS_KERNEL && r->rmap_count) {
		myprintk("INFO kernel double mapping\n");
	}
#endif
#endif
	MYASSERT(FTABLE_NEXT(mfn) != -1);
	list_for_each_entry(rms, &r->rmaps_list, list) {
		if (add_rmap_entry(rms, pt, ptindex, mfn))
			break;
	}
	if (&rms->list==&r->rmaps_list) {	// if failed
		rms = (struct rmap_set *)myxmalloc_bytes(sizeof(struct rmap_set)+MAX_RMAP_ENTRIES_IN_SET*sizeof(unsigned long), 1);
		if (rms==0) {
			mypanic("xmalloc failed!\n");
			return;
		}
		init_rmaps(rms, MAX_RMAP_ENTRIES_IN_SET);
		add_rmap_entry(rms, pt, ptindex, mfn);	// must success always
		list_add_tail(&rms->list, &r->rmaps_list);
	}
	vr_inc_rmap_count(vr, rmapi, r);
}


// grep vr->lock before calling
void add_rmap(struct vregion_t *vr, struct page_table *pt, int ptindex, unsigned long mfn, int rmapi)
{
	MYASSERT(spin_is_locked(&vr->lock));
	struct rmap_entry *rme;
	int cache;
#ifdef DEBUG_CHECK_DUPLICATE_RMAP
	rme = find_rmap(vr, pt, ptindex, mfn);
	if (rme) {
		myprintk("already exists!! pgd:%x[%d] pt->mfn=%x(%d),l1e_pfn=%x, rm->pt->pgd:%x[%d] rm->pt->mfn:%x(%d)\n", pt->pgd->mfn, pt->pgd_index, pt->mfn, ptindex, mfn, rme->pt->pgd->mfn, rme->pt->pgd_index, rme->pt->mfn, rme->ptindex);
		spin_unlock(&vr->lock);
		return;
	}
#endif
	add_rmap_common(vr,pt,ptindex,mfn,rmapi);
//	TRACE_3D(TRC_MIN_ADDRMAP, pt->mfn, ptindex, vrid);
}


// 0 == fail ,   nonempty
// 1 == success, nonempty
// 2 == fail ,   empty
// 3 == success, empty
static int del_rmap_entry(struct rmap_set *rms, struct page_table *pt, int ptindex, unsigned long mfn)
{
	int i, empty=1, success=0;
	MYASSERT(pt);
	for(i=0;i<rms->size;i++) {
		if (!rme_pt(rms->rmaps[i]))
			continue;
		l1_pgentry_t *l1t = rme_pt(rms->rmaps[i])->shadow[0];
//		unsigned long l1_mfn = l1e_get_pfn(l1t[rme_pti(rms->rmaps[i])]);
		// if pt==0 , find matched mfn
//		if ((pt && (rms->rmaps[i].pt == pt && rms->rmaps[i].ptindex == ptindex)) || (!pt && rms->rmaps[i].mfn == mfn))
		if (rme_pt(rms->rmaps[i]) == pt && rme_pti(rms->rmaps[i]) == ptindex)
		{
#ifndef ENABLE_HETERO
#ifdef DEBUG_WARN
//			if (l1_mfn != mfn)
//				myprintk("BUG! found but different mfn. rm:%x != now:%x\n", l1_mfn, mfn);
#endif
#endif
			rme_set(&rms->rmaps[i], NULL, 0);
//			l1_mfn = 0;
#ifdef DEBUG_ASSERT
			if (success && pt)
				mypanic("already success==1 when pt!=0 ?");
#endif
			success = 1;
		} else
			empty = 0;
	}
	return success+empty*2;
}

int del_rmap(struct page_table *pt, int ptindex, unsigned long mfn, int rmapi)
{
	struct rmap_set *rms, *n;
	struct vregion_t *vr;
	int ret , success = 0;
	struct vregion_t *new_private_vr = NULL;
	struct rmaps_builtin *r;
	int total_rmap, sync_locked = 0;
	int i;
#if 0
	// when we disable our code(mini_activated==0), I found some racing that
	// guest already reached here through l1e_unmark2() and myhypercall() is 
	// destroying(unmarking->del_rmap()ing) then the guest finds vr==NULL here..
	// so 
	// TODO: maybe I don't need this anymore when mini_count is complete
	// TODO: Is it possible that we unmark not-yet-marked l1e? If so, we would find vr==null or find no such rmap to delete
	if (/*vrt_is_null(mfn) always false*/ 0 ) {
		if (mini_activated)
			mypanic("vr==NULL while mini_activated??");
		return 0;	// report failure
	}
#endif
again:
	vr = vrt_get(mfn, VR_REFCNT_RMAP, sync_locked);
	MYASSERT(vr);

	// TODO: remove this and always lock sync_lock??
	if (!sync_locked) {
	// determine if we lock sync_lock
	total_rmap = 0;
	for(i=0;i<RMAPS_MAX;i++) {
		r = &FTABLE_RMAPS(mfn, i);
		total_rmap += r->rmap_count;
	}
	if (total_rmap == 1) {
		spin_unlock(&vr->lock);
		vr_put(vr, VR_REFCNT_RMAP, 0);

		// so, it's possible to lock sync_lock unnecessarily if second vrt_get() returns different vr.
		sync_locked = 1;
		myspin_lock(&SYNC_LOCK(mfn), 6);
		goto again;
	}
	}

#ifdef ENABLE_BITMAP_VRT
//	myspin_lock_pt(pt, 104);
	int cache;
	for(cache=0;cache<MAX_CACHE;cache++) {
		if (test_bitmap(pt, ptindex, cache))
			close_bitmap(pt, ptindex, cache);
	}
//	spin_unlock_pt(pt, 104);
#endif
	MYASSERT(vr->head != -1);

	r = &FTABLE_RMAPS(mfn, rmapi);
	list_for_each_entry_safe(rms, n, &r->rmaps_list, list) {
		ret = del_rmap_entry(rms, pt, ptindex, mfn);
		switch(ret) {
		case 3:	// 3 == success, empty
			if (rms != &r->default_rmaps) {
				list_del(&rms->list);
				myxfree(rms, 1);
			}
		case 1:	// 1 == success, nonempty
			vr_dec_rmap_count(vr, rmapi, r);
#ifdef DEBUG_ASSERT
			if (success && pt) {
				mypanic("already success==1 in del_rmap, pt!=0?");
			}
#endif
			success = 1;
		case 0:	// just continue	// 0 == fail ,   nonempty
			break;
		case 2:	// 2 == fail ,   empty
			if (rms == &r->default_rmaps)
				break;
		default:
			myprintk("ret:%d vr:%x, rms:%x\n",ret, vr, rms);
			mypanic("bug! empty rmap_set??");
		}
	}

// this immediately remove from hot page list when process dies
#if 0 //def ENABLE_HOT_PAGES	// TODO: use attribute SHRINK_NORMAP
	if (rmapi == RMAPS_USER && test_bit(VR_USER, &vr->flags) && success) {	// user 1-->0
		struct rmaps_builtin *r;
		r = &FTABLE_RMAPS(mfn, rmapi);
#ifdef ENABLE_HETERO
		if (r->rmap_count == 0) {	// user 1-->0
			hetero_free(mfn);
		}
#endif
		if (r->rmap_count == 0 && vr == seed_user_hot /*TODO:use attribute SHRINK_NORMAP*/) {			// user 1-->0
			spin_unlock(&vr->lock);
			vr_put(vr, VR_REFCNT_RMAP, 0);

			struct vregion_t *vr2, *old;
			vr2 = get_seed_user();
			old = vrt_set(mfn, vr2, 100, !sync_locked);	// 100 skips unlocking vr2
			MYASSERT(old == vr);
			if (old)
				vr_put(old, VR_REFCNT_VRT_TEMP, 2);
			vr_get(vr2, VR_REFCNT_RMAP);	// as if we called vrt_get()
			vr = vr2;
			FTABLE_ABIT(mfn) = 0;	// reset abit
			FTABLE_TIME(mfn) = 0;	// reset time
#ifdef DEBUG_ASSERT
			r = &FTABLE_RMAPS(mfn, RMAPS_KERNEL);
			MYASSERT(r->rmap_count == 0);
#endif
		}
	}
#endif
#ifdef ENABLE_VR_USER
	if (rmapi == RMAPS_USER && test_bit(VR_USER, &vr->flags) && success) {	// user 1-->0
		struct rmaps_builtin *r;
		r = &FTABLE_RMAPS(mfn, rmapi);
		if (r->rmap_count == 0) {			// user 1-->0
			spin_unlock(&vr->lock);
			vr_put(vr, VR_REFCNT_RMAP, 0);

			struct vregion_t *vr2, *old;
			vr2 = get_seed_kernel();
			old = vrt_set(mfn, vr2, 100, !sync_locked);	// 100 skips unlocking vr2
			MYASSERT(old == vr);
			if (old)
				vr_put(old, VR_REFCNT_VRT_TEMP, 2);
			vr_get(vr2, VR_REFCNT_RMAP);	// as if we called vrt_get()
			vr = vr2;
#ifdef DEBUG_ASSERT
			r = &FTABLE_RMAPS(mfn, RMAPS_KERNEL);
			MYASSERT(r->rmap_count != 0);
#endif
		}
	}
#endif
#ifdef ENABLE_VR_KERNEL	// kenel vr
	if (rmapi == RMAPS_KERNEL && test_bit(VR_KERNEL, &vr->flags) && success) {	// kernel 1-->0
		struct rmaps_builtin *r;
		r = &FTABLE_RMAPS(mfn, rmapi);
		if (r->rmap_count == 0) {			// kernel 1-->0
			spin_unlock(&vr->lock);
			vr_put(vr, VR_REFCNT_RMAP, 0);

			struct vregion_t *vr2, *old;
			vr2 = get_seed_xen();
			old = vrt_set(mfn, vr2, 100, !sync_locked);	// 100 skips unlocking vr2
			MYASSERT(old == vr);
			if (old)
				vr_put(old, VR_REFCNT_VRT_TEMP, 2);
			vr_get(vr2, VR_REFCNT_RMAP);	// as if we called vrt_get()
			vr = vr2;
#ifdef DEBUG_ASSERT
			r = &FTABLE_RMAPS(mfn, RMAPS_USER);
			MYASSERT(r->rmap_count == 0);
#endif
		}
	}
#endif
#if 0	// TODO..
	if (rmapi == RMAPS_KERNEL && test_bit(VR_KERNEL, &vr->flags) && success) {	// user 1-->0
		struct rmaps_builtin *r;
		r = &FTABLE_RMAPS(mfn, rmapi);
		if (r->rmap_count == 0) {			// kernel 1-->0
			spin_unlock(&vr->lock);
			vr_put(vr, VR_REFCNT_RMAP, 0);

			MYASSERT(sync_locked);
			struct vregion_t *vr2, *old;
			old = vrt_set(mfn, NULL, 1, VRT_SET_LOCK_SYNC);
			vr2 = vrt_get(mfn, VR_REFCNT_RMAP, 1);
			MYASSERT(old == vr);
			if (old)
				vr_put(old, VR_REFCNT_VRT_TEMP, 2);
			vr = vr2;
#ifdef DEBUG_ASSERT
			r = &FTABLE_RMAPS(mfn, RMAPS_USER);
			MYASSERT(r->rmap_count == 0);
#endif

		}
	}
#endif
#if 0 //  defined(ENABLE_REGIONING3)
	// FIX.....
	total_rmap = 0;
	for(i=0;i<RMAPS_MAX;i++) {
		r = &FTABLE_RMAPS(mfn, i);
		total_rmap += r->rmap_count;
	}
	if (!total_rmap && test_bit(VR_SHRINK_NORMAP, &vr->flags)) {
		struct vregion_t *vr2, *old;
		vr2 = get_seed_user();
		// no more this mfn, so erase vrt slot
		MYASSERT(sync_locked);
		old = vrt_set(mfn, vr2, 100, !sync_locked);	// NULL to delete vrt entry since no rmap exists for this mfn. 100 skips unlocking vr2
		MYASSERT(old == vr);
		MYASSERT(spin_is_locked(&old->lock));
		if (old)
			vr_put(old, VR_REFCNT_VRT_TEMP, 0);
	}
#endif
	if (sync_locked) {
		spin_unlock(&SYNC_LOCK(mfn));
		sync_locked = 0;
	}
	if (vr->rmap_count[RMAPS_USER] == 0 && vr->rmap_count[RMAPS_KERNEL] == 0)	// this is different from total_rmap==0
	{
		int i;
		check_vregion(vr, 1);
		MYASSERT(success);	// must be success
		spin_unlock(&vr->lock);
		vr_put(vr, VR_REFCNT_RMAP, 2);	// will delete vr except VR_GUEST|VR_SEED
		return success;
	}
	spin_unlock(&vr->lock);
	vr_put(vr, VR_REFCNT_RMAP, 0);
	return success;
}

// called only by find_rmap(). nonzero==success, 0==fail
unsigned long *find_rmap_entry(struct rmap_set *rms, struct page_table *pt, int ptindex, unsigned long mfn)
{
	int i;

	for(i=0;i<rms->size;i++) {
		if (rme_pt(rms->rmaps[i]) == pt && rme_pti(rms->rmaps[i]) == ptindex) {
#ifdef DEBUG_WARN
			l1_pgentry_t *l1t = rme_pt(rms->rmaps[i])->shadow[0];
			unsigned long l1_mfn = l1e_get_pfn(l1t[rme_pti(rms->rmaps[i])]);
			if (l1_mfn != mfn)
				myprintk("WARN! find_rmap. found but different l1e_pfn. rm:%x != now:%x\n", l1_mfn, mfn );
#endif
			return &rms->rmaps[i];
		}
	}
	return 0;
}

// vr->lock is held when called.
unsigned long *find_rmap(struct vregion_t *vr, struct page_table *pt, int ptindex, unsigned long mfn)
{
#ifdef DEBUG_ASSERT
	if (!spin_is_locked(&vr->lock))
		mypanic("find_rmap: grep vr->lock first!");
#endif
	struct rmap_set *rms;
	unsigned long *ret;

	if (vr->head == -1)
		return 0;
	struct rmaps_builtin *r;
	int start = vr->head;
	int cur = start;
	do {
	r = &FTABLE_RMAPS(cur, RMAPS_USER);
	list_for_each_entry(rms, &r->rmaps_list, list) {
		if ((ret = find_rmap_entry(rms, pt, ptindex, mfn)))
			return ret;
	}
	cur = FTABLE_NEXT(cur);
	} while(cur != start);
	return 0;
}
#endif
