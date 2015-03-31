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

#ifdef ENABLE_VREGIONS
spinlock_t vregions_seed_lock;
spinlock_t vregions_free_lock;
spinlock_t biglock;
LIST_HEAD(vregions_seed);
LIST_HEAD(vregions_free);
int vregions_seed_count;
int vregions_free_count;
int vregions_xmalloc_count;


#if 1 	// vrt part

#define VRT_MASK	0xFFFF000000000000

#if 0
#define MEMPAT_UNMAPPED		0x000	// unmapped i.f.f. no vr
#define MEMPAT_NOMEMPAT		0x001	// mapped, but no info (initial state)
#define MEMPAT_ONETIME		0x002
#define MEMPAT_SPARSE		0x003
#define MEMPAT_DENSE		0x004

// get vrt_lock before call
inline unsigned long mempat_get(unsigned mfn) {
#ifdef ENABLE_SEPARATE_VRT
	return (((unsigned long)vregion_table[mfn])&VRT_MASK)>>26;
#else
	return (((unsigned long)frame_table[mfn].frame.vr)&VRT_MASK)>>26;
#endif
}
// get vrt_lock before call
inline void mempat_set(unsigned mfn, unsigned val) {
#ifdef ENABLE_SEPARATE_VRT
	vregion_table[mfn] = (struct vregion_t *)((((unsigned long)vregion_table[mfn])&~VRT_MASK)|(val<<26));
#else
	frame_table[mfn].frame.vr = (struct vregion_t *)((((unsigned long)frame_table[mfn].frame.vr)&~VRT_MASK)|(val<<26));
#endif
}
#endif


#define VRT_LOCK(mfn)	(vrt_lock[(mfn)&(MFN_LOCKS_MAX-1)])
static spinlock_t vrt_lock[MFN_LOCKS_MAX];
spinlock_t sync_lock[MFN_LOCKS_MAX];

// vr_get() is called here, so DON'T forget to call vr_put() after this function. 
inline struct vregion_t *_vrt_get(unsigned mfn, int loc) {
	myspin_lock(&VRT_LOCK(mfn), 7);
	unsigned long t = ((unsigned long)FTABLE_VR(mfn))&~VRT_MASK;
	struct vregion_t *ret = NULL;
	if (t) {
		ret = (struct vregion_t *)(t|VRT_MASK);
		vr_get(ret, loc);
	}
	spin_unlock(&VRT_LOCK(mfn));
	return ret;
}

// vr_get() is called here for new value, but vr_put() is not called for the old value.
inline unsigned long _vrt_set(unsigned mfn, struct vregion_t *val) {
	myspin_lock(&VRT_LOCK(mfn), 8);
	unsigned long t = (unsigned long)FTABLE_VR(mfn);
	FTABLE_VR(mfn) = (struct vregion_t *)((t&VRT_MASK)|(((unsigned long)val)&~VRT_MASK));
	if (val)
		vr_get(val, VR_REFCNT_VRT);
	spin_unlock(&VRT_LOCK(mfn));
	t = t&~VRT_MASK;
	if (!t)
		return NULL;
	return (struct vregion_t *)(t|VRT_MASK);
}


void mfn_chain_del(unsigned mfn, struct vregion_t *old) 
{
	int next = FTABLE_NEXT(mfn);
	int prev = FTABLE_PREV(mfn);

	// delete
	MYASSERT(next!=-1 && prev!=-1);
	MYASSERT(old->head != -1);
	if (next == mfn) {
		MYASSERT(prev == mfn);
		MYASSERT(old->head == mfn);
		old->head = -1;
	} else {
		FTABLE_PREV(next) = prev;
		FTABLE_NEXT(prev) = next;
		if (mfn == old->head) {
			old->head = next;
		}
	}
	// clear mfn eitherway.
	FTABLE_PREV(mfn) = -1;
	FTABLE_NEXT(mfn) = -1;
}

void mfn_chain_add(unsigned mfn, struct vregion_t *val) 
{
	int i = val->head;
	int j;
	if (i==-1) {
		val->head = mfn;
		FTABLE_NEXT(mfn) = mfn;
		FTABLE_PREV(mfn) = mfn;
	} else {
		// insert (between i and j)
		j = FTABLE_NEXT(i);
		FTABLE_NEXT(mfn) = j;
		FTABLE_PREV(mfn) = i;
		FTABLE_NEXT(i) = mfn;
		FTABLE_PREV(j) = mfn;
	}
}


// vr_get() is called by _vrt_get, so DON'T forget to call vr_put() after this function. 
// also, the return vr is locked unless it's NULL
inline struct vregion_t *vrt_get(unsigned long mfn, int loc, int sync_locked)
{
	struct vregion_t *vr;
	mfn_check(mfn);
	if (!sync_locked)
		myspin_lock(&SYNC_LOCK(mfn), 10);
	vr = _vrt_get(mfn, loc);
	if (!vr) {
		if (!sync_locked)
			spin_unlock(&SYNC_LOCK(mfn));
		return NULL;
	}
#ifdef DEBUG_ASSERT
	if (vr < (struct vregion_t *)VRT_MASK) {
		myprintk("vr==%p !!\n", vr);
		mypanic("vrt_get: vr< VRT_MASK");
	}
#endif	
	myspin_lock(&vr->lock, 139);
	if (!sync_locked)
		spin_unlock(&SYNC_LOCK(mfn));		// this might not be a good way, but safe anyway
	return vr;
}


struct vregion_t *global;
#define MAX_SEED_SIZE	100000	// (too large => synchronization overhead) (too small => large # of vr)
static struct vregion_t *seed_xen;
static struct vregion_t *seed_kernel;
static struct vregion_t *seed_user;
#ifdef ENABLE_HOT_PAGES
struct vregion_t *seed_user_hot;
#endif

struct vregion_t *get_seed_user(void)	// TODO: refcnt on return value? probably I don't need..
{
	// I dont need vr->lock here..
	if (seed_user->frame_count >= MAX_SEED_SIZE)
	{
		vr_put(seed_user, VR_REFCNT_SEED, 0);
		seed_user = new_vregion(VR_REFCNT_SEED, NEWVR_SEED_USER);
	}
	return seed_user;
}

struct vregion_t *get_seed_kernel(void)	// TODO: refcnt on return value? probably I don't need..
{
	// I dont need vr->lock here..
	if (seed_kernel->frame_count >= MAX_SEED_SIZE)
	{
		vr_put(seed_kernel, VR_REFCNT_SEED, 0);
		seed_kernel = new_vregion(VR_REFCNT_SEED, NEWVR_SEED_KERNEL);
	}
	return seed_kernel;
}

struct vregion_t *get_seed_xen(void)	// TODO: refcnt on return value? probably I don't need..
{
	// I dont need vr->lock here..
	if (seed_xen->frame_count >= MAX_SEED_SIZE)
	{
		vr_put(seed_xen, VR_REFCNT_SEED, 0);
		seed_xen = new_vregion(VR_REFCNT_SEED, NEWVR_SEED_XEN);
	}
	return seed_xen;
}





//#ifndef SUD_DISABLE_SPINLOCK	 
//ORIGINAL CODE
#if 0
struct vregion_t *vrt_set(unsigned long mfn, struct vregion_t *vr, int flags)
{
	int i;
	int was_null = flags & VRT_SET_WAS_NULL;
	struct rmaps_builtin *r;
	int maybe_same = flags & VRT_SET_MAYBE_SAME;

	if (!was_null && !vr) {
#ifdef ENABLE_RMAP
		// speculative peek without holding lock. we need check it again below.
		r = &FTABLE_RMAPS(mfn,RMAPS_USER);
		if (r->rmap_count) {
			vr = get_seed_user();
		} else {
			r = &FTABLE_RMAPS(mfn,RMAPS_KERNEL);
			if (r->rmap_count)
				vr = get_seed_kernel();
			else
				vr = get_seed_xen();
		}
#else
		vr = get_seed_xen();
#endif
		was_null = 1;
	}
#ifdef DEBUG_ASSERT
	if (vr && vr < (struct vregion_t *)VRT_MASK) mypanic("vrt_set: vr && vr < VRT_MASK");
#endif
	mfn_check(mfn);

	struct vregion_t *old;
	if (flags & VRT_SET_LOCK_SYNC) {
		myspin_lock(&SYNC_LOCK(mfn), 44);
	}
	MYASSERT(spin_is_locked(&SYNC_LOCK(mfn)));
	old = _vrt_set(mfn, vr);
#ifdef DEBUG_ASSERT
	if (flags & VRT_SET_INIT) {
		MYASSERT(!old);
	} else
		MYASSERT(old);
#endif
	// here _vrt_set() was successful, vr_get() was called already.
	if ( old == vr )
	{
		if (maybe_same) {	// TODO: optimize more.. maybe just peek without locking.. see split_vregion
			goto same_vr;	// skip mfn_chain things..
		}
		myprintk("old vr\n");
		print_vregion(old, 0);
		myprintk("new vr\n");
		print_vregion(vr, 0);
		mypanic("WARN Unnecessary vrt_set..Set to same vr??\n");
	}
#ifdef DEBUG_ASSERT
#ifdef ENABLE_GUEST_REGION
	// TODO:enable
//	if (vr && old && test_bit(VR_GUEST, &old->flags) && test_bit(VR_REGULAR, &vr->flags))
//		mypanic("Guest-vr -> regular??\n");
#endif
#endif

	// if parent==NULL, clear abit_history
	if ( old ) {
#if 1
		if (old == seed_user_hot) {
		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				atomic_dec(&hot_pages_vm[vm_id]);
			} else {
				myprintk("region.c: if ( old ) WARN invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("region.c: if ( old ) WARN null owner..mfn:%lx\n", mfn);
		}
			
		}
#endif
		myspin_lock(&old->lock, 45);
#ifdef DEBUG_ASSERT
if (!(was_null 						// xx --> seed
	|| test_bit(VR_POOL, &old->flags) 		// seed --> xx
	|| test_bit(VR_NO_REGIONING, &vr->flags)	// xx --> global
	|| (test_bit(VR_REGULAR, &old->flags) && test_bit(VR_REGULAR, &vr->flags))	// reg --> reg.. merge during regioning..
	)) {
	myprintk("old vr\n");
	print_vregion(old, 0);
	myprintk("new vr\n");
	print_vregion(vr, 0);
	mypanic("not-permitted transition ??");
}
#endif
		vr_dec_frame_count(old);
#ifdef ENABLE_RMAP
		for(i=0;i<RMAPS_MAX;i++) {
			r = &FTABLE_RMAPS(mfn,i);
			vr_sub_rmap_count(old, r->rmap_count, i);
		}
#endif
#ifdef ENABLE_HISTOGRAM
//		for(i=0;i<MAX_CACHE;i++) {
//			vr_dec_density(old, bitcount(ABIT_HISTORY(mfn, i)), i);
//		}
		vr_dec_density(old, bitcount(FTABLE_ABIT(mfn)), 0 /* temp */);
#endif
		mfn_chain_del(mfn, old);
#ifdef ENABLE_VREGION_MAPPING	// TODO: this is naive implementation.. needs optimization
		for(i=0;i<MAX_CACHE;i++) {
			if (!is_vregion_cache_mapped(old, i))
				open_mfn(mfn, i, NULL, 0);
		}
#endif
#ifdef ENABLE_REGIONING3
		if (test_bit(VR_NO_REGIONING, &old->flags)) {	// exiting no_regioning vr
			close_mfn(mfn, -1, NULL, 1);
		}
#endif
		spin_unlock(&old->lock);
	}
//	MYASSERT( FTABLE_NEXT(mfn) == -1 && FTABLE_PREV(mfn) == -1 );
	if (vr) {
#if 1
		if (vr == seed_user_hot) {
		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				atomic_inc(&hot_pages_vm[vm_id]);
			} else {
				myprintk("region.c: if (vr) WARN invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("region.c: if (vr) WARN null owner..mfn:%lx\n", mfn);
		}
			
		}
#endif
		myspin_lock(&vr->lock, 99);
#ifdef ENABLE_HISTOGRAM
		vr_inc_density(vr, bitcount(FTABLE_ABIT(mfn)), 0 /* temp */);
#endif
#ifdef ENABLE_DENSITY
		if (parent==NULL) {
			// abit_history and density is init'ed 
			// only when physical page enters region.
			// TODO: if abit_history is recent enough, we can use it.
			for(i=0;i<MAX_CACHE;i++) {
				ABIT_HISTORY(mfn,i) = 0;
				vr_inc_density(vr, 0, i);
			}
		} else {
			for(i=0;i<MAX_CACHE;i++) {
				vr_inc_density(vr, bitcount(ABIT_HISTORY(mfn, i)), i);
			}
//			vr->last_abit_update is updated after returning this func
		}
#endif
#ifdef ENABLE_RMAP
#ifndef ENABLE_HETERO
		r = &FTABLE_RMAPS(mfn,RMAPS_USER);
		if (test_bit(VR_USER, &vr->flags) && !r->rmap_count) {
			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
		}
		if (test_bit(VR_KERNEL, &vr->flags) && r->rmap_count) {
			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
		}
//		if (test_bit(VR_XEN, &vr->flags) && r->rmap_count) {
//			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
//		}
#endif
		int count = 0;
		for(i=0;i<RMAPS_MAX;i++) {
			r = &FTABLE_RMAPS(mfn,i);
			vr_add_rmap_count(vr, r->rmap_count, i);
			count += r->rmap_count;
		}
		if (test_bit(VR_SHRINK_NORMAP, &vr->flags))	// always non-zero rmaps for this attribute
			MYASSERT(count);
#endif
		vr_inc_frame_count(vr);
		mfn_chain_add(mfn, vr);
#ifdef ENABLE_VREGION_MAPPING	// TODO: this is naive implementation.. needs optimization
		for(i=0;i<MAX_CACHE;i++) {
			if (!is_vregion_cache_mapped(vr, i)) {
				close_mfn(mfn, i, NULL, 0);
			}
		}
#endif
#ifdef ENABLE_REGIONING3
		if (test_bit(VR_NO_REGIONING, &vr->flags)) {	// entering of no_regioning vr
			open_mfn(mfn, -1, NULL, 1);
		}
#endif
		if (!(flags & VRT_SET_SKIP_UNLOCK_VR2))		// if SKIP_UNLOCK_VR2 is set, must not spin_lock vr after this point until vr is unlocked at calling func.
			spin_unlock(&vr->lock);
	}
same_vr:
//	check_cacheman();
	if (flags & VRT_SET_LOCK_SYNC)
		spin_unlock(&SYNC_LOCK(mfn));	// end of sync. so now vr has this mfn.
	
	if ((flags & VRT_SET_RETURN_OLD) && old) {
		vr_get(old, VR_REFCNT_VRT_TEMP);
		vr_put(old, VR_REFCNT_VRT, 0);
		return old;
	}

	if (old)
		vr_put(old, VR_REFCNT_VRT, 2);

	return NULL;
}
#else


//Highly modified version from sudarsun. 
//If code crashes enable the original function above.
struct vregion_t *vrt_set(unsigned long mfn, struct vregion_t *vr, int flags)
{
	int i;
	int was_null = flags & VRT_SET_WAS_NULL;
	struct rmaps_builtin *r;
	int maybe_same = flags & VRT_SET_MAYBE_SAME;

	//spin_lock(&biglock);

	if (!was_null && !vr) {
#ifdef ENABLE_RMAP
		// speculative peek without holding lock. we need check it again below.
		r = &FTABLE_RMAPS(mfn,RMAPS_USER);
		if (r->rmap_count) {
			vr = get_seed_user();
		} else {
			r = &FTABLE_RMAPS(mfn,RMAPS_KERNEL);
			if (r->rmap_count)
				vr = get_seed_kernel();
			else
				vr = get_seed_xen();
		}
#else
		vr = get_seed_xen();
#endif
		was_null = 1;
	}

	//if(vr)
	//spin_lock(&biglock);

#ifdef DEBUG_ASSERT
	if (vr && vr < (struct vregion_t *)VRT_MASK) mypanic("vrt_set: vr && vr < VRT_MASK");
#endif
	mfn_check(mfn);

	struct vregion_t *old;
	if (flags & VRT_SET_LOCK_SYNC) {
		myspin_lock(&SYNC_LOCK(mfn), 44);
	}
	MYASSERT(spin_is_locked(&SYNC_LOCK(mfn)));
	old = _vrt_set(mfn, vr);
#ifdef DEBUG_ASSERT
	if (flags & VRT_SET_INIT) {
		MYASSERT(!old);
	} else
		MYASSERT(old);
#endif
	// here _vrt_set() was successful, vr_get() was called already.
	if ( old == vr )
	{
		if (maybe_same) {	// TODO: optimize more.. maybe just peek without locking.. see split_vregion
			goto same_vr;	// skip mfn_chain things..
		}
		myprintk("old vr\n");
		print_vregion(old, 0);
		myprintk("new vr\n");
		print_vregion(vr, 0);
		mypanic("WARN Unnecessary vrt_set..Set to same vr??\n");
	}

	// if parent==NULL, clear abit_history
	if ( old ) {
#if 1
		if (old == seed_user_hot) {
		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				atomic_dec(&hot_pages_vm[vm_id]);
			} else {
				myprintk("region.c: if ( old ) WARN invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("region.c: if ( old ) WARN null owner..mfn:%lx\n", mfn);
		}
			
		}
#endif
		myspin_lock(&old->lock, 45);
#ifdef DEBUG_ASSERT
if (!(was_null 						// xx --> seed
	|| test_bit(VR_POOL, &old->flags) 		// seed --> xx
	|| test_bit(VR_NO_REGIONING, &vr->flags)	// xx --> global
	|| (test_bit(VR_REGULAR, &old->flags) && test_bit(VR_REGULAR, &vr->flags))	// reg --> reg.. merge during regioning..
	)) {
	myprintk("old vr\n");
	print_vregion(old, 0);
	myprintk("new vr\n");
	print_vregion(vr, 0);
	mypanic("not-permitted transition ??");
}
#endif
		vr_dec_frame_count(old);
#ifdef ENABLE_RMAP
		for(i=0;i<RMAPS_MAX;i++) {
			r = &FTABLE_RMAPS(mfn,i);
			vr_sub_rmap_count(old, r->rmap_count, i);
		}
#endif
#ifdef ENABLE_HISTOGRAM
//		for(i=0;i<MAX_CACHE;i++) {
//			vr_dec_density(old, bitcount(ABIT_HISTORY(mfn, i)), i);
//		}
		vr_dec_density(old, bitcount(FTABLE_ABIT(mfn)), 0 );
#endif
		mfn_chain_del(mfn, old);
#ifdef ENABLE_VREGION_MAPPING	// TODO: this is naive implementation.. needs optimization
		for(i=0;i<MAX_CACHE;i++) {
			if (!is_vregion_cache_mapped(old, i))
				open_mfn(mfn, i, NULL, 0);
		}
#endif
#ifdef ENABLE_REGIONING3
		if (test_bit(VR_NO_REGIONING, &old->flags)) {	// exiting no_regioning vr
			close_mfn(mfn, -1, NULL, 1);
		}
#endif
		spin_unlock(&old->lock);
	}
//	MYASSERT( FTABLE_NEXT(mfn) == -1 && FTABLE_PREV(mfn) == -1 );
	if (vr) {
#if 1
		if (vr == seed_user_hot) {
		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				atomic_inc(&hot_pages_vm[vm_id]);
			} else {
				myprintk("region.c: if (vr) WARN invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("region.c: if (vr) WARN null owner..mfn:%lx\n", mfn);
		}
			
		}
#endif
		myspin_lock(&vr->lock, 99);
#ifdef ENABLE_HISTOGRAM
		vr_inc_density(vr, bitcount(FTABLE_ABIT(mfn)), 0);
#endif
#ifdef ENABLE_DENSITY
		if (parent==NULL) {
			// abit_history and density is init'ed 
			// only when physical page enters region.
			// TODO: if abit_history is recent enough, we can use it.
			for(i=0;i<MAX_CACHE;i++) {
				ABIT_HISTORY(mfn,i) = 0;
				vr_inc_density(vr, 0, i);
			}
		} else {
			for(i=0;i<MAX_CACHE;i++) {
				vr_inc_density(vr, bitcount(ABIT_HISTORY(mfn, i)), i);
			}
//			vr->last_abit_update is updated after returning this func
		}
#endif
#ifdef ENABLE_RMAP
#ifndef ENABLE_HETERO
		r = &FTABLE_RMAPS(mfn,RMAPS_USER);
		if (test_bit(VR_USER, &vr->flags) && !r->rmap_count) {
			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
		}
		if (test_bit(VR_KERNEL, &vr->flags) && r->rmap_count) {
			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
		}
//		if (test_bit(VR_XEN, &vr->flags) && r->rmap_count) {
//			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
//		}
#endif
		int count = 0;
		for(i=0;i<RMAPS_MAX;i++) {
			r = &FTABLE_RMAPS(mfn,i);
			vr_add_rmap_count(vr, r->rmap_count, i);
			count += r->rmap_count;
		}
		if (test_bit(VR_SHRINK_NORMAP, &vr->flags))	// always non-zero rmaps for this attribute
			MYASSERT(count);
#endif
		vr_inc_frame_count(vr);
		mfn_chain_add(mfn, vr);
#ifdef ENABLE_VREGION_MAPPING	// TODO: this is naive implementation.. needs optimization
		for(i=0;i<MAX_CACHE;i++) {
			if (!is_vregion_cache_mapped(vr, i)) {
				close_mfn(mfn, i, NULL, 0);
			}
		}
#endif
#ifdef ENABLE_REGIONING3
		if (test_bit(VR_NO_REGIONING, &vr->flags)) {	// entering of no_regioning vr
			open_mfn(mfn, -1, NULL, 1);
		}
#endif
		if (!(flags & VRT_SET_SKIP_UNLOCK_VR2))		// if SKIP_UNLOCK_VR2 is set, must not spin_lock vr after this point until vr is unlocked at calling func.
			spin_unlock(&vr->lock);
	}
same_vr:
	//if(vr)
	//spin_unlock(&biglock);

//	check_cacheman();
	if (flags & VRT_SET_LOCK_SYNC)
		spin_unlock(&SYNC_LOCK(mfn));	// end of sync. so now vr has this mfn.
	
	if ((flags & VRT_SET_RETURN_OLD) && old) {
		vr_get(old, VR_REFCNT_VRT_TEMP);
		vr_put(old, VR_REFCNT_VRT, 0);
		return old;
	}

	if (old)
		vr_put(old, VR_REFCNT_VRT, 2);

	return NULL;
}
#endif



/*
struct vregion_t *vrt_set(unsigned long mfn, struct vregion_t *vr, int flags)
{
	int i;
	int was_null = flags & VRT_SET_WAS_NULL;
	struct rmaps_builtin *r;
	int maybe_same = flags & VRT_SET_MAYBE_SAME;

	//spin_lock(&biglock);

	if (!was_null && !vr) {
#ifdef ENABLE_RMAP
		// speculative peek without holding lock. we need check it again below.
		r = &FTABLE_RMAPS(mfn,RMAPS_USER);
		if (r->rmap_count) {
			vr = get_seed_user();
		} else {
			r = &FTABLE_RMAPS(mfn,RMAPS_KERNEL);
			if (r->rmap_count)
				vr = get_seed_kernel();
			else
				vr = get_seed_xen();
		}
#else
		vr = get_seed_xen();
#endif
		was_null = 1;
	}

	//if(vr)
	//spin_lock(&biglock);

#ifdef DEBUG_ASSERT
	if (vr && vr < (struct vregion_t *)VRT_MASK) mypanic("vrt_set: vr && vr < VRT_MASK");
#endif
	mfn_check(mfn);

	struct vregion_t *old;
	if (flags & VRT_SET_LOCK_SYNC) {
		myspin_lock(&SYNC_LOCK(mfn), 44);
	}
	MYASSERT(spin_is_locked(&SYNC_LOCK(mfn)));
	old = _vrt_set(mfn, vr);
#ifdef DEBUG_ASSERT
	if (flags & VRT_SET_INIT) {
		MYASSERT(!old);
	} else
		MYASSERT(old);
#endif
	// here _vrt_set() was successful, vr_get() was called already.
	if ( old == vr )
	{
		if (maybe_same) {	// TODO: optimize more.. maybe just peek without locking.. see split_vregion
			goto same_vr;	// skip mfn_chain things..
		}
		myprintk("old vr\n");
		print_vregion(old, 0);
		myprintk("new vr\n");
		print_vregion(vr, 0);
		mypanic("WARN Unnecessary vrt_set..Set to same vr??\n");
	}
#ifdef DEBUG_ASSERT
#ifdef ENABLE_GUEST_REGION
	// TODO:enable
//	if (vr && old && test_bit(VR_GUEST, &old->flags) && test_bit(VR_REGULAR, &vr->flags))
//		mypanic("Guest-vr -> regular??\n");
#endif
#endif

	// if parent==NULL, clear abit_history
	if ( old ) {
#if 1
		if (old == seed_user_hot) {
		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				atomic_dec(&hot_pages_vm[vm_id]);
			} else {
				myprintk("region.c: if ( old ) WARN invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("region.c: if ( old ) WARN null owner..mfn:%lx\n", mfn);
		}
			
		}
#endif
		myspin_lock(&old->lock, 45);
#ifdef DEBUG_ASSERT
if (!(was_null 						// xx --> seed
	|| test_bit(VR_POOL, &old->flags) 		// seed --> xx
	|| test_bit(VR_NO_REGIONING, &vr->flags)	// xx --> global
	|| (test_bit(VR_REGULAR, &old->flags) && test_bit(VR_REGULAR, &vr->flags))	// reg --> reg.. merge during regioning..
	)) {
	myprintk("old vr\n");
	print_vregion(old, 0);
	myprintk("new vr\n");
	print_vregion(vr, 0);
	mypanic("not-permitted transition ??");
}
#endif
		vr_dec_frame_count(old);
#ifdef ENABLE_RMAP
		for(i=0;i<RMAPS_MAX;i++) {
			r = &FTABLE_RMAPS(mfn,i);
			vr_sub_rmap_count(old, r->rmap_count, i);
		}
#endif
#ifdef ENABLE_HISTOGRAM
//		for(i=0;i<MAX_CACHE;i++) {
//			vr_dec_density(old, bitcount(ABIT_HISTORY(mfn, i)), i);
//		}
		vr_dec_density(old, bitcount(FTABLE_ABIT(mfn)), 0 );
#endif
		mfn_chain_del(mfn, old);
#ifdef ENABLE_VREGION_MAPPING	// TODO: this is naive implementation.. needs optimization
		for(i=0;i<MAX_CACHE;i++) {
			if (!is_vregion_cache_mapped(old, i))
				open_mfn(mfn, i, NULL, 0);
		}
#endif
#ifdef ENABLE_REGIONING3
		if (test_bit(VR_NO_REGIONING, &old->flags)) {	// exiting no_regioning vr
			close_mfn(mfn, -1, NULL, 1);
		}
#endif
		spin_unlock(&old->lock);
	}
//	MYASSERT( FTABLE_NEXT(mfn) == -1 && FTABLE_PREV(mfn) == -1 );
	if (vr) {
#if 1
		if (vr == seed_user_hot) {
		struct domain *vm = page_get_owner(__mfn_to_page(mfn));
		if (vm) {
			int vm_id = vm->domain_id;
			if (vm_id>=0 && vm_id < MAX_HETERO_VM) {
				atomic_inc(&hot_pages_vm[vm_id]);
			} else {
				myprintk("region.c: if (vr) WARN invalid vm_id:%d\n", vm_id);
			}
		} else {
			myprintk("region.c: if (vr) WARN null owner..mfn:%lx\n", mfn);
		}
			
		}
#endif
		myspin_lock(&vr->lock, 99);
#ifdef ENABLE_HISTOGRAM
		vr_inc_density(vr, bitcount(FTABLE_ABIT(mfn)), 0);
#endif
#ifdef ENABLE_DENSITY
		if (parent==NULL) {
			// abit_history and density is init'ed 
			// only when physical page enters region.
			// TODO: if abit_history is recent enough, we can use it.
			for(i=0;i<MAX_CACHE;i++) {
				ABIT_HISTORY(mfn,i) = 0;
				vr_inc_density(vr, 0, i);
			}
		} else {
			for(i=0;i<MAX_CACHE;i++) {
				vr_inc_density(vr, bitcount(ABIT_HISTORY(mfn, i)), i);
			}
//			vr->last_abit_update is updated after returning this func
		}
#endif
#ifdef ENABLE_RMAP
#ifndef ENABLE_HETERO
		r = &FTABLE_RMAPS(mfn,RMAPS_USER);
		if (test_bit(VR_USER, &vr->flags) && !r->rmap_count) {
			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
		}
		if (test_bit(VR_KERNEL, &vr->flags) && r->rmap_count) {
			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
		}
//		if (test_bit(VR_XEN, &vr->flags) && r->rmap_count) {
//			MYASSERT(flags & VRT_SET_SKIP_UNLOCK_VR2);
//		}
#endif
		int count = 0;
		for(i=0;i<RMAPS_MAX;i++) {
			r = &FTABLE_RMAPS(mfn,i);
			vr_add_rmap_count(vr, r->rmap_count, i);
			count += r->rmap_count;
		}
		if (test_bit(VR_SHRINK_NORMAP, &vr->flags))	// always non-zero rmaps for this attribute
			MYASSERT(count);
#endif
		vr_inc_frame_count(vr);
		mfn_chain_add(mfn, vr);
#ifdef ENABLE_VREGION_MAPPING	// TODO: this is naive implementation.. needs optimization
		for(i=0;i<MAX_CACHE;i++) {
			if (!is_vregion_cache_mapped(vr, i)) {
				close_mfn(mfn, i, NULL, 0);
			}
		}
#endif
#ifdef ENABLE_REGIONING3
		if (test_bit(VR_NO_REGIONING, &vr->flags)) {	// entering of no_regioning vr
			open_mfn(mfn, -1, NULL, 1);
		}
#endif
		if (!(flags & VRT_SET_SKIP_UNLOCK_VR2))		// if SKIP_UNLOCK_VR2 is set, must not spin_lock vr after this point until vr is unlocked at calling func.
			spin_unlock(&vr->lock);
	}
same_vr:
	//if(vr)
	//spin_unlock(&biglock);

//	check_cacheman();
	if (flags & VRT_SET_LOCK_SYNC)
		spin_unlock(&SYNC_LOCK(mfn));	// end of sync. so now vr has this mfn.
	
	if ((flags & VRT_SET_RETURN_OLD) && old) {
		vr_get(old, VR_REFCNT_VRT_TEMP);
		vr_put(old, VR_REFCNT_VRT, 0);
		return old;
	}

	if (old)
		vr_put(old, VR_REFCNT_VRT, 2);

	return NULL;
}
#endif
*/



void vrt_destroy_chunk(unsigned long s, unsigned long e)
{
	int i, j;
	struct rmaps_builtin *r;

	// TODO
	for(i=s;i<e;i++) {
		// sync lock??
#ifdef DEBUG_ASSERT
#ifdef ENABLE_RMAP
		// when we delete frame, it shouldn't have rmap
		for(j=0;j<RMAPS_MAX;j++) {
			r = &FTABLE_RMAPS(i,j);
//			MYASSERT(!r->rmap_count);		// TODO: enable this..
			if (r->rmap_count)
				myprintk("WARN mfn:0x%x [%d] %d nonzero!\n", i, j, r->rmap_count);
		}
#endif
#endif
		vrt_set(i, NULL, VRT_SET_LOCK_SYNC | VRT_SET_WAS_NULL);
		MYASSERT( FTABLE_NEXT(i) == -1 && FTABLE_PREV(i) == -1);
	}
}


void vrt_destroy(void)
{
    // see init_frametable()
    unsigned int sidx, eidx, nidx;
    unsigned int max_idx = (max_pdx + PDX_GROUP_COUNT - 1) / PDX_GROUP_COUNT;
myprintk("%d pdx groups, %d count, vbit[0]:%lx\n", max_idx, PDX_GROUP_COUNT, pdx_group_valid[0]);
    for ( sidx = 0; ; sidx = nidx )
    {
        eidx = find_next_zero_bit(pdx_group_valid, max_idx, sidx);
        nidx = find_next_bit(pdx_group_valid, max_idx, eidx);
        if ( nidx >= max_idx )
            break;
        vrt_destroy_chunk(sidx * PDX_GROUP_COUNT,
                       eidx * PDX_GROUP_COUNT);
    }
    if ( !mem_hotplug )
        vrt_destroy_chunk(sidx * PDX_GROUP_COUNT,
                              max_page);
    else
        mypanic("mem_hotplug set!?\n");
#ifdef __x86_64__
    if (opt_allow_superpage)
	mypanic("allow_superpage?\n");
#endif


	vr_put(seed_xen, VR_REFCNT_SEED, 1);
	seed_xen = NULL;
	vr_put(seed_kernel, VR_REFCNT_SEED, 1);
	seed_kernel = NULL;
	vr_put(seed_user, VR_REFCNT_SEED, 1);
	seed_user = NULL;
#ifdef ENABLE_HOT_PAGES
	vr_put(seed_user_hot, VR_REFCNT_SEED, 1);
	seed_user_hot = NULL;
#endif
	vr_put(global, VR_REFCNT_GLOBAL, 1);
	global = NULL;

}

void init_vrt_chunk(unsigned long s, unsigned long e)
{
	int i;
	for(i=s;i<e;i++) {
		FTABLE_VR(i) = NULL;
		FTABLE_NEXT(i) = -1;
		FTABLE_PREV(i) = -1;
#ifdef ENABLE_RMAP
		int j;
		struct rmaps_builtin *rmaps;
		for(j=0;j<RMAPS_MAX;j++) {
			rmaps = &FTABLE_RMAPS(i,j);
			INIT_LIST_HEAD(&rmaps->rmaps_list);
			init_rmaps(&rmaps->default_rmaps, MAX_RMAP_ENTRIES_DEFAULT);
			list_add(&rmaps->default_rmaps.list, &rmaps->rmaps_list);
			rmaps->rmap_count = 0;
		}
#endif
	}
	for(i=s;i<e;i++) {
		vrt_set(i, NULL, VRT_SET_LOCK_SYNC | VRT_SET_INIT);
	}
}

void vrt_init(void)
{
	int i;
	MYASSERT((HYPERVISOR_VIRT_START & VRT_MASK ) == VRT_MASK);	// sanity check for VRT_MASK

	seed_xen = new_vregion(VR_REFCNT_SEED, NEWVR_SEED_XEN);
	seed_kernel = new_vregion(VR_REFCNT_SEED, NEWVR_SEED_KERNEL);
	seed_user = new_vregion(VR_REFCNT_SEED, NEWVR_SEED_USER);
#ifdef ENABLE_HOT_PAGES
	seed_user_hot = new_vregion(VR_REFCNT_SEED, NEWVR_SEED_USER_HOT);
#endif
	global = new_vregion(VR_REFCNT_GLOBAL, NEWVR_GLOBAL);
	MYASSERT(cachemap_is_global(global));	// global vr is always global..

	for(i=0;i<MFN_LOCKS_MAX;i++) {
		spin_lock_init(&vrt_lock[i]);
		spin_lock_init(&sync_lock[i]);
	}

    // see init_frametable()
    unsigned int sidx, eidx, nidx;
    unsigned int max_idx = (max_pdx + PDX_GROUP_COUNT - 1) / PDX_GROUP_COUNT;
myprintk("%d pdx groups, %d count, vbit[0]:%lx\n", max_idx, PDX_GROUP_COUNT, pdx_group_valid[0]);
    for ( sidx = 0; ; sidx = nidx )
    {
        eidx = find_next_zero_bit(pdx_group_valid, max_idx, sidx);
        nidx = find_next_bit(pdx_group_valid, max_idx, eidx);
        if ( nidx >= max_idx )
            break;
        init_vrt_chunk(sidx * PDX_GROUP_COUNT,
                       eidx * PDX_GROUP_COUNT);
    }
    if ( !mem_hotplug )
        init_vrt_chunk(sidx * PDX_GROUP_COUNT,
                              max_page);
    else
        mypanic("mem_hotplug set!?\n");
#ifdef __x86_64__
    if (opt_allow_superpage)
	mypanic("allow_superpage?\n");
#endif
}


// TODO: review..
void check_vrt_chunk(unsigned long s, unsigned long e)
{
	int i, j, count = 0, count2 = 0, count3=0, count4=0, count5=0;
	int next, prev, max = e-s;
	for(i=s;i<e;i++) {
		struct vregion_t *vr = _vrt_get(i, VR_REFCNT_VRT_TEMP);	// temp
		if (vr) {
			vr_put(vr, VR_REFCNT_VRT_TEMP, 0);
//			myprintk("WARN! mfn:%x has vr:%x\n", i, vr);
//			print_vregion(vr, 0);
			count++;
		}
#ifdef ENABLE_RMAP
		for(j=0;j<RMAPS_MAX;j++) {
			struct rmaps_builtin *r;
			r = &FTABLE_RMAPS(i, j);
			if (r->rmap_count)
				count2++;
		}
#endif
		next = FTABLE_NEXT(i);
		if (next != -1)
			count3++;
		prev = FTABLE_PREV(i);
		if (prev != -1)
			count4++;
	}
	myprintk("%d mfns (%d guest) in vrt has vr.\n", count, count5);
	if (count != max)
		myprintk("WARN!!! %d mfns != %d max ?!?\n", count, max);
#ifdef ENABLE_RMAP
	if (count2)
		myprintk("WARN!!! %d non-zero rmaps in FTABLE_RMAPS\n", count2);
#endif
	if (count3 != max)
		myprintk("WARN!!! %d next in FTABLE_NEXT != %d max\n", count3, max);
	if (count4 != max)
		myprintk("WARN!!! %d prev in FTABLE_PREV != %d max\n", count4, max);
}

void check_vrt(void)
{
    // see init_frametable()
    unsigned int sidx, eidx, nidx;
    unsigned int max_idx = (max_pdx + PDX_GROUP_COUNT - 1) / PDX_GROUP_COUNT;
myprintk("%d pdx groups, %d count, vbit[0]:%lx\n", max_idx, PDX_GROUP_COUNT, pdx_group_valid[0]);
    for ( sidx = 0; ; sidx = nidx )
    {
        eidx = find_next_zero_bit(pdx_group_valid, max_idx, sidx);
        nidx = find_next_bit(pdx_group_valid, max_idx, eidx);
        if ( nidx >= max_idx )
            break;
        check_vrt_chunk(sidx * PDX_GROUP_COUNT,
                       eidx * PDX_GROUP_COUNT);
    }
    if ( !mem_hotplug )
        check_vrt_chunk(sidx * PDX_GROUP_COUNT,
                              max_page);
    else
        mypanic("mem_hotplug set!?\n");
#ifdef __x86_64__
    if (opt_allow_superpage)
	mypanic("allow_superpage?\n");
#endif
}
#endif


#ifdef ENABLE_RMAP	// rmap inc , dec part
inline void vr_sub_rmap_count(struct vregion_t *vr, int d, int rmapi)
{
#ifdef DEBUG_ASSERT
	MYASSERT(spin_is_locked(&vr->lock));
	if (vr->rmap_count[rmapi] < d)
		mypanic("rmap_count going negative?");
	MYASSERT(rmapi < RMAPS_MAX);
#endif
	vr->rmap_count[rmapi] -= d;
//	MYASSERT(vr->frame_count <= vr->rmap_count);	// TODO: enable this
}
inline void vr_add_rmap_count(struct vregion_t *vr, int d, int rmapi)
{
	vr->rmap_count[rmapi] += d;
#ifdef DEBUG_ASSERT
	MYASSERT(spin_is_locked(&vr->lock));
	if (vr->rmap_count[rmapi] < d)
		mypanic("rmap_count overflow (<d)?");
	MYASSERT(rmapi < RMAPS_MAX);
#endif
//	MYASSERT(vr->frame_count <= vr->rmap_count);	// TODO: enable this
}

inline void vr_dec_rmap_count(struct vregion_t *vr, int rmapi, struct rmaps_builtin *r)
{
#ifdef DEBUG_ASSERT
	MYASSERT(spin_is_locked(&vr->lock));
	if (!vr->rmap_count[rmapi])
		mypanic("rmap_count going -1?");
	if (!r->rmap_count)
		mypanic("r rmap_count going -1?");
	MYASSERT(rmapi < RMAPS_MAX);
#endif
	vr->rmap_count[rmapi]--;
	r->rmap_count--;
//	MYASSERT(vr->frame_count <= vr->rmap_count);	// TODO: enable this
}
inline void vr_inc_rmap_count(struct vregion_t *vr, int rmapi, struct rmaps_builtin *r)
{
	vr->rmap_count[rmapi]++;
	r->rmap_count++;
#ifdef DEBUG_ASSERT
	MYASSERT(spin_is_locked(&vr->lock));
	if (!vr->rmap_count[rmapi])
		mypanic("rmap_count overflow?");
	if (!r->rmap_count)
		mypanic("r rmap_count overflow?");
	MYASSERT(rmapi < RMAPS_MAX);
#endif
//	MYASSERT(vr->frame_count <= vr->rmap_count);	// TODO: enable this
}
#endif
#if 1	// vr_frame_inc, dec part
inline void vr_dec_frame_count(struct vregion_t *vr)
{
	int i;
#ifdef DEBUG_ASSERT
	MYASSERT(spin_is_locked(&vr->lock));
	if (!vr->frame_count)
		mypanic("frame_count going -1?");
#endif
	vr->frame_count--;
//	MYASSERT(vr->frame_count <= vr->rmap_count);	// TODO: enable this
#ifdef ENABLE_CACHEMAN1
	for(i=0;i<max_cache;i++) {
		if (test_cachein(vr, i)) {
			myspin_lock(&cacheman[i].lock, 57);
			cacheman[i].frames_count--;
			// TODO I think density should be also adjusted here so that sum(density)==frames_count, right?
			spin_unlock(&cacheman[i].lock);
		}
	}
#endif
}
inline void vr_inc_frame_count(struct vregion_t *vr)
{
	int i;
	vr->frame_count++;
#ifdef DEBUG_ASSERT
	if (!vr->frame_count)
		mypanic("frame_count overflow?");
	MYASSERT(spin_is_locked(&vr->lock));
#endif
//	MYASSERT(vr->frame_count <= vr->rmap_count);	// TODO: enable this
#ifdef ENABLE_CACHEMAN1
	for(i=0;i<max_cache;i++) {
		if (test_cachein(vr, i)) {
			myspin_lock(&cacheman[i].lock, 58);
			cacheman[i].frames_count++;
			// TODO I think density should be also adjusted here so that sum(density)==frames_count, right?
			spin_unlock(&cacheman[i].lock);
		}
	}
#endif
}
#endif

inline void vr_get(struct vregion_t *vr, int loc)
{
	if (!(loc < MAX_VR_REFCNT)) {
		myprintk("TODO: loc=%d\n", loc);
		mypanic("TODO:");
	}
	MYASSERT(vr);
	if (atomic_inc_and_test(&vr->vr_refcnt[loc]))
		mypanic("BUG: vr_get");
}

// hint==0 : don't delete vr			hint==1 : should call del_vregion()
// hint==2 : may or may not del_vregion()
inline void vr_put(struct vregion_t *vr, int loc, int hint)
{
	if (!(loc < MAX_VR_REFCNT)) {
		myprintk("TODO: loc=%d\n", loc);
		mypanic("TODO:");
	}
	MYASSERT(vr);
	if (!atomic_dec_and_test(&vr->vr_refcnt[loc])) {
		goto no_del_vregion;
	}
	int i;
	for(i=0;i<MAX_VR_REFCNT;i++)
		if (atomic_read(&vr->vr_refcnt[i]))
			break;
	if (i==MAX_VR_REFCNT) {
#ifdef DEBUG_ASSERT
		if (hint == 0) {	// shoud've not called del_vreigon() here
			print_vregion(vr, 0);
			myprintk("WARN shouldn't delete vr here..loc:%d\n", loc);
			mypanic("vr_put\n");
		}
//		myprintk("vr:%p refcnt got zero..del\n", vr );
#endif
		del_vregion(vr);
		return 1;
	}
no_del_vregion:
#ifdef DEBUG_ASSERT
	if (hint == 1)
	{	// should've called del_vregion() above.
		myprintk("WARN vr_put didn't del it? loc=%d\n", loc);	// I think this might happen very rerely although I never seen it.
		print_vregion(vr, 0);
	}
#endif
	return 0;
}


void init_vregion_pools(void)
{
	int i,j;
	for(i=0;i<MAX_VREGION_1MB_POOL;i++) {
		vregion_1mb_pool[i] = NULL;
	}
	vregion_1mb_pool_count = 0;

	num_vregions_per_1mb = (1024*1024-256)/sizeof(struct vregion_t);
	for(i=0;i<MAX_VREGION_1MB_POOL;i++) {
		vregion_1mb_pool[i] = myxmalloc_bytes( sizeof(struct vregion_t) * num_vregions_per_1mb , 6);
		if (!vregion_1mb_pool[i])
			break;
		memset(vregion_1mb_pool[i], 0, sizeof(struct vregion_t) * num_vregions_per_1mb);
		vregion_1mb_pool_count++;
	}

	spin_lock_init(&vregions_seed_lock);
	spin_lock_init(&vregions_free_lock);
	INIT_LIST_HEAD(&vregions_seed);
	INIT_LIST_HEAD(&vregions_free);
	vregions_seed_count = 0;
	vregions_free_count = 0;
	vregions_xmalloc_count = 0;
	for(i=0;i<vregion_1mb_pool_count;i++) {
		for(j=0;j<num_vregions_per_1mb;j++) {
			struct vregion_t *vr = &(vregion_1mb_pool[i])[j];
			init_vregion(vr);
			list_add(&vr->u.vr_list, &vregions_free);
			vregions_free_count++;
		}
	}
	myprintk("%d-sized %d pools\n", num_vregions_per_1mb, vregion_1mb_pool_count);
	if (vregion_1mb_pool_count != MAX_VREGION_1MB_POOL) {
		myprintk("WARN: couldn't allocate all %d vregion pools??\n", MAX_VREGION_1MB_POOL);
	}
	myprintk("tot:%d free vregions.\n", vregions_free_count);
	myprint_xenheap();
}

static void clean_vregion(struct vregion_t *vr)
{
	// clear flags
	if (vr->flags) {
		myprintk("WARN! still has flags..\n");
		print_vregion(vr, 0);
	}
	vr->flags = 0;
	INIT_LIST_HEAD(&vr->u.vr_list);
}

// when you make changes, synchronize with new_vregion_common() function.
void init_vregion(struct vregion_t *vr)
{
	int i;
	INIT_LIST_HEAD(&vr->u.vr_list);
#ifdef ENABLE_GLOBAL_LIST
	INIT_LIST_HEAD(&vr->global_list);
#endif
	for(i=0;i<MAX_VR_REFCNT;i++)
		atomic_set(&vr->vr_refcnt[i], 0);
	spin_lock_init(&vr->lock);
#ifdef ENABLE_ADD_RMAP_OPTIMIZATION
	vr->free_rmaps = &vr->default_rmaps;
	vr->free_rmapi = 0;
#endif
	vr->frame_count = 0;
	for(i=0;i<RMAPS_MAX;i++)
		vr->rmap_count[i] = 0;
	vr->flags = 0;
	vr->head = -1;
//	vr->range = 0;
}



static void del_vregion_common(struct vregion_t *vr)
{
	int i;

#ifdef DEBUG_ASSERT
	struct rmap_set *rms;
	myspin_lock(&vr->lock,65);
	if (cachemap_count(vr))
		myprintk("nonzero cachemap_count %d!\n", cachemap_count(vr));
	if (cache_in_count(vr))
		myprintk("nonzero cache_in_count %d!\n", cache_in_count(vr));
	if (vr->rmap_count[RMAPS_USER])
		myprintk("nonzero rmap_count user %d!\n", vr->rmap_count[RMAPS_USER]);
	if (vr->rmap_count[RMAPS_KERNEL])
		myprintk("nonzero rmap_count kernel %d!\n", vr->rmap_count[RMAPS_KERNEL]);
	if (vr->frame_count)
		myprintk("nonzero frame_count %d!\n", vr->frame_count);
	if (vr->head != -1) {
		myprintk("head==%d is not -1\n", vr->head);
#ifdef ENABLE_RMAP
	if (!is_rmaps_empty(vr)) {
		myprintk("not-empty rmaps!\n");
	}
#endif
	}
	spin_unlock(&vr->lock);
#endif
	for(i=0;i<MAX_VR_REFCNT;i++) {
	if (atomic_read(&vr->vr_refcnt[i])) {
		mypanic("should not happen..\n");
	}
	}
	// rms is freed immediately whenever it's empty. e.g. del_rmap()
	for(i=0;i<vregion_1mb_pool_count;i++) {
		if ((unsigned long)vr>=(unsigned long)vregion_1mb_pool[i] && (unsigned long)vr<(unsigned long)vregion_1mb_pool[i]+num_vregions_per_1mb*sizeof(struct vregion_t)) {
			clean_vregion(vr);
			// directly put it into free list skipping dying list
			myspin_lock(&vregions_free_lock, 42);
			list_add(&vr->u.vr_list, &vregions_free);	// we can add it to tail for safety....
			vregions_free_count++;
			spin_unlock(&vregions_free_lock);
			break;
		}
	}
	if (i==vregion_1mb_pool_count) {	// if it's xmalloc'ed
		myxfree(vr, 2);
	}
}

// Do we have to lock vr->lock before calling this???
void del_vregion(struct vregion_t *vr)
{
	int i, j;
#ifdef DEBUG_ASSERT
	if (vr->frame_count || vr->rmap_count[RMAPS_USER] || vr->rmap_count[RMAPS_KERNEL]) {
		myprintk("%d frame, %d,%d rmap??\n", vr->frame_count, vr->rmap_count[RMAPS_USER], vr->rmap_count[RMAPS_KERNEL]);
		print_vregion(vr, VRPRINT_RMAP);
		mypanic("non-empty region to delete?");
	}
#ifdef ENABLE_HISTOGRAM
	// check abit_density
	for(i=0;i<MAX_CACHE;i++)
		for(j=0;j<32;j++)
			MYASSERT(vr->abit_histogram[i][j] == 0);
#endif
#endif

#ifdef ENABLE_CACHEMAN1
	// this should be called before flags are cleared below.. this function checks flags...
	cache_out_all(vr);
#endif
	vr->flags &= ((1UL<<VR_ATTR_START)-1);	// clear all vr_attr. This removes VR_FIXED_MAP, so should be done before open_vregion_cache() below..
#ifdef ENABLE_VREGION_MAPPING
	int tmp;
	myspin_lock(&vr->lock, 82);
	for(i=0;i<MAX_CACHE;i++) {
		tmp = is_vregion_cache_mapped(vr, i);
		if (!tmp) {
			open_vregion_cache(vr, i);
		}
	}
	spin_unlock(&vr->lock);
#endif

#ifdef ENABLE_GLOBAL_LIST
	// remove before calling del_vregion_common(), so as long as you find it holding seed_lock, it's not gone away.
	myspin_lock(&vregions_seed_lock, 9);
	list_del(&vr->global_list);
	vregions_seed_count--;
	spin_unlock(&vregions_seed_lock);
#endif
	del_vregion_common(vr);
}


static struct vregion_t *new_vregion_common(void)
{
	struct vregion_t *vr = NULL;
	int i, j;
	myspin_lock(&vregions_free_lock, 12);
	if (list_empty(&vregions_free)) {
		spin_unlock(&vregions_free_lock);
		vregions_xmalloc_count++;

		vr = myxmalloc(struct vregion_t, 2);
		if (vr==NULL)
			mypanic("new_vregion: xmalloc failed??");
		init_vregion(vr);
	} else {
		// we're getting new one, so don't need lock vr->lock
		vr = list_entry(vregions_free.next , struct vregion_t, u.vr_list);
		list_del(&vr->u.vr_list);
		vregions_free_count--;
		spin_unlock(&vregions_free_lock);
		// make sure they're completely cleaned-up
		for(i=0;i<MAX_VR_REFCNT;i++) {
			MYASSERT(!atomic_read(&vr->vr_refcnt[i]));
		}
		MYASSERT(!spin_is_locked(&vr->lock));
#ifdef ENABLE_RMAP
		MYASSERT(is_rmaps_empty(vr));
#endif
		MYASSERT(!vr->frame_count);
		MYASSERT(!vr->rmap_count[RMAPS_USER]);
		MYASSERT(!vr->rmap_count[RMAPS_KERNEL]);
		if (vr->flags) {
			print_vregion(vr, 0);
			myprintk("not-cleaned vrflags\n");
			MYASSERT(!vr->flags);
		}
		MYASSERT(vr->head == -1);
#ifdef ENABLE_ADD_RMAP_OPTIMIZATION
		MYASSERT(vr->free_rmaps == &vr->default_rmaps);
		MYASSERT(vr->free_rmapi == 0);
#endif
//		MYASSERT(vr->range == 0);
	}
	// TODO: these should be in init_vregion? so that they can be gracefully cleaned up ?
#ifdef ENABLE_ABIT
//	vr->last_abit_update = 0;
#endif
#ifdef ENABLE_HISTOGRAM
	for(j=0;j<MAX_CACHE;j++)
		for(i=0;i<32;i++)
			MYASSERT(vr->abit_histogram[i][j] == 0);
//			vr_reset_density(vr, i, j);
#endif
#ifdef ENABLE_REGIONING3
	vr->tpoint = 0;
	vr->access = 0;
#endif
	vr->u.inuse.cman = NULL;
	vr->u.inuse.empty = NULL;
	return vr;
}

// new empty vregion due to  add_guest_region()
struct vregion_t *new_vregion(int loc, unsigned long flags)
{
	struct vregion_t *vr;
	vr = new_vregion_common();
	vr_get(vr, loc);

	myspin_lock(&vr->lock, 130);
	MYASSERT(vr->flags == 0);
	vr->flags = flags;
	spin_unlock(&vr->lock);
#ifdef ENABLE_GLOBAL_LIST
	// move to seed list. now you can access it through seed_lock,
	// but! it's not referece-counted, so once you unlock seed_lock, it may go away!!
	myspin_lock(&vregions_seed_lock, 74);
	list_add(&vr->global_list, &vregions_seed);
	vregions_seed_count++;
	spin_unlock(&vregions_seed_lock);
#endif
	return vr;
}

// caller should vr-get(vr) before calling this to prevent 'vr' disappearing..
// move all mfns to 'to' region
void split_vregion(struct vregion_t *vr, struct vregion_t *to)
{
	unsigned long mfn;
	struct vregion_t *old;
	do {
		mfn = vr->head;	// peek without locking
		myspin_lock(&SYNC_LOCK(mfn), 50);
		myspin_lock(&vr->lock, 8);
		if (vr->head != -1) {
			if (mfn != vr->head) {	// if differs, we need lock it again..
				myprintk("retry..\n");
				spin_unlock(&vr->lock);
				spin_unlock(&SYNC_LOCK(mfn));
				continue;
			}
			spin_unlock(&vr->lock);
			old = vrt_set(mfn, to, VRT_SET_RETURN_OLD);
			// since we hold sync_lock, the vrt entry shouldn't change
			MYASSERT(old == vr);
			if (old)
				vr_put(old, VR_REFCNT_VRT_TEMP, 0);
		} else {
			MYASSERT(!vr->frame_count);
			spin_unlock(&vr->lock);
			spin_unlock(&SYNC_LOCK(mfn));
			break;
		}
		spin_unlock(&SYNC_LOCK(mfn));
	} while(1);
}

void merge_vregion(struct vregion_t *vr, struct vregion_t *to)
{
	MYASSERT(test_bit(VR_REGULAR, &vr->flags) && test_bit(VR_REGULAR, &to->flags));
	MYASSERT(vr->flags == to->flags);
	split_vregion(vr, to);	// so, it takes O(n). how to improve it?
}
#endif
