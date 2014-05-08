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

#ifdef ENABLE_PER_CACHE_PT

#define intpte_get_pfn(X)	\
    ((unsigned long)(((X) & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT))	// see l1e_get_pfn()

int l1e_state(l1_pgentry_t l1e)
{
	if (l1e_get_pfn(l1e)) {
		if (l1e_get_flags(l1e)&
#ifdef ENABLE_PROTECTION_BIT
			_PAGE_USER
#else
			_PAGE_PRESENT
#endif
			)
			return L1E_OPEN;
		else
			return L1E_CLOSED;
	} else {
		MYASSERT(!(l1e_get_flags(l1e)&_PAGE_PRESENT));
		return L1E_NOT_PRESENT;
	}
}

// change flags
void flag_shadow(struct page_table *pt, int ptindex, l1_pgentry_t nl1e)
{
	int i;
	l1_pgentry_t *l1t;
	l1_pgentry_t *pl1e;
	l1_pgentry_t ol1e;
	MYASSERT(l1e_get_flags(nl1e)&_PAGE_PRESENT);

	for(i=0;i<max_cache;i++) {
		l1t = pt->shadow[i];
		pl1e = &l1t[ptindex];
		ol1e = *pl1e;
//		MYASSERT(l1e_get_pfn(ol1e) == l1e_get_pfn(nl1e));

#if 1 //def ENABLE_KERNEL_SPACE
	if (i==0)
	if ((l1e_get_flags(nl1e)&_PAGE_GUEST_KERNEL) != (l1e_get_flags(ol1e)&_PAGE_GUEST_KERNEL)) {
		myprintk("%d->%d guest kernel bit @ va:%lx\n", 
		(l1e_get_flags(ol1e)&_PAGE_GUEST_KERNEL),
		(l1e_get_flags(nl1e)&_PAGE_GUEST_KERNEL),
		get_va(pt, ptindex)
		);
	}
#endif
		MYASSERT(l1e_state(nl1e) == L1E_OPEN);

		if ( l1e_state(ol1e) == L1E_CLOSED ) {
			l1_pgentry_t temp = nl1e;
			l1e_close(&temp, 0);
			l1t[ptindex] = temp;
		} else
			l1t[ptindex] = nl1e;
	}

#ifdef ENABLE_REGIONING2
		// pgd->current_region may be open even. others are initially closed by add_shadow
		l1t = pt->regioning_shadow;
		pl1e = &l1t[ptindex];
		ol1e = *pl1e;
		MYASSERT(l1e_get_pfn(l1t[ptindex]) == l1e_get_pfn(nl1e));
		MYASSERT(l1e_state(nl1e) == L1E_OPEN);
		if ( l1e_state(ol1e) == L1E_CLOSED ) {
			l1_pgentry_t temp = nl1e;
			l1e_close(&temp, 0);
			l1t[ptindex] = temp;
		} else
			l1t[ptindex] = nl1e;
#endif
}

// del non-xenheap page to (usually) leaf pt
void del_shadow(struct page_table *pt, int ptindex, unsigned long mfn)
{
	int i;
	l1_pgentry_t *p;
#ifdef ENABLE_MYXTRACE
	if (is_xen_heap_mfn(mfn)) {	// in case of xentrace, it maps xen_heap_mfn..
		myprintk("WARN! guest un-maps xen_heap_mfn.. maybe xentrace?\n");
	}
#else
	MYASSERT(!is_xen_heap_mfn(mfn));
#endif
	for(i=0;i<max_cache;i++) {
		p = pt->shadow[i];
//		MYASSERT(mfn == l1e_get_pfn(p[ptindex]));
/*		if (!(mfn == l1e_get_pfn(p[ptindex]))) {
			myprintk("mfn:%lx != %lx , pti:%d, l%d\n", mfn, l1e_get_pfn(p[ptindex]), ptindex, pt->level);
//			mypanic("!!@@@###");
		}*/
#if 0		// this is also normal cases
		if (l1e_state(p[ptindex]) == L1E_CLOSED) {
			myprintk("WARN: del closed entry\n");
		}
#endif
		p[ptindex].l1 = NULL;
	}
#ifdef ENABLE_BITMAP_BASIC
	if (pt->level == 1)
		close_bitmap(pt, ptindex, -1);
#endif
#ifdef ENABLE_REGIONING2
	p = pt->regioning_shadow;
	p[ptindex].l1 = NULL;
#endif
}

#ifdef ENABLE_KERNEL_SHADOW
// guest-kernel area..
void add_shadow2(struct page_table *pt, int ptindex, struct page_table *pt2)
{
	int i;
	intpte_t *p, *p2;
	for(i=0;i<max_cache;i++) {
		p = pt->shadow[i];
		p2 = pt2->shadow[i];
		if (!(p[ptindex] == NULL)) {
			print_pt(pt);
			myprintk("pti:%d \n", ptindex);
			mypanic("!!!");
		}
		p[ptindex] = p2[ptindex];
	}
#ifdef ENABLE_REGIONING2
		p = pt->regioning_shadow;
		p2 = pt2->regioning_shadow;
		if (!(p[ptindex] == NULL)) {
			print_pt(pt);
			myprintk("pti:%d \n", ptindex);
			mypanic("!!!!");
		}
		p[ptindex] = p2[ptindex];	// open by default.. so no kernel space regioning
#if 0 //def ENABLE_REGIONING3
		TODO kernel space regioning???
		// initially closed except when regioning_init_open==1
		if (!regioning_init_open) {
			MYASSERT(pt->level == 1);	// close only leaf pt
			l1e_close(&p[ptindex], 0);
		}
#endif
#endif
}
#endif


// add non-xenheap page to (usually) leaf pt
void add_shadow(struct page_table *pt, int ptindex, intpte_t l1e, unsigned int bitmap, int regioning_init_open)
{
	int i;
	intpte_t *p;
#ifdef ENABLE_MYXTRACE
	if (is_xen_heap_mfn(intpte_get_pfn(l1e))) {	// in case of xentrace, it maps xen_heap_mfn..
		myprintk("WARN! guest maps xen_heap_mfn.. maybe xentrace?\n");
	}
#else
	MYASSERT(!is_xen_heap_mfn(intpte_get_pfn(l1e)));
#endif
	l1e &= ~((unsigned long)(_PAGE_AVAIL));	// clean l1e
	MYASSERT(l1e & _PAGE_PRESENT);
#if 0
	unsigned int flag = get_pte_flags(l1e) & _PAGE_GUEST_KERNEL;
	if () {
		if (flag)
		{
			myprintk("user-leaf. pti:%x l1e:%x va:%x\n", ptindex, l1e, get_va(pt, ptindex));
			print_pt(pt);
		}
	} else {
		if (!flag)
		{
			myprintk("kernel-leaf. pti:%x l1e:%x va:%x\n", ptindex, l1e, get_va(pt, ptindex));
			print_pt(pt);
		}
	}
#endif
	for(i=0;i<max_cache;i++) {
		p = pt->shadow[i];
		if (!(p[ptindex] == NULL)) {
			print_pt(pt);
			myprintk("pti:%d l1e=%lx\n", ptindex, l1e);
			mypanic("!!!");
		}
		p[ptindex] = l1e;
		if (pt->level != 1)
			continue;
#if 1
		// TODO: do I need myspin_lock_pt(pt, xx) ???
		// TODO: use macro for this..
		if (test_bit(VR_CACHEMAP_BASE+i, &bitmap)) {	// if closed.. i.e. (!is_vregion_cache_mapped())
                        // in this case, bitmap is already zeroed..
#ifdef ENABLE_BITMAP_VRT
#ifdef DEBUG_WARN
			if (test_bitmap(pt, ptindex, i))
				myprintk("WARN! open bit?\n");
#endif
#endif
			l1e_close(&p[ptindex], 0);
		} else {
#ifdef ENABLE_BITMAP_VRT
                        open_bitmap(pt, ptindex, i);
#endif
		}
#endif
	}
#ifdef ENABLE_BITMAP_BASIC
	if (pt->level == 1)
		open_bitmap(pt, ptindex, -1);
#endif
#ifdef ENABLE_REGIONING2
		p = pt->regioning_shadow;
		p[ptindex] = l1e;
#ifdef ENABLE_REGIONING3
		// initially closed except when regioning_init_open==1
		if (!regioning_init_open) {
			MYASSERT(pt->level == 1);	// close only leaf pt
			l1e_close(&p[ptindex], 0);
		}
#endif
#endif
}

#ifdef ENABLE_KERNEL_SHADOW
#define SHADOW_NONLEAF_ASSERTION
#else
#define SHADOW_NONLEAF_ASSERTION	\
{					\
	unsigned long va = get_va(pt, ptindex);	\
	if (va >= USERLAND_END) {		\
		myprintk("va:%lx !!\n", va);	\
		mypanic("panic");		\
	}					\
}
#endif

// del xenheap page to interior pt
void del_shadow_nonleaf(struct page_table *pt, int ptindex)
{
	int i;
	intpte_t *p;
	MYASSERT(pt->level != 1);
SHADOW_NONLEAF_ASSERTION
	for(i=0;i<max_cache;i++) {
		p = pt->shadow[i];
		unsigned long mfn = intpte_get_pfn(p[ptindex]);
		MYASSERT(is_xen_heap_mfn(mfn));
		p[ptindex] = NULL;
	}
#ifdef ENABLE_REGIONING2
		p = pt->regioning_shadow;
		p[ptindex] = NULL;
#endif
}
// add xenheap page to interior pt
void add_shadow_nonleaf(struct page_table *pt, int ptindex, struct page_table *newl1, unsigned long flags)
{
	int i;
	unsigned long mfn;
	intpte_t *p;

	MYASSERT(flags & _PAGE_PRESENT);
	MYASSERT(pt->level != 1);
SHADOW_NONLEAF_ASSERTION

//	if (flags & _PAGE_USER)
	if (pt->level == 4 && L4_GUEST_KERNEL(ptindex))
	{
		myprintk("kernel-nonleaf. pti:%d f:%x va:0x%lx\n", ptindex, flags, get_va(pt, ptindex));
		print_pt(pt);
	}

	for(i=0;i<max_cache;i++) {
		p = pt->shadow[i];
		MYASSERT(p[ptindex] == NULL);
		mfn = virt_to_mfn(newl1->shadow[i]);
		MYASSERT(is_xen_heap_mfn(mfn));
		p[ptindex] = (put_pte_flags(flags) | ((intpte_t)(mfn)<<PAGE_SHIFT));
//		p[ptindex] = (flags | (mfn<<PAGE_SHIFT));
		MYASSERT(intpte_get_pfn(p[ptindex]) == mfn);
		MYASSERT(get_pte_flags(p[ptindex]) == flags);
	}
#ifdef ENABLE_REGIONING2
		p = pt->regioning_shadow;
		MYASSERT(p[ptindex] == NULL);
		mfn = virt_to_mfn(newl1->regioning_shadow);
		MYASSERT(is_xen_heap_mfn(mfn));
		p[ptindex] = (put_pte_flags(flags) | (mfn<<PAGE_SHIFT));
//		p[ptindex] = (flags | (mfn<<PAGE_SHIFT));
#endif
}
int cr3_is_shadow(int locked)
{
	struct page_dir *pgd = current->current_pgd;
	int ret = 0;
#ifdef ENABLE_REGIONING2
if (!locked)
	myspin_lock(&pgd->lock, 24);
#endif
	unsigned long mfn = (read_cr3() >> PAGE_SHIFT);

	if (mfn == virt_to_mfn(pgd->pt->shadow[cache_now]))
		ret = 1;
#ifdef ENABLE_REGIONING2
struct vregion_t *cur = pgd->current_region;
int cpu = pgd->regioning_cpu;
if (!locked)
	spin_unlock(&pgd->lock);

	if (ret) {
//		if (myspin_trylock(&pgd->lock, 34)) {	// for call from ticks
//			if (pgd->current_region && pgd->regioning_cpu == smp_processor_id()) {
			if (cur && cpu == smp_processor_id()) {
				myprintk("mfn:%x\n", mfn);
				mypanic("normal-shadow during regioning?");
			}
//			spin_unlock(&pgd->lock);
//		}
	} else {
		if (mfn == virt_to_mfn(pgd->pt->regioning_shadow))
			ret = 2;
		else
			mypanic("?!?!?");
//		if (myspin_trylock(&pgd->lock, 29)) {	// for call frrom ticks
			if (cpu != smp_processor_id())
				myprintk("regioning_cpu is %d ?\n", cpu);
			if (!cur)
				mypanic("zero cur_region during regioning?");
//			spin_unlock(&pgd->lock);
//		}
	}
#endif
	if (!ret) {
		myprintk("pgdmfn:%lx, cr3:%lx [%lx,%lx], "
			 "g:%lx u:%lx\n",pgd->pt->mfn, mfn, virt_to_mfn(pgd->pt->shadow[0]), virt_to_mfn(pgd->pt->shadow[1]),
			 current->arch.guest_table.pfn, current->arch.guest_table_user.pfn);
	}
	return ret;
}
#endif
