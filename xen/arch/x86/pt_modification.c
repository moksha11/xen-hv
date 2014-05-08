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


#ifdef ENABLE_PT_MODIFICATION

#define PTR_TO_INDEX(X)	(((unsigned long)(X) & ~PAGE_MASK)>>3)

void l1e_update_success_common(l1_pgentry_t *pl1e, l1_pgentry_t ol1e, l1_pgentry_t nl1e, int grant)
{
	int ptindex, any_marking;
	struct page_table *pt = this_cpu(found_pt);

	if (!mini_activated) {	// !mini_activated
		if (pt)			// in case of disabling, this happens..
			unlock_pt(0);   // because sometimes locked, and disabled, so we miss unlocking..TODO: make it clear..
		return;
	}
	if (pt == NULL) {
#ifdef VERBOSE_PAGE_TABLE_L1E_NOT_MANAGED
//		myprintk("not-managed. %x->%x\n", ol1e.l1, nl1e.l1);
		printk("[L1]");
#endif
		return;	// not-managed yet...
	}
	MYASSERT(!pt->user_l4);

	MYASSERT(mini_activated);
	ptindex = PTR_TO_INDEX(pl1e);
	MYASSERT(ptindex < L1_PAGETABLE_ENTRIES);

#ifdef DEBUG_ASSERT
	unsigned long va = get_va(pt, ptindex);
/*	if (grant) {
		myprintk("INFO grant l1e entry.. va=%lx, %lx->%lx @ %lx\n", va, ol1e.l1, nl1e.l1, pl1e);
	}*/
#ifdef ENABLE_KERNEL_SHADOW
	if (va >= HYPERVISOR_VIRT_START && va < HYPERVISOR_VIRT_END)
#else
	if (va >= USERLAND_END)
#endif
	{	// kernel or xen space
		myprintk("kernel or xen space..skip. va:%lx up_index[%d,%d,%d] %lx->%lx\n", va, pt->up_index, pt->up_pt->up_index, pt->up_pt->up_pt->up_index, ol1e.l1, nl1e.l1);
		mypanic("l1e_update_success_common in kernel\n");
		unlock_pt(0);
		return;
	}
#endif

#ifdef ENABLE_MARK_VREGION
	any_marking = 0;
	if ((l1e_get_flags(ol1e) & _PAGE_PRESENT) && ((l1e_get_pfn(ol1e)!=l1e_get_pfn(nl1e)) || !(l1e_get_flags(nl1e)&_PAGE_PRESENT)) ) {
		l1e_unmark(pl1e, 0,  pt, ptindex, l1e_get_pfn(ol1e));
		any_marking = 1;
	}

        if ((l1e_get_flags(nl1e) & _PAGE_PRESENT) && ((l1e_get_pfn(ol1e)!=l1e_get_pfn(nl1e)) || !(l1e_get_flags(ol1e)&_PAGE_PRESENT)) ) {
		l1e_mark(pl1e, 0, pt, ptindex );
		any_marking = 1;
        }

#ifdef ENABLE_PER_CACHE_PT
	// flags other than marks
	if (!any_marking && (l1e_get_flags(nl1e)&_PAGE_PRESENT) && l1e_get_flags(ol1e) != l1e_get_flags(nl1e)) {
		flag_shadow(pt, ptindex, nl1e);
	}

	// TODO: ol1e is always open....
#endif

#endif
//	flush_tlb_all();	// WARN! do not use this.. this slows down so much!! especially for L1
//	flush_area_all(va, TLB_FLUSH);
	unlock_pt(0);

#ifdef VERBOSE_PAGE_TABLE_L1E_CHANGE_SUCCESS
	myprintk("ol1e:%x->nl1e:%x\n", ol1e.l1, pl1e->l1 );
#endif


#ifdef VERBOSE_CLOCK
//#define _PAGE_ACCESSED 0x020U
//#define _PAGE_DIRTY    0x040U
//	if (ol1e.l1 && pl1e->l1 && ((ol1e.l1 & (_PAGE_ACCESSED | _PAGE_DIRTY)))!=((pl1e->l1)&(_PAGE_ACCESSED|_PAGE_DIRTY)))
//		myprintk("Detected AD change: ol1e:%x->nl1e:%x\n", ol1e.l1, pl1e->l1 );
#endif
}
void l2e_update_success(l2_pgentry_t *pl2e, l2_pgentry_t ol2e, l2_pgentry_t nl2e, unsigned long mfn)
{
	if (!mini_activated)
		return;
	atomic_inc(&mini_count);
	atomic_inc(&mini_place[4]);

	struct page_table *pt;
	mfn_check(mfn);
	ptman_lock(mfn);
	pt = ptman_find(mfn);
	ptman_unlock(mfn);
	if (!pt) {	// check if it's managed pt
		// In initial phase, sometimes happens... we could do add_pgd(), but ignore.
//		myprintk("mod_l2_entry().. not-managed but try to modify..ignore..\n");
		printk("[L2]");
		goto success_l2_out;
	}
	MYASSERT(!pt->user_l4);
	int pt_index = PTR_TO_INDEX(pl2e);
	MYASSERT(pt_index < L2_PAGETABLE_ENTRIES);
#ifdef ENABLE_PT_RECURSIVE
	if (get_va(pt, pt_index) >= USERLAND_END )
#ifdef ENABLE_KERNEL_SHADOW
	{
		mypanic("l2e_update_success in kernel\n");
	}
#else
		goto success_l2_out;
#endif
	MYASSERT(pt->level == 2);
#endif

#ifdef VERBOSE_PAGE_TABLE_L2E_CHANGE_SUCCESS
	myprintk("ol2e:%x->nl2e:%x\n", ol2e.l2, nl2e.l2 );
#endif
	int any_marking = 0;
	if ((l2e_get_flags(ol2e) & _PAGE_PRESENT) && ((l2e_get_pfn(ol2e)!=l2e_get_pfn(nl2e)) || !(l2e_get_flags(nl2e)&_PAGE_PRESENT)) ) {
#ifdef ENABLE_PT_RECURSIVE
#ifdef ENABLE_PER_CACHE_PT
		del_shadow_nonleaf(pt, pt_index);
#endif
		del_pt(pt, pt_index ,l2e_get_pfn(ol2e));
		any_marking = 1;
#endif
	}

       if ((l2e_get_flags(nl2e) & _PAGE_PRESENT) && ((l2e_get_pfn(ol2e)!=l2e_get_pfn(nl2e)) || !(l2e_get_flags(ol2e)&_PAGE_PRESENT)) ) {
#ifdef ENABLE_PT_RECURSIVE
		struct page_table *newpt = add_pt(pt, pt_index, l2e_get_pfn(nl2e));
#ifdef ENABLE_PER_CACHE_PT
		add_shadow_nonleaf(pt, pt_index, newpt, l2e_get_flags(nl2e));
#endif
		any_marking = 1;
#endif
	}
#ifdef ENABLE_PT_RECURSIVE
	if (!any_marking && l2e_get_flags(ol2e) != l2e_get_flags(nl2e)) {
		myprintk("WARN: flag-changes in l2e..TODO.. %x -> %x\n", ol2e.l2, nl2e.l2 );
	}
#endif
success_l2_out:
//	flush_tlb_all();	// WARN! do not use this.. this slows down so much!! especially for L1
//	flush_area_all(va, TLB_FLUSH);
	unlock_pt(0);
	atomic_dec(&mini_place[4]);
	atomic_dec(&mini_count);
}

#if CONFIG_PAGING_LEVELS >= 3
void l3e_update_success(l3_pgentry_t *pl3e, l3_pgentry_t ol3e, l3_pgentry_t nl3e, unsigned long mfn)
{
	if (!mini_activated)
		return;
	atomic_inc(&mini_count);
	atomic_inc(&mini_place[5]);

	struct page_table *pt;
	mfn_check(mfn);
	ptman_lock(mfn);
	pt = ptman_find(mfn);
	ptman_unlock(mfn);
	if (!pt) {	// check if it's managed pt
		// In initial phase, sometimes happens... we could do add_pgd(), but ignore.
//		myprintk("mod_l3_entry().. not-managed but try to modify..ignore..\n");
		printk("[L3]");
		goto success_l3_out;
	}
	MYASSERT(!pt->user_l4);
	int pt_index = PTR_TO_INDEX(pl3e);
	MYASSERT(pt_index < L3_PAGETABLE_ENTRIES);
#ifdef ENABLE_PT_RECURSIVE
	if (get_va(pt, pt_index) >= USERLAND_END )
#ifdef ENABLE_KERNEL_SHADOW
	{
		mypanic("l3e_update_success in kernel\n");
	}
#else
		goto success_l3_out;
#endif
	MYASSERT(pt->level == 3);
#endif

#ifdef VERBOSE_PAGE_TABLE_L3E_CHANGE_SUCCESS
	myprintk("ol3e:%x->nl3e:%x\n", ol3e.l3, nl3e.l3 );
#endif
	int any_marking = 0;
	if ((l3e_get_flags(ol3e) & _PAGE_PRESENT) && ((l3e_get_pfn(ol3e)!=l3e_get_pfn(nl3e)) || !(l3e_get_flags(nl3e)&_PAGE_PRESENT)) ) {
#ifdef ENABLE_PT_RECURSIVE
#ifdef ENABLE_PER_CACHE_PT
		del_shadow_nonleaf(pt, pt_index);
#endif
		del_pt(pt, pt_index ,l3e_get_pfn(ol3e));
		any_marking = 1;
#endif
	}

       if ((l3e_get_flags(nl3e) & _PAGE_PRESENT) && ((l3e_get_pfn(ol3e)!=l3e_get_pfn(nl3e)) || !(l3e_get_flags(ol3e)&_PAGE_PRESENT)) ) {
#ifdef ENABLE_PT_RECURSIVE
		struct page_table *newpt = add_pt(pt, pt_index, l3e_get_pfn(nl3e));
#ifdef ENABLE_PER_CACHE_PT
		add_shadow_nonleaf(pt, pt_index, newpt, l3e_get_flags(nl3e));
#endif
		any_marking = 1;
#endif
	}
#ifdef ENABLE_PT_RECURSIVE
	if (!any_marking && l3e_get_flags(ol3e) != l3e_get_flags(nl3e)) {
		myprintk("WARN: flag-changes in l3e..TODO.. %x -> %x\n", ol3e.l3, nl3e.l3 );
	}
#endif
success_l3_out:
//	flush_tlb_all();	// WARN! do not use this.. this slows down so much!! especially for L1
//	flush_area_all(va, TLB_FLUSH);
	unlock_pt(0);
	atomic_dec(&mini_place[5]);
	atomic_dec(&mini_count);
}
#endif
#if CONFIG_PAGING_LEVELS >= 4
void l4e_update_success(l4_pgentry_t *pl4e, l4_pgentry_t ol4e, l4_pgentry_t nl4e, unsigned long mfn)
{
	if (!mini_activated)
		return;
	atomic_inc(&mini_count);
	atomic_inc(&mini_place[6]);

	struct page_table *pt;
	mfn_check(mfn);
	ptman_lock(mfn);
	pt = ptman_find(mfn);
	ptman_unlock(mfn);
	if (!pt) {	// check if it's managed pt
		// In initial phase, sometimes happens... we could do add_pgd(), but ignore.
//		myprintk("mod_l4_entry().. not-managed but try to modify..ignore..\n");
		printk("[L4]");
		goto success_l4_out;
	}
	if (pt->user_l4)	// ignore user_l4 l4e_update
		goto success_l4_out;
	int pt_index = PTR_TO_INDEX(pl4e);
	MYASSERT(pt_index < L4_PAGETABLE_ENTRIES);
#ifdef ENABLE_PT_RECURSIVE
	if (get_va(pt, pt_index) >= USERLAND_END )
#ifdef ENABLE_KERNEL_SHADOW
	{
		mypanic("l4e_update_success in kernel\n");
	}
#else
		goto success_l4_out;
#endif
	MYASSERT(pt->level == 4);
#endif

#ifdef VERBOSE_PAGE_TABLE_L4E_CHANGE_SUCCESS
	myprintk("ol4e:%x->nl4e:%x\n", ol4e.l4, nl4e.l4 );
#endif
	int any_marking = 0;
	if ((l4e_get_flags(ol4e) & _PAGE_PRESENT) && ((l4e_get_pfn(ol4e)!=l4e_get_pfn(nl4e)) || !(l4e_get_flags(nl4e)&_PAGE_PRESENT)) ) {
#ifdef ENABLE_PT_RECURSIVE
#ifdef ENABLE_PER_CACHE_PT
		del_shadow_nonleaf(pt, pt_index);
#endif
		del_pt(pt, pt_index ,l4e_get_pfn(ol4e));
		any_marking = 1;
#endif
	}

       if ((l4e_get_flags(nl4e) & _PAGE_PRESENT) && ((l4e_get_pfn(ol4e)!=l4e_get_pfn(nl4e)) || !(l4e_get_flags(ol4e)&_PAGE_PRESENT)) ) {
#ifdef ENABLE_PT_RECURSIVE
		struct page_table *newpt = add_pt(pt, pt_index, l4e_get_pfn(nl4e) /*, L4_GUEST_KERNEL(pt_index)*/ );
#ifdef ENABLE_PER_CACHE_PT
		add_shadow_nonleaf(pt, pt_index, newpt, l4e_get_flags(nl4e));
#endif
		any_marking = 1;
#endif
	}
#ifdef ENABLE_PT_RECURSIVE
	if (!any_marking && l4e_get_flags(ol4e) != l4e_get_flags(nl4e)) {
		myprintk("WARN: flag-changes in l4e..TODO.. %x -> %x\n", ol4e.l4, nl4e.l4 );
	}
#endif
success_l4_out:
//	flush_tlb_all();	// WARN! do not use this.. this slows down so much!! especially for L1
//	flush_area_all(va, TLB_FLUSH);
	unlock_pt(0);
	atomic_dec(&mini_place[6]);
	atomic_dec(&mini_count);
}
#endif
#endif
