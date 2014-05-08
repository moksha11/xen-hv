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

#ifdef ENABLE_PGD

struct list_head pgd_list;
int pgd_count;
spinlock_t pgd_list_lock;

void init_pgds(void)
{
	INIT_LIST_HEAD(&pgd_list);
	pgd_count = 0;
	spin_lock_init(&pgd_list_lock);
}

#ifdef ENABLE_GLOBALIZE2
void init_ui(struct usched_info *ui)
{
	int i;
	for(i=0;i<MAX_USCHED_INFO;i++) {
		ui[i].eip = 0;
		ui[i].addr = 0;
		ui[i].from = -1;
		ui[i].vr = NULL;
		ui[i].vr_flags = 0;
		ui[i].mfn = -1;
		ui[i].time = 0;
	}
}
#endif

void print_page(unsigned long mfn)
{
	struct page_info *p = mfn_to_page(mfn);
	myprintk("mfn:%x, type:%x, raw_type:%x, owner:%x is_xen_heap:%d is_iomem:%d\n", mfn, p->u.inuse.type_info & PGT_type_mask, p->u.inuse.type_info, page_get_owner(p), is_xen_heap_page(p), is_iomem_page(mfn) );
}
#ifdef ENABLE_PTMAN
struct page_table *add_pgd_user(unsigned long mfn)
{
	mfn_check(mfn);
	MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_l4_page_table );
	MYASSERT_PAGE_IS_VALIDATED( mfn_to_page(mfn));
#if 0	// do I need any of these?? taken from add_pgd()
#ifdef ENABLE_PTMAN
	lock_pgd(mfn, pgd, 3);
#endif
#ifdef ENABLE_PTMAN
	pgd->pt = add_pt(pgd, -1, mfn);
#else
	pgd->mfn = mfn;
#endif
	myspin_lock(&pgd_list_lock, 116);
	list_add(&pgd->list, &pgd_list);
	pgd_count++;
	spin_unlock(&pgd_list_lock);
#ifdef ENABLE_PTMAN
	unlock_pt(1);
#endif
#ifdef ENABLE_PTMAN
#ifdef VERBOSE_PAGE_TABLE_INOUT
	myprintk("pgdmfn=%5x added,count=%d\n", pgd->pt->mfn, pgd_count);
#endif
	TRACE_2D(TRC_MIN_ADD_PGD, pgd->pt->mfn, 0 /* TODO remove this.. was pgd id */ );
#else
#ifdef VERBOSE_PAGE_TABLE_INOUT
	myprintk("pgdmfn=%5x added,count=%d\n", pgd->mfn, pgd_count);
#endif
	TRACE_2D(TRC_MIN_ADD_PGD, pgd->mfn, 0 /* TODO remove this.. was pgd id */ );
#endif
#endif
	return add_pt_user(mfn);
}
#endif
struct page_dir *add_pgd(unsigned long mfn, unsigned long flag)
{
	int i;
	struct page_dir *pgd;
	mfn_check(mfn);
#ifdef DEBUG_ASSERT
	if (!test_bit(PGD_KERNEL, &flag) ) {
		MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_l4_page_table );
//		print_page(mfn);
		MYASSERT_PAGE_IS_VALIDATED( mfn_to_page(mfn));
	}
#endif
	pgd = myxmalloc(struct page_dir, 4);
	if (!pgd)
		mypanic("xmalloc failed! - add_pgd()\n");
	pgd->domain = current->domain;
	INIT_LIST_HEAD(&pgd->list);
	atomic_set(&pgd->refcnt, 0);
	spin_lock_init(&pgd->lock);
	pgd->flag = flag;
	pgd->mark_count = 0;
	memset(pgd->openbit_count, 0, sizeof(pgd->openbit_count));
#ifdef ENABLE_REGIONING2
//	spin_lock_init(&pgd->rlock);
	pgd->current_region = NULL;
	pgd->regioning_cpu = -1;
#ifdef ENABLE_REGIONING5
	pgd->regioning_kstack = NULL;
#endif
	pgd->regioning_tick = 0;
	pgd->region_switch_count = 0;
	pgd->sequential_count = 0;
	pgd->merge_count = 0;
	pgd->region_prev_user_page_touch = -1;
	pgd->region_prev_kernel_page_touch = -1;
	pgd->region_prev_time = 0;
	pgd->regioning_adjust = pgd->regioning_adjust_prev = 0;
	pgd->regioning_pause_reason = -1;
	pgd->regioning_pause_count = 0;
	pgd->regioning_usched_count = 0;
	pgd->newregular_during_normalexec_count = 0;
	pgd->regioning_count = 0;
	pgd->regioning_prev_region = NULL;
#endif
#ifdef VERBOSE_BITMAP_PRINT
	pgd->opening_count = 0;
#endif
/*	pgd->vregions_private_count = 0;
        INIT_LIST_HEAD(&pgd->vregions_private);
        spin_lock_init(&pgd->vregions_private_lock);
*/
	pgd->mfn_user = 0;
#ifdef ENABLE_DENSITY
	// should be fine
	memset(pgd->abit_density, 0, sizeof(pgd->abit_density));
#endif
#ifdef ENABLE_RANGE
	for(i=0;i<MAX_RANGES;i++) {
		pgd->ranges[i].vfn = 0;
		pgd->ranges[i].count = 0;
		pgd->ranges[i].rd = 0;
	}
#endif
#ifdef ENABLE_CLOCK
	pgd->clock_residue = 0;
	pgd->clock_prev_now = NOW();
	pgd->clock_cr3_changes = 0;
	pgd->clock_timer = 0;
	pgd->clock_schedule= 0;
	pgd->vtick_count = 0;
#endif
#ifdef ENABLE_ABIT
	pgd->clear_abit_count = 0;
#endif
#ifdef ENABLE_PTMAN
	pgd->pt = NULL;	// will be set below
	lock_pgd(mfn, pgd, 3);
	pgd->pt = add_pt(pgd, -1, mfn);
#else
	pgd->pt = myxmalloc(struct page_table, 3);
	if (!pgd->pt)
		mypanic("xmalloc failed.");
	pgd->pt->mfn = mfn;
	pgd->pt->user_l4 = 0;
#endif
	myspin_lock(&pgd_list_lock, 116);
	list_add(&pgd->list, &pgd_list);
	pgd_count++;
	spin_unlock(&pgd_list_lock);
#ifdef ENABLE_PTMAN
	unlock_pt(1);
#endif
#ifdef ENABLE_PTMAN
#ifdef VERBOSE_PAGE_TABLE_INOUT
	myprintk("pgdmfn=%5x added,count=%d\n", pgd->pt->mfn, pgd_count);
#endif
	TRACE_2D(TRC_MIN_ADD_PGD, pgd->pt->mfn, 0 /* TODO remove this.. was pgd id */ );
#else
#ifdef VERBOSE_PAGE_TABLE_INOUT
	myprintk("pgdmfn=%5x added,count=%d\n", pgd->mfn, pgd_count);
#endif
	TRACE_2D(TRC_MIN_ADD_PGD, pgd->pt->mfn, 0 /* TODO remove this.. was pgd id */ );
#endif
	return pgd;
}


void del_pgd_common(struct page_dir *pgd)
{
	struct page_table *pt;
#ifdef DEBUG_ASSERT
//MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_none );
//MYASSERT_PAGE_IS_NOT_VALIDATED( mfn_to_page(mfn));
	if (!pgd)
		mypanic("del_pgd_common(): null pgd?");
#endif
#ifdef ENABLE_REGIONING2
	if (pgd->current_region) {
		regioning_stop(CLOCK_EVENT_DYING_PGD, pgd);
	}
	MYASSERT(pgd->current_region == NULL);
	MYASSERT(pgd->regioning_tick == 0);
#endif
	struct vcpu *v;
	struct domain *d;

#ifdef DEBUG_ASSERT
	rcu_read_lock(&domlist_read_lock);
	for_each_domain_vcpu(d,v) {
		if (v->current_pgd == pgd) {
			atomic_dec(&v->current_pgd->refcnt);
			v->current_pgd = NULL;
			myprintk("WARN! d%dv%d's current_pgd is resetted to NULL!!\n", d->domain_id, v->vcpu_id);
			mypanic("shouldn't happen!!");
		}
	}
	rcu_read_unlock(&domlist_read_lock);
#endif
	MYASSERT (!atomic_read(&pgd->refcnt));

#ifdef VERBOSE_PAGE_TABLE_INOUT
	myprintk("pgdmfn=%5x deled. count=%d\n", pgd->pt->mfn, pgd_count);
	TRACE_2D(TRC_MIN_DEL_PGD, pgd->pt->mfn, pgd_count);
#endif
#ifdef ENABLE_PTMAN
	unsigned long mfn = pgd->pt->mfn;
	del_pt(pgd, -1, mfn);
	pgd->pt = NULL;
#ifdef ENABLE_KERNEL_SHADOW
	//TODO kernel pgd should be deleted at the last
	if (test_and_clear_bit(PGD_KERNEL, &pgd->flag)) {
		myprintk("unset pgd_kernel..\n");
		if (pgd_count)	// TODO: lock?
			myprintk("WARN count=%d left..pgd_kernel should be deleted at last\n", pgd_count);
		myfree_xenheap_page(mfn_to_virt(mfn), 9);
	}
#endif
#else
	pgd->pt->user_l4 = 0;
	pgd->pt->mfn = NULL;
	myxfree(pgd->pt, 3);
	pgd->pt = NULL;
#endif
/*	if (pgd->mfn_user) {
		myprintk("TODO: del mfn_user\n");
	}*/

#ifdef ENABLE_RANGE
	del_all_ranges(pgd);	// this will free ranged guest region.. not del_pt() above.. (call del_pt() first for this)
#endif
}
#ifndef ENABLE_PTMAN
struct page_dir *find_pgd_simple(unsigned long pfn)
{
	MYASSERT(spin_is_locked(&pgd_list_lock));
	// simple search instead of find_pgd()
	struct page_dir *i;
	list_for_each_entry(i, &pgd_list, list) {
		if (i->pt->mfn == pfn) {
			return i;
		}
	}
	return NULL;
}
#endif


void del_pgd_user(unsigned long mfn, struct page_table *pt)
{
#ifdef ENABLE_PTMAN
	// TODO: compare it to add_pgd().. maybe need lock, too
	ptman_lock(mfn);
	ptman_del(mfn);
	ptman_unlock(mfn);

//	myprintk("del_pgd_user called\n");
//	del_table_common_user(pt, mfn);
//	myxfree(pt, 3);	// TODO: this seems like doesn't free all user l4...
	// TODO: find pgd->mfn_user that matches to mfn, and delete it...
#endif
}

void del_pgd(unsigned long mfn)
{
	struct page_dir *pgd = NULL;
	struct page_table *pt;
	// first del from ptman, then from list
	myspin_lock(&pgd_list_lock, 66);
#ifdef ENABLE_PTMAN
	ptman_lock(mfn);
	pgd = find_pgd(mfn, &pt);
	ptman_unlock(mfn);
#else
	pgd = find_pgd_simple(mfn);
#endif
	if (!pgd) {
		if (pt) {	// user_l4.. this part is del_pgd_user()
			spin_unlock(&pgd_list_lock);
			del_pgd_user(mfn, pt);
			return;
		}
#ifdef VERBOSE_INFO
		myprintk("INFO del_pgd failed..(initial or finishing?)\n");
#endif
		spin_unlock(&pgd_list_lock);
		return;
	}
	list_del(&pgd->list);
	pgd_count--;
	if (test_and_set_bit(PGD_DYING, &pgd->flag))	// I think I don't need lock
		mypanic("already dying?\n");
	spin_unlock(&pgd_list_lock);

	if (atomic_read(&pgd->refcnt)) {
		// shouldn't happen except finishing
		myprintk("del_pgd() non-zero refcnt\n");
		if (mini_activated)
			myprintk("WARN! Waiting pgd->refcnt with mini_activated?\n");
		while(atomic_read(&pgd->refcnt)) {
			cpu_relax();
		}
	}
#ifdef ENABLE_PTMAN
	lock_pt(mfn, CONFIG_PAGING_LEVELS, 4);
#endif
	del_pgd_common(pgd);
#ifdef ENABLE_PTMAN
	unlock_pt(1);
#endif

	myxfree(pgd, 4);
#ifdef VERBOSE_PAGE_TABLE_INOUT_LOW
	myprintk("%x deleted\n", mfn);
#endif
}

void del_all_pgd(void)
{
	struct page_dir *pgd;
	struct vcpu *v;
	struct domain *d;

	myprintk("reset-pgd forciblyl..   ");
	rcu_read_lock(&domlist_read_lock);
	for_each_domain_vcpu(d,v) {
		if (v->current_pgd) {
			pgd = v->current_pgd;
			v->current_pgd = NULL;
			printk("d%dv%d , ", d->domain_id, v->vcpu_id);
			atomic_dec(&pgd->refcnt);
		}
	}
	rcu_read_unlock(&domlist_read_lock);
	printk("\n");
	myprintk("starting del_all_pgd()\n");
again:
	myspin_lock(&pgd_list_lock, 22);
	list_for_each_entry(pgd, &pgd_list, list) {
		if (pgd) {
			spin_unlock(&pgd_list_lock);
			del_pgd(pgd->pt->mfn);	// try del_pgd()
			goto again;
		}
	}
	spin_unlock(&pgd_list_lock);
	myprintk("end of del_all_pgd()\n");
}

struct page_dir *find_or_add_pgd(unsigned long mfn)
{
	struct page_dir *pgd;
#ifdef ENABLE_PTMAN
	ptman_lock(mfn);
	pgd = find_pgd(mfn, NULL);
	ptman_unlock(mfn);
#else
	myspin_lock(&pgd_list_lock, 175);
	pgd = find_pgd_simple(mfn);
	spin_unlock(&pgd_list_lock);
#endif
#ifdef ENABLE_KERNEL_SHADOW
	l4_pgentry_t *l4t, *p;
	if (!current->domain->kernel_pgd) {
		myspin_lock(&current->domain->kernel_pgd_lock, 64);
		if (!current->domain->kernel_pgd) {
			int i;
			// alloc dummy kernel pgd
			p = (l4_pgentry_t *)myalloc_xenheap_page(9);
			MYASSERT(p);
			memset((void *)p, 0, PAGE_SIZE);
			// copy
			l4t = map_domain_page(mfn);
			for(i=L4_GUEST_START;i<L4_GUEST_END;i++) {
				if (!(l4e_get_flags(l4t[i]) & _PAGE_PRESENT))
					continue;
				p[i] = l4t[i];
			}
			unmap_domain_page(l4t);
			myprintk("constructing kernel_pgd.\n");
			current->domain->kernel_pgd = add_pgd(virt_to_mfn(p), 1UL << PGD_KERNEL);
			MYASSERT(current->domain->kernel_pgd);
			myprintk("kernel_pgd(%lx) set.. (dummy) pgd->pt->mfn:%lx\n", current->domain->kernel_pgd, current->domain->kernel_pgd->pt->mfn);
			print_pt(current->domain->kernel_pgd->pt);

		}
		spin_unlock(&current->domain->kernel_pgd_lock);
	}
#endif
	if (!pgd) {
		pgd = add_pgd(mfn, 0);	// TODO: make sure we handle racing...
	}
	MYASSERT(pgd);
	return pgd;
}


unsigned long change_cr3(unsigned long old_base_mfn)
{
	atomic_inc(&mini_count);
	atomic_inc(&mini_place[3]);
	static s_time_t prev_now = 0;
	struct page_dir *pgd = NULL, *old_pgd;
	int i;
	unsigned long shadow_cr3 = NULL;
	s_time_t now;

	TRACE_4D(TRC_MIN_NEW_GUEST_CR3, current->domain->domain_id, current->vcpu_id, old_base_mfn, current->arch.cr3 >> PAGE_SHIFT );
	// TODO: pgd may be deleted or disappear?? because of no locking??
	MYASSERT((current->arch.cr3 >> PAGE_SHIFT) == current->arch.guest_table.pfn);	// always kernel space, not user space
	pgd = find_or_add_pgd(current->arch.cr3 >> PAGE_SHIFT);

#ifdef DEBUG_ASSERT
	if (current->current_pgd && current->current_pgd->pt->mfn != old_base_mfn) {
		print_pt(current->current_pgd->pt);
		myprintk("WARN!! cur_pgdmfn:%x != old_base_mfn:%x ??\n", current->current_pgd->pt->mfn, old_base_mfn);
	}
#endif
	// TODO: should be changed to old_kstack
	old_pgd = current->current_pgd;
	now = NOW();
#ifdef ENABLE_CLOCK
	if (old_pgd) {
		old_pgd->clock_residue += now - old_pgd->clock_prev_now;
		old_pgd->clock_prev_now = now;	// in fact, don't need this
		do_clock(CLOCK_EVENT_NEW_CR3, old_pgd, now);
	}
	pgd->clock_prev_now = now;	// update
#endif
//	if (old_pgd) {
//		old_pgd->last_run = now;
//	}

	atomic_inc(&pgd->refcnt);
	current->current_pgd = pgd;	// see shadow_cr3 below

	if (old_pgd) {
		atomic_dec(&old_pgd->refcnt);
/*
		if (old_pgd->dying && atomic_read(&old_pgd->user_count) == 0) {
			if ((cacheman[0].frames_count > cacheman[1].frames_count && pgd->cache_current == 0) || (cacheman[0].frames_count < cacheman[1].frames_count && pgd->cache_current == 1))  {
				del_pgd(old_pgd);
				pgd_migration_count++;
#ifdef VERBOSE_PGD_MIGRATION
				myprintk("after del, now:active:%dvs%d\n", cacheman[0].active_frames_count, cacheman[1].active_frames_count);
#endif
			} else {
				old_pgd->dying = 0;
			}
		}
*/
	}

#ifdef VERBOSE_UPDATE_CR3
	if (current->print_countdown > 0) {
		myprintk("NOW:%6lldms(d:%4lldms) ",now/1000000ULL, (now - prev_now)/1000000ULL );
		printk("%5lx --> %5lx ", old_base_mfn, current->arch.cr3>>PAGE_SHIFT);
/*		if (old_pgd)
			printk("%lx --> %lx ", old_pgd->pt->mfn, pgd->pt->mfn);
		else
			printk("000 --> %lx ",                   pgd->pt->mfn);
*/
		print_openbit_count(pgd);
		printk("\n");
		prev_now = now;
		current->print_countdown--;
	}
#endif
#ifdef ENABLE_PER_CACHE_PT
	shadow_cr3 = (virt_to_mfn(pgd->pt->shadow[cache_now]) << PAGE_SHIFT);
#if 0
	print_pt(pgd->pt);
	l3_pgentry_t *va = pgd->pt->shadow[cache_now];
	for(i=0;i<512;i++) {
		if (va[i].l3)
			myprintk("%d:%lx .. ", i, l3e_get_intpte(va[i]));
	}
#endif
#ifdef ENABLE_REGIONING2
	if (pgd->current_region && pgd->regioning_cpu == smp_processor_id()) {
		shadow_cr3 = (virt_to_mfn(pgd->pt->regioning_shadow) << PAGE_SHIFT);
	}
	regioning_resume(pgd, CLOCK_EVENT_NEW_CR3);
#endif
//	myprintk("shadow:0x%x, orig:0x%x\n", shadow_cr3, current->arch.cr3);
#endif
	atomic_dec(&mini_place[3]);
	atomic_dec(&mini_count);
	return shadow_cr3;
}
#endif
