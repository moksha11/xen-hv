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

#ifdef ENABLE_PTMAN
#define PTMAN_SHIFT		11
#define MAX_PTMAN_ENTRY		(1UL<<PTMAN_SHIFT)
#define HASH_FUNC(MFN)		((MFN)&(MAX_PTMAN_ENTRY-1))
spinlock_t ptman_locks[MAX_PTMAN_ENTRY];
struct list_head ptman[MAX_PTMAN_ENTRY];
struct page_table *ptman_find(unsigned long mfn);

void init_ptman(void)
{
	int i;
	for(i=0;i<MAX_PTMAN_ENTRY;i++) {	
		INIT_LIST_HEAD(&ptman[i]);
		spin_lock_init(&ptman_locks[i]);
	}
}
void ptman_lock(unsigned long mfn)
{
	int i = HASH_FUNC(mfn);
	myspin_lock(&ptman_locks[i] , 144);
}
void ptman_unlock(unsigned long mfn)
{
	int i = HASH_FUNC(mfn);
	spin_unlock(&ptman_locks[i]);
}
void ptman_add(unsigned long mfn, struct page_table *p)
{
	int i = HASH_FUNC(mfn);
#ifdef DEBUG_ASSERT
	if (!spin_is_locked(&ptman_locks[i]))
		mypanic("lock before ptman_add");
	if (ptman_find(mfn)) {
		myprintk("mfn:%x , p:%x already exists!\n", mfn, p);
		mypanic("already exists!");
	}
#endif
	list_add(&p->ptman_list,&ptman[i]);
}
void ptman_del(unsigned long mfn)
{
	struct page_table *p;
	int i = HASH_FUNC(mfn);
#ifdef DEBUG_ASSERT
	if (!spin_is_locked(&ptman_locks[i]))
		mypanic("lock before ptman_del");
#endif
	p = ptman_find(mfn);
	if (!p) {
		myprintk("mfn:%x , ptr:%x doesn't exists!\n", mfn, p);
		mypanic("doesn't exists!");
	}
	list_del_init(&p->ptman_list);
}

struct page_table *ptman_find(unsigned long mfn)
{
	struct page_table *p;
	int i = HASH_FUNC(mfn);
#ifdef DEBUG_ASSERT
	if (!spin_is_locked(&ptman_locks[i]))		mypanic("lock before ptman_find");
#endif
	list_for_each_entry(p, &ptman[i], ptman_list) {
		if (p->mfn == mfn) {
			return p;
		}
	}
	return NULL;
}

// TODO: probably we can merge below two functions
struct page_table *find_pt_mfn(unsigned long mfn)
{
	struct page_table *ret;
	ptman_lock(mfn);
	ret = ptman_find(mfn);
	ptman_unlock(mfn);
	return ret;
}

void lock_pgd(unsigned long mfn, struct page_dir *newpgd, int loc)
{
	struct page_table *pt;
	struct page_dir *pgd;

	atomic_inc(&mini_count);
	atomic_inc(&mini_place[7]);

	if (!mini_activated && !mini_disabling) {
		goto exit_lock_pgd;
	}
#ifdef DEBUG_WARN
	if (this_cpu(found_pt))
		myprintk("WARN found_pt exists??? pre_loc=%d, now_loc =%d\n", this_cpu(locked_pt_loc) , loc);
	if (mini_disabling) {
//		unlock_pt();
	}
#endif
	ptman_lock(mfn);
	pgd = find_pgd(mfn, NULL);
	ptman_unlock(mfn);
	if (pgd) {
		myprintk("TODO: delete this pgd...\n");
		mypanic("TODO");
	}
	this_cpu(found_pt) = NULL;
	pgd = newpgd;
	if (this_cpu(locked_pt)) {
		mypanic("WARN locked_pt non-zero? level2 or newpgd\n");
	} else {
//		myspin_lock(&pgd->temp_lock, 145);
//		this_cpu(locked_pt) = &pgd->temp_lock;
		myspin_lock(&temp_lock, 145);
		this_cpu(locked_pt) = &temp_lock;
	}
exit_lock_pgd:
	atomic_dec(&mini_place[7]);
	atomic_dec(&mini_count);
}

// TODO: replace temp_lock with finer locks (e.g. pgd->lock)
void lock_pt(unsigned long mfn, int level, int loc)
{
	struct page_table *pt;
	struct page_dir *pgd;

	atomic_inc(&mini_count);
	atomic_inc(&mini_place[8]);
	if (!mini_activated && !mini_disabling) {
		goto exit_lock_pt;
	}
#ifdef DEBUG_WARN
	if (this_cpu(found_pt))
		myprintk("WARN found_pt exists??? pre_loc=%d, now_loc =%d\n", this_cpu(locked_pt_loc) , loc);
	if (mini_disabling) {
//		unlock_pt();
	}
#endif
	pt = find_pt_mfn(mfn);
	this_cpu(found_pt) = pt;
	if (!pt) {
//		myprintk("not-managed pt? mfn:%x lvl:%d initial phase?\n", mfn, level);	// TODO
	} else {
		if (this_cpu(locked_pt)) {
			mypanic("WARN locked_pt non-zero?\n");
		} else {
			myspin_lock(&pt->temp_lock, 115);
			this_cpu(locked_pt) = &pt->temp_lock;
			this_cpu(locked_pt_loc) = loc;
		}
	}
exit_lock_pt:
	atomic_dec(&mini_place[8]);
	atomic_dec(&mini_count);
}

void unlock_pt(int forcibly)
{
	if (!forcibly && !this_cpu(found_pt))
		return;
   	if (this_cpu(locked_pt)) {
		spin_unlock(this_cpu(locked_pt));
		this_cpu(locked_pt) = 0;
		this_cpu(found_pt) = 0;
		this_cpu(locked_pt_loc) = 0;
	} else {
		myprintk("locked_pt = null?? initial?\n");
	}
}

struct page_dir *get_pgd(struct page_table *pt)
{
	struct page_dir *pgd;
	MYASSERT(!pt->user_l4);	// don't call get_pgd if it's user_l4
	if (pt->level == 1) {
		pgd = pt->up_pt->up_pt->up_pt->aux;
	} else if (pt->level == 2) {
		pgd = pt->up_pt->up_pt->aux;
	} else if (pt->level == 3) {
		pgd = pt->up_pt->aux;
	} else if (pt->level == 4) {
		pgd = pt->aux;
	}
	MYASSERT(pgd > USERLAND_END);
	return pgd;
}

unsigned long get_va(struct page_table *pt, unsigned int ptindex)
{
	unsigned long va = 0;
	MYASSERT(ptindex < L1_PAGETABLE_ENTRIES);	// less than 512
	MYASSERT(!pt->user_l4);
	if (pt->level == 1) {
		va |= (ptindex << 12);
		va |= (pt->up_index << 21);
		pt = pt->up_pt;
		va |= (pt->up_index << 30);
		pt = pt->up_pt;
		va |= (pt->up_index << 39);
		pt = pt->up_pt;
	} else if (pt->level == 2) {
		va |= (ptindex << 21);
		va |= (pt->up_index << 30);
		pt = pt->up_pt;
		va |= (pt->up_index << 39);
		pt = pt->up_pt;
	} else if (pt->level == 3) {
		va |= (ptindex << 30);
		va |= (pt->up_index << 39);
		pt = pt->up_pt;
	} else if (pt->level == 4) {
		va |= (ptindex << 39);
	}
	MYASSERT(pt->up_pt == NULL);	// reached top level
#if 1
	MYASSERT(!(va>>48));
	if (va >= USERLAND_END) {
		va |= 0xffff000000000000;
	}
#endif
	return va;
}


struct page_table *find_pt(unsigned long up_index, unsigned long mfn)
{
	struct page_table *ret;
	ptman_lock(mfn);
	ret = ptman_find(mfn);
#ifdef DEBUG_ASSERT
	if (ret && ret->up_index != up_index) {
		myprintk("found but different up_index?? %lx != %lx\n", ret->up_index, up_index);
		print_pt(ret);
	}
	if (ret)
		MYASSERT(!ret->user_l4);
#endif
	ptman_unlock(mfn);
	return ret;
}

void add_table_common_user(struct page_table *pt, unsigned long mfn)
{
	mfn_check(mfn);
	INIT_LIST_HEAD(&pt->ptman_list);
	pt->mfn = mfn;
	pt->user_l4 = 1;
	pt->level = 999;	// poison..
	INIT_LIST_HEAD(&pt->list);
	INIT_LIST_HEAD(&pt->pt_list);
	spin_lock_init(&pt->temp_lock);
#ifdef ENABLE_PER_CACHE_PT	// light-weight cache switch
	// TODO?
#endif
	pt->up_index = 999;	// poison
	pt->pt_count = 999;	// poison
	pt->aux = 999;		// poison
	pt->up_pt = 999;	// poison
}

void add_table_common(struct page_table *pt, unsigned long mfn, int level, int up_index, struct page_table *up_pt)
{
	mfn_check(mfn);
	INIT_LIST_HEAD(&pt->ptman_list);
	pt->mfn = mfn;
	pt->user_l4 = 0;
	pt->level = level;
	INIT_LIST_HEAD(&pt->list);
	INIT_LIST_HEAD(&pt->pt_list);
	spin_lock_init(&pt->temp_lock);
#ifdef ENABLE_PER_CACHE_PT	// light-weight cache switch
	int i;
	void *p;
	// we could use myxmalloc() because eventually it uses alloc_xenheap_page(). However it has header which wastes one more page for each alloc
	for(i=0;i<MAX_CACHE;i++) {
#ifdef NO_PGD_ABOVE_4GB
		p = myalloc_xenheap_page_4gb(9);
#else
		p = myalloc_xenheap_page(9);
#endif
		MYASSERT(p);
		memset(p, 0, PAGE_SIZE);
		pt->shadow[i] = p;
MYASSERT((unsigned long)pt->shadow[i] == (unsigned long)p);
	}
#ifdef ENABLE_REGIONING2
#ifdef NO_PGD_ABOVE_4GB
		p = myalloc_xenheap_page_4gb(9);
#else
		p = myalloc_xenheap_page(9);
#endif
		MYASSERT(p);
		memset(p, 0, PAGE_SIZE);
		pt->regioning_shadow = p;
#endif
#endif
	pt->up_index = up_index;
	pt->pt_count = 0;

	if (up_index == -1) {	// root
		pt->aux = up_pt;
		pt->up_pt = NULL;
	} else {
		pt->aux = NULL;
		pt->up_pt = up_pt;
	}
#ifdef ENABLE_BITMAP_BASIC
	if (level == 1) {	// leaf
		struct l1e_struct *aux = myxmalloc(struct l1e_struct, 8);
		int i;
		if (!aux)
			mypanic("xmalloc failed.");
		memset(aux, 0, sizeof(struct l1e_struct));
		MYASSERT(pt->aux == NULL);
		pt->aux = aux;
	}
#endif
}

void del_table_common(struct page_table *pt)
{
#ifdef ENABLE_PER_CACHE_PT	// light-weight cache switch
	int i,j;
	unsigned long *p;
	for(i=0;i<MAX_CACHE;i++) {
		p = pt->shadow[i];	//mfn_to_virt(pt->shadow[i]);
#ifdef DEBUG_CHECK_CLEAN_PT
		for(j=0;j<((pt->level==2)?INDEX_USERLAND:1024);j++) {
			if (p[j])
				mypanic("not-cleaned per-cache-shadow?\n");
		}
#endif
		myfree_xenheap_page(p, 9);
		pt->shadow[i] = 0;
	}
#ifdef ENABLE_REGIONING2
		p = pt->regioning_shadow;
		myfree_xenheap_page(p, 9);
		pt->regioning_shadow = 0;
#endif
#endif
#ifdef ENABLE_BITMAP_BASIC
	if (pt->level == 1) {
		MYASSERT(pt->aux);
		myxfree(pt->aux, 8);
		pt->aux = NULL;
	}
#endif
	MYASSERT(pt->pt_count == 0);
	MYASSERT(list_empty(&pt->pt_list));
}


#define L4T_END 256
#define L3T_END	512
#define L2T_END	512

void _del_pt(struct page_table *pt)
{
	struct page_table *oldpt;
	struct list_head *i, *temp;
	// recursive calls
	list_for_each_safe(i, temp, &pt->pt_list) {
		oldpt = list_entry(i, struct page_table, list);
#ifdef ENABLE_PER_CACHE_PT
		del_shadow_nonleaf(oldpt->up_pt, oldpt->up_index);
#endif
		del_pt(oldpt->up_pt, oldpt->up_index, oldpt->mfn);
	}
	// TODO: del_shadow for kernel&xen space??
#ifdef DEBUG_ASSERT
	if (pt->pt_count)
		mypanic("del_pt(): pt->pt_count?? ");
#endif
}

void del_pt(struct page_table *up_pt, unsigned long up_index, unsigned long mfn)
{
	struct page_table *pt;

	mfn_check(mfn);
#if 0 // def DEBUG_ASSERT
	if (up_index == -1) {
	} else if (up_pt->level == 2) {
		MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_l1_page_table );
	} else if (up_pt->level == 3) {
		MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_l2_page_table );
	} else if (up_pt->level == 4) {
		MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_l3_page_table );
	} else
		mypanic("level out of range del_pt");
	MYASSERT_PAGE_IS_VALIDATED( mfn_to_page(mfn));
#ifdef DEBUG_ASSERT
	//MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_none );
	//MYASSERT_PAGE_IS_NOT_VALIDATED( mfn_to_page(mfn));
#endif
#endif

	// first del from ptman, then from list
	pt = find_pt(up_index, mfn);
	if (!pt) {
		myprintk("del_pt:%x[%d]%x NOT FOUND!\n", up_pt->mfn, up_index, mfn);
		mypanic("del_pt");
	}

	if (pt->level == 1) {
	} else if (pt->level == 2) {
		_del_pt(pt);
	} else if (pt->level == 3) {
		_del_pt(pt);
	} else if (pt->level == 4) {
		_del_pt(pt);
	} else
		mypanic("pt->level out of range del_pt");

	ptman_lock(mfn);
	ptman_del(mfn);
	ptman_unlock(mfn);

	if (pt->level != CONFIG_PAGING_LEVELS) {
		// TODO: need lock pt->lock ?
		list_del_init(&pt->list);
		up_pt->pt_count--;
	}

#ifdef VERBOSE_PAGE_TABLE_INOUT
	if (up_index == -1)
		myprintk("l%d (pgd:%5x)=%5x deled.\n", CONFIG_PAGING_LEVELS, up_pt, mfn);
	else
		myprintk("l%d %5x[%3x]=%5x deled.\n", pt->level, up_pt->mfn, up_index, mfn);
#endif
	TRACE_3D(TRC_MIN_DEL_PT, up_pt->mfn, up_index, mfn);
#ifdef ENABLE_MARK_VREGION
	if (pt->level == 1)	// leaf
		unmark_pt(pt);
#endif
#if 0 //def ENABLE_BITMAP_VRT
#ifdef DEBUG_WARN
	if (pt->level == 1) {
		int c;
		int pos;
		myspin_lock_pt(pt, 109);
		for(c=0;c<MAX_CACHE;c++) {
			for ( pos = find_first_bit(pt->bitmap_open[c], 1024);
				pos < 1024;
				pos = find_next_bit(pt->bitmap_open[c], 1024, pos+1) )
			{
				myprintk("WARN bitmap still open? l1t=%x[%d]\n", pt->mfn, pos);
			}
		}
		spin_unlock_pt(pt, 109);
	}
#endif
#endif
	del_table_common(pt);
	myxfree(pt, 3);
}

struct page_table *add_pt_user(unsigned long mfn)
{
	struct page_table *pt;

	pt = myxmalloc(struct page_table, 3);	// TODO: free this..
	if (!pt)
		mypanic("xmalloc failed.");
	add_table_common_user(pt, mfn);

	ptman_lock(mfn);
#ifdef DEBUG_ASSERT
	struct page_table *temp_pt;
	temp_pt = ptman_find(mfn);
	if (temp_pt) {
		myprintk("BUG! %x already exists!\n", mfn);
		print_pt(temp_pt);
		mypanic("add_pt_user");
	}
#endif
	ptman_add(mfn, pt);
	ptman_unlock(mfn);
/*
#ifdef VERBOSE_PAGE_TABLE_INOUT
	if (up_index == -1)
		myprintk("l%d (pgd:%5x)=%5x added.\n", CONFIG_PAGING_LEVELS, up_pt, mfn);
	else
	if (pt->level != 1)
		myprintk("l%d %5x[%3x]=%5x added.\n", pt->level, up_pt->mfn, up_index, mfn);
#endif
	TRACE_3D(TRC_MIN_ADD_PT, up_pt->mfn, up_index, mfn);
*/
}

struct page_table *add_pt(struct page_table *up_pt, unsigned long up_index, unsigned long mfn)
{
	int i;
	struct page_table *pt;
	l4_pgentry_t *l4t;
	l3_pgentry_t *l3t;
	l2_pgentry_t *l2t;

	mfn_check(mfn);
#ifdef DEBUG_ASSERT
	if (up_index == -1) {
	} else if (up_pt->level == 2) {
		MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_l1_page_table );
	} else if (up_pt->level == 3) {
		MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_l2_page_table );
	} else if (up_pt->level == 4) {
		MYASSERT_PAGE_IS_TYPE( mfn_to_page(mfn), PGT_l3_page_table );
	} else
		mypanic("level out of range");

	if (!is_xen_heap_mfn(mfn))	// exclude kernel_pgd
		MYASSERT_PAGE_IS_VALIDATED( mfn_to_page(mfn));
#endif
	pt = myxmalloc(struct page_table, 3);
	if (!pt)
		mypanic("xmalloc failed.");

	if (up_index == -1)
		add_table_common(pt, mfn, CONFIG_PAGING_LEVELS, up_index, up_pt);
	else
		add_table_common(pt, mfn, up_pt->level-1, up_index, up_pt);

	if (pt->level == 1) {
	} else if (pt->level == 2) {
		// recursive calls
		l2t = map_domain_page(mfn);
		for(i=0;i<L2T_END;i++) {
			if (!(l2e_get_flags(l2t[i]) & _PAGE_PRESENT))
				continue;
			struct page_table *newpt = add_pt(pt, i, l2e_get_pfn(l2t[i]));
#ifdef ENABLE_PER_CACHE_PT
			add_shadow_nonleaf(pt, i, newpt, l2e_get_flags(l2t[i]));
#endif
		}
		unmap_domain_page(l2t);
	} else if (pt->level == 3) {
		// recursive calls
		l3t = map_domain_page(mfn);
		for(i=0;i<L3T_END;i++) {
			if (!(l3e_get_flags(l3t[i]) & _PAGE_PRESENT))
				continue;
			struct page_table *newpt = add_pt(pt, i, l3e_get_pfn(l3t[i]));
#ifdef ENABLE_PER_CACHE_PT
			add_shadow_nonleaf(pt, i, newpt, l3e_get_flags(l3t[i]));
#endif
		}
		unmap_domain_page(l3t);
	} else if (pt->level == 4) {
	struct page_dir *pgd = pt->aux;
	if (test_bit(PGD_KERNEL, &pgd->flag)) {
#ifdef ENABLE_KERNEL_SHADOW
		myprintk("constructing pgd_kernel\n");
		int count = 0;
		// recursive calls
		l4t = map_domain_page(mfn);
		for(i=L4_GUEST_START;i<L4_GUEST_END;i++) {	// guest-defined area. see config.h
			if (!(l4e_get_flags(l4t[i]) & _PAGE_PRESENT))
				continue;
			struct page_table *newpt = add_pt(pt, i, l4e_get_pfn(l4t[i]));
			count++;
#ifdef ENABLE_PER_CACHE_PT
			add_shadow_nonleaf(pt, i, newpt, l4e_get_flags(l4t[i]));
#endif
		}
		myprintk("Done with kernel_pgd, %d L4 entries\n", count);
#else
		mypanic("Should enable KERNEL_SHADOW!\n");
#endif
	} else {
		// recursive calls
		l4t = map_domain_page(mfn);
		for(i=0;i<L4T_END;i++) {
			if (!(l4e_get_flags(l4t[i]) & _PAGE_PRESENT))
				continue;
			struct page_table *newpt = add_pt(pt, i, l4e_get_pfn(l4t[i]));
#ifdef ENABLE_PER_CACHE_PT
			add_shadow_nonleaf(pt, i, newpt, l4e_get_flags(l4t[i]));
#endif
		}
#ifdef ENABLE_PER_CACHE_PT
#ifdef ENABLE_KERNEL_SHADOW
#ifdef DEBUG_ASSERT
		l4_pgentry_t *dummy;
		dummy = mfn_to_virt(current->domain->kernel_pgd->pt->mfn);
#endif
		struct page_table *pt2;
		pt2 = current->domain->kernel_pgd->pt;
#endif
#endif
		// copy kernel & xen space
		for(;i<L4_PAGETABLE_ENTRIES;i++) {
			if (l4e_get_flags(l4t[i]) & _PAGE_PRESENT) {
#ifdef ENABLE_PER_CACHE_PT
#ifdef ENABLE_KERNEL_SHADOW
				if (L4_GUEST_KERNEL(i)) {
					MYASSERT(l4t[i].l4 == dummy[i].l4);
					add_shadow2(pt, i, pt2);
				} else {	// TODO i==258 guest linear map?
					add_shadow(pt, i, l4e_get_intpte(l4t[i]) , 0, 1);
				}
#else
					add_shadow(pt, i, l4e_get_intpte(l4t[i]) , 0, 1);
#endif
#endif
			}
		}
		unmap_domain_page(l4t);
	}
	} else
		mypanic("pt->level out of range add_pt");

#ifdef DEBUG_ASSERT
	struct page_table *temp_pt = find_pt(up_index, mfn);
	if (temp_pt) {
		myprintk("BUG! %x[%x],%x already exists!\n", up_pt->mfn, up_index, mfn);
		print_pt(temp_pt);
		mypanic("add_pt");
	}
#endif
	// first add to list, then to ptman
	if (pt->level != CONFIG_PAGING_LEVELS) {
		// TODO: need pt->lock?
		list_add(&pt->list, &up_pt->pt_list);
		up_pt->pt_count++;
	}
	ptman_lock(mfn);
	ptman_add(mfn, pt);
	ptman_unlock(mfn);
#ifdef VERBOSE_PAGE_TABLE_INOUT
	if (up_index == -1)
		myprintk("l%d (pgd:%5x)=%5x added.\n", CONFIG_PAGING_LEVELS, up_pt, mfn);
	else
	if (pt->level != 1)
		myprintk("l%d %5x[%3x]=%5x added.\n", pt->level, up_pt->mfn, up_index, mfn);
#endif
	TRACE_3D(TRC_MIN_ADD_PT, up_pt->mfn, up_index, mfn);

#ifdef ENABLE_MARK_VREGION
	if (pt->level == 1)	// leaf
		mark_pt(pt);
#endif
	return pt;
}

// grep ptman_lock before call
struct page_dir *find_pgd(unsigned long mfn, struct page_table **pt_out)
{
	struct page_dir *pgd = NULL;
	struct page_table *pt;
	mfn_check(mfn);
	pt = ptman_find(mfn);
	if (pt && !pt->user_l4) {
		pgd = get_pgd(pt);
	}
	if (pt_out)
		*pt_out = pt;
	else
		if (pt)
			MYASSERT(!pt->user_l4);	// null pt_out is to assert non-user_l4
	return pgd;
}

#endif
