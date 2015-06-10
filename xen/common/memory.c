/******************************************************************************
 * memory.c
 *
 * Code to handle memory-related requests.
 *
 * Copyright (c) 2003-2004, B Dragovic
 * Copyright (c) 2003-2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/paging.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/errno.h>
#include <xen/tmem.h>
#include <xen/tmem_xen.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#ifdef CONFIG_X86
# include <asm/p2m.h>
#endif
#include <xen/numa.h>
#include <public/memory.h>
#include <xsm/xsm.h>
#include <xen/trace.h>

#define HETEROMEM
#include <asm/spinlock.h>
static spinlock_t heteropg_lock;
static int hotpg_hypercall_active;
static unsigned int pages_added;
static unsigned int guest_startidx;
static unsigned int guest_stopidx;
atomic_t disabl_shrink_hotpg;

#define MAX_HOT_MFNS 128000
#define MAX_HOT_MFNS_GUEST 128000
#define _USE_SHAREDMEM


PAGE_LIST_HEAD(in_hotskip_list);
static unsigned int *hotmfns;

struct memop_args {
    /* INPUT */
    struct domain *domain;     /* Domain to be affected. */
    XEN_GUEST_HANDLE(xen_pfn_t) extent_list; /* List of extent base addrs. */
    unsigned int nr_extents;   /* Number of extents to allocate or free. */
    unsigned int extent_order; /* Size of each extent. */
    unsigned int memflags;     /* Allocation flags. */

    /* INPUT/OUTPUT */
    unsigned int nr_done;    /* Number of extents processed so far. */
    int          preempted;  /* Was the hypercall preempted? */
};

static void increase_reservation(struct memop_args *a)
{
    struct page_info *page;
    unsigned long i;
    xen_pfn_t mfn;
    struct domain *d = a->domain;

    if ( !guest_handle_is_null(a->extent_list) &&
         !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( !multipage_allocation_permitted(current->domain, a->extent_order) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        page = alloc_domheap_pages(d, a->extent_order, a->memflags);
        if ( unlikely(page == NULL) ) 
        {
            gdprintk(XENLOG_INFO, "Could not allocate order=%d extent: "
                    "id=%d memflags=%x (%ld of %d)\n",
                     a->extent_order, d->domain_id, a->memflags,
                     i, a->nr_extents);
            goto out;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( !guest_handle_is_null(a->extent_list) )
        {
            mfn = page_to_mfn(page);
            if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                goto out;
        }
    }

 out:
    a->nr_done = i;
}

int hetero_chckskip_page(struct page_info *page, unsigned long curr){

	struct page_info *inpage;
	unsigned long mfn =0;

	page_list_for_each(inpage, &in_hotskip_list)	
		if(inpage){
			mfn = page_to_mfn(inpage);
			//printk("hetero_chckskip_page:inpage %lu, curr %lu \n",
			//		mfn, curr);
			if(inpage == page){
				return 1; 
			}
		}

	return -1;
}

int check_if_valid_domain_pg(unsigned int mfn) {

	struct domain *vm = page_get_owner(__mfn_to_page(mfn));
    if (vm) {
        int vm_id = vm->domain_id;
        if (vm_id > 0 && vm_id < MAX_HETERO_VM) { //&& (vm_id%2 !=0)) {
			return 0;
		}
	}
	return -1;
 }

int add_hotpage_tolist(struct page_info *page, unsigned int mfn) {

	unsigned int idx=0;
	size_t size=0;	

	//if(pages_added >= MAX_HOT_MFNS)
	//	return 0; 

	//printk("calling add_hotpage_tolist ...1\n");
	if(atomic_read(&disabl_shrink_hotpg))
        return 0;
	
	//failure if return is > 0
	if(check_if_valid_domain_pg(mfn))
		return 0;

#ifdef _USE_SHAREDMEM
	    hsm_add_mfn(mfn, pages_added);
		pages_added++;
		//printk("add_hotpage_tolist: hotmfns %u \n",pages_added);
		return 0;
#endif

	if(!hotmfns){
	  size = MAX_HOT_MFNS;	
	  hotmfns = xmalloc_array(unsigned int*, size*sizeof(unsigned int));
	  if(!hotmfns)	
		printk("add_hotpage_tolist: hotmfns allocation failed \n");
	}

 	if(hotmfns){
        idx = pages_added % MAX_HOT_MFNS;
		hotmfns[idx] = mfn;
		pages_added++;
    }
	return 0;
}


static void hetero_get_hotpage(struct memop_args *a, struct xen_hetero_memory_reservation *reservation)
{
    struct page_info *page, *inpage;
    unsigned int i=0, idx=0, j=0, itr=0;
    xen_pfn_t gpfn, mfn;

#ifdef _USE_SHAREDMEM
	if(atomic_read(&disabl_shrink_hotpg)) {
		//pages_added=0;
		//hsm_add_mfn(0,0);
		//hsm_reset_idx();
   		atomic_set(&disabl_shrink_hotpg, 0);
	}
	else{
		atomic_set(&disabl_shrink_hotpg, 1);	
		hsm_add_mfn(0,pages_added);
	}
	a->nr_done = 0;
	return;
#else
	atomic_set(&disabl_shrink_hotpg, 1);
#endif

	if(!hotmfns){
	  goto out;
	}

	i=0;
	a->nr_done = i;
	guest_startidx = 0;

	guest_stopidx = (guest_startidx + MAX_HOT_MFNS_GUEST -1) % MAX_HOT_MFNS ;

	if(guest_stopidx > pages_added)
		guest_stopidx = pages_added;

	 //atomic_set(&disabl_shrink_hotpg, 1);
	 for(idx=guest_startidx; idx< guest_stopidx; idx++) {

		if ( !guest_handle_is_null(a->extent_list) ){

         	mfn = hotmfns[idx];
			hotmfns[idx]=0;

			if(!mfn) {
				//printk("hetero_get_hotpage: invalid mfn hotmfns[%u]:%u\n", 
			 	//					mfn, hotmfns[idx]);
				continue;
			 }
			 //gpfn = get_gpfn_from_mfn(mfn);
			 //printk("hetero_get_hotpage: hotmfns[%u]:%u, gpfn %u\n",     
             //		idx, hotmfns[idx], get_gpfn_from_mfn(hotmfns[idx]));
        	 if(unlikely(__copy_to_guest_offset(a->extent_list,i++,&mfn, 1))){
				//printk("__copy_to_guest_offset failed \n");
		 	 } 
			//hotmfns[idx]=0;
		}
    }
	printk("hetero_get_hotpage:start idx %u, end idx %u\n",
				guest_startidx, guest_stopidx);
	//guest_startidx = (guest_startidx + idx + 1)% MAX_HOT_MFNS;
	guest_startidx = (guest_stopidx + 1)% MAX_HOT_MFNS;

out:
	/*reset pages to 0*/
	pages_added = 0;

    /*set to 0 after the hypercall*/
    atomic_set(&disabl_shrink_hotpg, 0);

	a->nr_done = i;

	return 0;
}


/* */
static void hetero_hotpage_hints(struct memop_args *a, struct xen_hetero_memory_reservation *reservation)
{
    struct page_info *page;
    unsigned long i, j;
    xen_pfn_t gpfn, mfn;
    struct domain *d = a->domain;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

	//printk(KERN_DEBUG "hetero_hotpage_hints: %u \n", a->nr_extents);

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        /*if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }*/

        if ( unlikely(__copy_from_guest_offset(&gpfn, a->extent_list, i, 1)) ){
            goto out;
		}
		//printk("hetero_hotpage_hints: copying from guests %lu \n",
		//	(unsigned long)gpfn);

		/*page = mfn_to_page(pfn_to_mfn(gpfn));
		if(!page){
			printk("hetero_hotpage_hints: page is NULL\n");	
			continue;	
		}else {
			 printk("hetero_hotpage_hints: page is not NULL\n");
		}*/

       struct page_info *page;
#ifdef CONFIG_X86
       p2m_type_t p2mt;
#endif
       unsigned long mfn;

#ifdef CONFIG_X86
    mfn = mfn_x(gfn_to_mfn(p2m_get_hostp2m(d), gpfn, &p2mt)); 
    if ( unlikely(p2m_is_paging(p2mt)) )
    {
        return 1;
    }
#else
    mfn = gmfn_to_mfn(d, gpfn);
#endif

    //printk("hetero_hotpage_hints: after extracting mfn "  
	  //    "gpfn %lu, mfn %lu \n",gpfn, mfn);

    if ( unlikely(!mfn_valid(mfn)) )
    {
        printk(XENLOG_INFO, "Domain %u page number %lx invalid\n",
                d->domain_id, gpfn);
        return 0;
    }
#if 1
  	  page = mfn_to_page(mfn);
	  if(page){
	    page_list_add(page, &in_hotskip_list);
		j++;
	  }
	  else { 
        printk("hetero_hotpage_hints: mfn_to_page is NULL \n");
      }
#endif

	}
out:
	printk("hetero_hotpage_hints:page added to lists %u\n",j);
    a->nr_done = i;
}




#if 0
/* HetroMem HETEROMEMFIX: Hardcoding node for now. Need to fix the bug of getting the right way to 
* interpret the node argument from guest. currently the memglag argument is NULL*/
static void hetero_populate_physmap(struct memop_args *a, struct xen_hetero_memory_reservation *reservation)
{
    struct page_info *page;
    unsigned long i, j;
    xen_pfn_t gpfn, mfn;
    struct domain *d = a->domain;
	unsigned int start_pages = 0;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( !multipage_allocation_permitted(current->domain, a->extent_order) )
        return;

	/*if(d->domain_id == 1){
		printk(KERN_DEBUG "*************nr_extents requested map:%d*****************\n",a->nr_extents);
	}*/

	if(d && d->domain_id > 0)
		start_pages = d->tot_pages;


    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, a->extent_list, i, 1)) )
            goto out;

        if ( a->memflags & MEMF_populate_on_demand )
        {
			printk("hetero_populate_physmap: guest_physmap_mark_populate_on_demand\n");
            if ( guest_physmap_mark_populate_on_demand(d, gpfn,
                                                       a->extent_order) < 0 )
                goto out;
        }
        else
        {
			//if(d && d->domain_id == 1){
			//	printk(KERN_DEBUG "populate_physmap: memflags %u, gpfn %u\n",
			//			reservation->mem_flags, gpfn);
			//}
//#ifdef ENABLE_MULTI_NODE
			if(d && d->domain_id > 0){
				page = alloc_domheap_pages(d, a->extent_order, (a->memflags | MEMF_node(SLOW_MEMORY_NODE) | MEMF_exact_node));
				printk("hetero_populate_physmap: allocating from memory node %u \n",SLOW_MEMORY_NODE);
			}
//#else
//			printk("hetero_populate_physmap: alloc_domheap_pages \n");
            page = alloc_domheap_pages(d, a->extent_order, a->memflags);
//#endif
            if ( unlikely(page == NULL) ) 
            {
                if ( !opt_tmem || (a->extent_order != 0) )
                    gdprintk(XENLOG_INFO, "Could not allocate order=%d extent:"
                             " id=%d memflags=%x (%ld of %d)\n",
                             a->extent_order, d->domain_id, a->memflags,
                             i, a->nr_extents);
                goto out;
            }
            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, gpfn, mfn, a->extent_order);
#ifdef HETERODEBUG
			if(d && d->domain_id >= 1){
				printk(KERN_DEBUG "populate_physmap: added page to guest gpfn:  %lu "
								  "mfn: %u, extent_order: %u\n ",
								  (unsigned int)gpfn, (unsigned int)mfn, a->extent_order);
			}
#endif

            if ( !paging_mode_translate(d) )
            {
                for ( j = 0; j < (1 << a->extent_order); j++ )
                    set_gpfn_from_mfn(mfn + j, gpfn + j);

                /* Inform the domain of the new page's machine address. */ 
                if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                    goto out;
#ifdef HETERODEBUG
				/*if(d && d->domain_id == 1){
					printk(KERN_DEBUG "copy page to extent list:  %lu "
								  "mfn: %u, extent_order: %u\n ",
								  (unsigned int)gpfn + j, (unsigned int)mfn + j, a->extent_order);
				}*/
#endif
            }
        }
    }
	printk("NUMA page alloc:%d %u %u\n",i, d->tot_pages, start_pages);

out:
    a->nr_done = i;
}
#else
static void hetero_populate_physmap(struct memop_args *a, struct xen_hetero_memory_reservation *reservation)
{
    struct page_info *page;
    unsigned long i, j;
    xen_pfn_t gpfn, mfn;
    struct domain *d = a->domain;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( !multipage_allocation_permitted(current->domain, a->extent_order) )
        return;

	/*printk("*************vishal map:%d*****************\n",a->nr_extents);*/
    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, a->extent_list, i, 1)) )
            goto out;

        if ( a->memflags & MEMF_populate_on_demand )
        {
            if ( guest_physmap_mark_populate_on_demand(d, gpfn,
                                                       a->extent_order) < 0 )
                goto out;
        }
        else
        {
//#ifdef ENABLE_MULTI_NODE
			//if(d && d->domain_id > 0){
			page = alloc_domheap_pages(d, a->extent_order, (a->memflags | MEMF_node(SLOW_MEMORY_NODE) | MEMF_exact_node ));
			//}
//#else
            //page = alloc_domheap_pages(d, a->extent_order, a->memflags);
//#endif
            if ( unlikely(page == NULL) ) 
            {
                if ( !opt_tmem || (a->extent_order != 0) )
                    gdprintk(XENLOG_INFO, "Could not allocate order=%d extent:"
                             " id=%d memflags=%x (%ld of %d)\n",
                             a->extent_order, d->domain_id, a->memflags,
                             i, a->nr_extents);
                goto out;
            }

            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, gpfn, mfn, a->extent_order);

            if ( !paging_mode_translate(d) )
            {
                for ( j = 0; j < (1 << a->extent_order); j++ )
                    set_gpfn_from_mfn(mfn + j, gpfn + j);

                /* Inform the domain of the new page's machine address. */ 
                if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                    goto out;
            }
        }
    }
	printk("NUMA page alloc:%d %u\n",i, d->tot_pages);

out:
    a->nr_done = i;
}
#endif

static void populate_physmap(struct memop_args *a)
{
    struct page_info *page;
    unsigned long i, j;
    xen_pfn_t gpfn, mfn;
    struct domain *d = a->domain;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( !multipage_allocation_permitted(current->domain, a->extent_order) )
        return;

	/*printk("*************vishal map:%d*****************\n",a->nr_extents);*/
    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, a->extent_list, i, 1)) )
            goto out;

        if ( a->memflags & MEMF_populate_on_demand )
        {
            if ( guest_physmap_mark_populate_on_demand(d, gpfn,
                                                       a->extent_order) < 0 )
                goto out;
        }
        else
        {
#ifdef ENABLE_MULTI_NODE
			//if(d && d->domain_id > 0){
			page = alloc_domheap_pages(d, a->extent_order, (a->memflags | MEMF_node(FAST_MEMORY_NODE) | MEMF_exact_node ));
			//}
#else
            page = alloc_domheap_pages(d, a->extent_order, a->memflags);
#endif
            if ( unlikely(page == NULL) ) 
            {
                if ( !opt_tmem || (a->extent_order != 0) )
                    gdprintk(XENLOG_INFO, "Could not allocate order=%d extent:"
                             " id=%d memflags=%x (%ld of %d)\n",
                             a->extent_order, d->domain_id, a->memflags,
                             i, a->nr_extents);
                goto out;
            }

            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, gpfn, mfn, a->extent_order);

            if ( !paging_mode_translate(d) )
            {
                for ( j = 0; j < (1 << a->extent_order); j++ )
                    set_gpfn_from_mfn(mfn + j, gpfn + j);

                /* Inform the domain of the new page's machine address. */ 
                if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                    goto out;
            }
        }
    }
	printk("NUMA page alloc:%d %u\n",i, d->tot_pages);

out:
    a->nr_done = i;
}

int guest_remove_page(struct domain *d, unsigned long gmfn)
{
    struct page_info *page;
#ifdef CONFIG_X86
    p2m_type_t p2mt;
#endif
    unsigned long mfn;

#ifdef CONFIG_X86
    mfn = mfn_x(gfn_to_mfn(p2m_get_hostp2m(d), gmfn, &p2mt)); 
    if ( unlikely(p2m_is_paging(p2mt)) )
    {
        guest_physmap_remove_page(d, gmfn, mfn, 0);
        p2m_mem_paging_drop_page(p2m_get_hostp2m(d), gmfn);
        return 1;
    }
#else
    mfn = gmfn_to_mfn(d, gmfn);
#endif
    if ( unlikely(!mfn_valid(mfn)) )
    {
        gdprintk(XENLOG_INFO, "Domain %u page number %lx invalid\n",
                d->domain_id, gmfn);
        return 0;
    }
            
    page = mfn_to_page(mfn);
#ifdef CONFIG_X86
    /* If gmfn is shared, just drop the guest reference (which may or may not
     * free the page) */
    if(p2m_is_shared(p2mt))
    {
        put_page_and_type(page);
        guest_physmap_remove_page(d, gmfn, mfn, 0);
        return 1;
    }

#endif /* CONFIG_X86 */
    if ( unlikely(!get_page(page, d)) )
    {
        gdprintk(XENLOG_INFO, "Bad page free for domain %u\n", d->domain_id);
        return 0;
    }

    if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
        put_page_and_type(page);
            
    if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
        put_page(page);

    guest_physmap_remove_page(d, gmfn, mfn, 0);

    put_page(page);

    return 1;
}

static void decrease_reservation(struct memop_args *a)
{
    unsigned long i, j;
    xen_pfn_t gmfn;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gmfn, a->extent_list, i, 1)) )
            goto out;

        if ( tb_init_done )
        {
            struct {
                u64 gfn;
                int d:16,order:16;
            } t;

            t.gfn = gmfn;
            t.d = a->domain->domain_id;
            t.order = a->extent_order;
        
            __trace_var(TRC_MEM_DECREASE_RESERVATION, 0, sizeof(t), &t);
        }

        /* See if populate-on-demand wants to handle this */
        if ( is_hvm_domain(a->domain)
             && p2m_pod_decrease_reservation(a->domain, gmfn, a->extent_order) )
            continue;

        for ( j = 0; j < (1 << a->extent_order); j++ )
            if ( !guest_remove_page(a->domain, gmfn + j) )
                goto out;
    }

 out:
    a->nr_done = i;
}

static long memory_exchange(XEN_GUEST_HANDLE(xen_memory_exchange_t) arg)
{
    struct xen_memory_exchange exch;
    PAGE_LIST_HEAD(in_chunk_list);
    PAGE_LIST_HEAD(out_chunk_list);
    unsigned long in_chunk_order, out_chunk_order;
    xen_pfn_t     gpfn, gmfn, mfn;
    unsigned long i, j, k;
    unsigned int  memflags = 0;
    long          rc = 0;
    struct domain *d;
    struct page_info *page;

    if ( copy_from_guest(&exch, arg, 1) )
        return -EFAULT;

    /* Various sanity checks. */
    if ( (exch.nr_exchanged > exch.in.nr_extents) ||
         /* Input and output domain identifiers match? */
         (exch.in.domid != exch.out.domid) ||
         /* Sizes of input and output lists do not overflow a long? */
         ((~0UL >> exch.in.extent_order) < exch.in.nr_extents) ||
         ((~0UL >> exch.out.extent_order) < exch.out.nr_extents) ||
         /* Sizes of input and output lists match? */
         ((exch.in.nr_extents << exch.in.extent_order) !=
          (exch.out.nr_extents << exch.out.extent_order)) )
    {
        rc = -EINVAL;
        goto fail_early;
    }

    /* Only privileged guests can allocate multi-page contiguous extents. */
    if ( !multipage_allocation_permitted(current->domain,
                                         exch.in.extent_order) ||
         !multipage_allocation_permitted(current->domain,
                                         exch.out.extent_order) )
    {
        rc = -EPERM;
        goto fail_early;
    }

    if ( exch.in.extent_order <= exch.out.extent_order )
    {
        in_chunk_order  = exch.out.extent_order - exch.in.extent_order;
        out_chunk_order = 0;
    }
    else
    {
        in_chunk_order  = 0;
        out_chunk_order = exch.in.extent_order - exch.out.extent_order;
    }

    if ( likely(exch.in.domid == DOMID_SELF) )
    {
        d = rcu_lock_current_domain();
    }
    else
    {
        if ( (d = rcu_lock_domain_by_id(exch.in.domid)) == NULL )
            goto fail_early;

        if ( !IS_PRIV_FOR(current->domain, d) )
        {
            rcu_unlock_domain(d);
            rc = -EPERM;
            goto fail_early;
        }
    }

    memflags |= MEMF_bits(domain_clamp_alloc_bitsize(
        d,
        XENMEMF_get_address_bits(exch.out.mem_flags) ? :
        (BITS_PER_LONG+PAGE_SHIFT)));
    memflags |= MEMF_node(XENMEMF_get_node(exch.out.mem_flags));

    for ( i = (exch.nr_exchanged >> in_chunk_order);
          i < (exch.in.nr_extents >> in_chunk_order);
          i++ )
    {
        if ( hypercall_preempt_check() )
        {
            exch.nr_exchanged = i << in_chunk_order;
            rcu_unlock_domain(d);
            if ( copy_field_to_guest(arg, &exch, nr_exchanged) )
                return -EFAULT;
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh", XENMEM_exchange, arg);
        }

        /* Steal a chunk's worth of input pages from the domain. */
        for ( j = 0; j < (1UL << in_chunk_order); j++ )
        {
            if ( unlikely(__copy_from_guest_offset(
                &gmfn, exch.in.extent_start, (i<<in_chunk_order)+j, 1)) )
            {
                rc = -EFAULT;
                goto fail;
            }

            for ( k = 0; k < (1UL << exch.in.extent_order); k++ )
            {
#ifdef CONFIG_X86
                p2m_type_t p2mt;

                /* Shared pages cannot be exchanged */
                mfn = mfn_x(gfn_to_mfn_unshare(p2m_get_hostp2m(d), gmfn + k, &p2mt, 0));
                if ( p2m_is_shared(p2mt) )
                {
                    rc = -ENOMEM;
                    goto fail; 
                }
#else /* !CONFIG_X86 */
                mfn = gmfn_to_mfn(d, gmfn + k);
#endif
                if ( unlikely(!mfn_valid(mfn)) )
                {
                    rc = -EINVAL;
                    goto fail;
                }

                page = mfn_to_page(mfn);

                if ( unlikely(steal_page(d, page, MEMF_no_refcount)) )
                {
                    rc = -EINVAL;
                    goto fail;
                }

                page_list_add(page, &in_chunk_list);
            }
        }

        /* Allocate a chunk's worth of anonymous output pages. */
        for ( j = 0; j < (1UL << out_chunk_order); j++ )
        {
            page = alloc_domheap_pages(NULL, exch.out.extent_order, memflags);
            if ( unlikely(page == NULL) )
            {
                rc = -ENOMEM;
                goto fail;
            }

            page_list_add(page, &out_chunk_list);
        }

        /*
         * Success! Beyond this point we cannot fail for this chunk.
         */

        /* Destroy final reference to each input page. */
        while ( (page = page_list_remove_head(&in_chunk_list)) )
        {
            unsigned long gfn;

            if ( !test_and_clear_bit(_PGC_allocated, &page->count_info) )
                BUG();
            mfn = page_to_mfn(page);
            gfn = mfn_to_gmfn(d, mfn);
            /* Pages were unshared above */
            BUG_ON(SHARED_M2P(gfn));
            guest_physmap_remove_page(d, gfn, mfn, 0);
            put_page(page);
        }

        /* Assign each output page to the domain. */
        j = 0;
        while ( (page = page_list_remove_head(&out_chunk_list)) )
        {
            if ( assign_pages(d, page, exch.out.extent_order,
                              MEMF_no_refcount) )
            {
                unsigned long dec_count;
                bool_t drop_dom_ref;

                /*
                 * Pages in in_chunk_list is stolen without
                 * decreasing the tot_pages. If the domain is dying when
                 * assign pages, we need decrease the count. For those pages
                 * that has been assigned, it should be covered by
                 * domain_relinquish_resources().
                 */
                dec_count = (((1UL << exch.in.extent_order) *
                              (1UL << in_chunk_order)) -
                             (j * (1UL << exch.out.extent_order)));

                spin_lock(&d->page_alloc_lock);
                d->tot_pages -= dec_count;
                drop_dom_ref = (dec_count && !d->tot_pages);
                spin_unlock(&d->page_alloc_lock);

                if ( drop_dom_ref )
                    put_domain(d);

                free_domheap_pages(page, exch.out.extent_order);
                goto dying;
            }

            /* Note that we ignore errors accessing the output extent list. */
            (void)__copy_from_guest_offset(
                &gpfn, exch.out.extent_start, (i<<out_chunk_order)+j, 1);

            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, gpfn, mfn, exch.out.extent_order);

            if ( !paging_mode_translate(d) )
            {
                for ( k = 0; k < (1UL << exch.out.extent_order); k++ )
                    set_gpfn_from_mfn(mfn + k, gpfn + k);
                (void)__copy_to_guest_offset(
                    exch.out.extent_start, (i<<out_chunk_order)+j, &mfn, 1);
            }
            j++;
        }
        BUG_ON( !(d->is_dying) && (j != (1UL << out_chunk_order)) );
    }

    exch.nr_exchanged = exch.in.nr_extents;
    if ( copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    rcu_unlock_domain(d);
    return rc;

    /*
     * Failed a chunk! Free any partial chunk work. Tell caller how many
     * chunks succeeded.
     */
 fail:
    /* Reassign any input pages we managed to steal. */
    while ( (page = page_list_remove_head(&in_chunk_list)) )
        if ( assign_pages(d, page, 0, MEMF_no_refcount) )
            BUG();
 dying:
    rcu_unlock_domain(d);
    /* Free any output pages we managed to allocate. */
    while ( (page = page_list_remove_head(&out_chunk_list)) )
        free_domheap_pages(page, exch.out.extent_order);

    exch.nr_exchanged = i << in_chunk_order;

 fail_early:
    if ( copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    return rc;
}

long do_memory_op(unsigned long cmd, XEN_GUEST_HANDLE(void) arg)
{
    struct domain *d;
    int rc, op;
    unsigned int address_bits;
    unsigned long start_extent;
    struct xen_memory_reservation reservation;
	/*HeteroMem Changes*/
    struct xen_hetero_memory_reservation hetero_reservation;

    struct memop_args args;
    domid_t domid;

    op = cmd & MEMOP_CMD_MASK;

    switch ( op )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
    case XENMEM_hetero_populate_physmap:
    case XENMEM_hetero_stop_hotpage_scan:

        start_extent = cmd >> MEMOP_EXTENT_SHIFT;

        if ( copy_from_guest(&reservation, arg, 1) )
            return start_extent;

		/* HeteroMem: If HeteroMem, copy the arg to heteromem reservation
		 * structure */
		//if (op == XENMEM_hetero_populate_physmap || op == XENMEM_hetero_stop_hotpage_scan) {
		if (op == XENMEM_hetero_stop_hotpage_scan) {
			//printk("do_mem_op: XENMEM_hetero_stop_hotpage_scan called step 2\n");
			if ( copy_from_guest(&hetero_reservation, arg, 1) )
			    return start_extent;
		}

        /* Is size too large for us to encode a continuation? */
        if ( reservation.nr_extents > (ULONG_MAX >> MEMOP_EXTENT_SHIFT) )
            return start_extent;

		
		if(op != XENMEM_hetero_stop_hotpage_scan) {

	        if ((unlikely(start_extent >= reservation.nr_extents)) )
    	        return start_extent;
		}

        args.extent_list  = reservation.extent_start;
        args.nr_extents   = reservation.nr_extents;
        args.extent_order = reservation.extent_order;
        args.nr_done      = start_extent;
        args.preempted    = 0;
        args.memflags     = 0;

#if 0
#ifdef HETEROMEM
         /*HETEROMEMDEBUG*/
         if ( op == XENMEM_populate_physmap
         	   && (reservation.mem_flags & XENMEMF_hetero_mem_request) )
                printk(KERN_DEBUG "******Request from guest heteromem \n");
		 else if((d->domain_id == 1) && (op == XENMEM_populate_physmap)){
	        printk(KERN_DEBUG "In populate_physmap \n");
		 }
#endif
#endif

		 //if (op == XENMEM_hetero_populate_physmap || op == XENMEM_hetero_stop_hotpage_scan)
			//printk("do_mem_op: XENMEM_hetero_stop_hotpage_scan called step 5\n");


        address_bits = XENMEMF_get_address_bits(reservation.mem_flags);
        if ( (address_bits != 0) &&
             (address_bits < (get_order_from_pages(max_page) + PAGE_SHIFT)) )
        {
            if ( address_bits <= PAGE_SHIFT )
                return start_extent;
            args.memflags = MEMF_bits(address_bits);
        }

		 //if (op == XENMEM_hetero_populate_physmap || op == XENMEM_hetero_stop_hotpage_scan)
			//printk("do_mem_op: XENMEM_hetero_stop_hotpage_scan called step 6\n");

        args.memflags |= MEMF_node(XENMEMF_get_node(reservation.mem_flags));
        if ( reservation.mem_flags & XENMEMF_exact_node_request )
            args.memflags |= MEMF_exact_node;

		 //if (op == XENMEM_hetero_populate_physmap || op == XENMEM_hetero_stop_hotpage_scan)
		//	printk("do_mem_op: XENMEM_hetero_stop_hotpage_scan called step 7\n");

        if ( op == XENMEM_populate_physmap
             && (reservation.mem_flags & XENMEMF_populate_on_demand) )
            args.memflags |= MEMF_populate_on_demand;

        if ( op == XENMEM_hetero_populate_physmap
             && (reservation.mem_flags & XENMEMF_populate_on_demand) )
            args.memflags |= MEMF_populate_on_demand;

		//if ( op == XENMEM_hetero_stop_hotpage_scan){
			//printk("XENMEM_hetero_stop_hotpage_scan called \n");	
		//}

        if ( likely(reservation.domid == DOMID_SELF) )
        {
            d = rcu_lock_current_domain();
        }
        else
        {
            if ( (d = rcu_lock_domain_by_id(reservation.domid)) == NULL )
                return start_extent;
            if ( !IS_PRIV_FOR(current->domain, d) )
            {
                rcu_unlock_domain(d);
                return start_extent;
            }
        }
        args.domain = d;

        rc = xsm_memory_adjust_reservation(current->domain, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        switch ( op )
        {
        case XENMEM_increase_reservation:
			//printk("XENMEM_increase_reservation \n");
            increase_reservation(&args);
            break;
        case XENMEM_decrease_reservation:
			//printk("XENMEM_decrease_reservation: \n");
            decrease_reservation(&args);
            break;
	    case XENMEM_hetero_populate_physmap:
			//printk("XENMEM_hetero_populate_physmap: \n");
			hetero_populate_physmap(&args, &hetero_reservation);
			break;

		case XENMEM_hetero_stop_hotpage_scan:
			 //hetero_hotpage_hints(&args, &hetero_reservation);
			 //printk("do_memory_op: Calling hetero_get_hotpage \n");
			 hetero_get_hotpage(&args, &hetero_reservation);
			 //hetero_get_hotpage(guest_handle_cast(arg,  xen_hetero_memory_reservation_t));
			break;

        default: /* XENMEM_populate_physmap */
            populate_physmap(&args);
            break;
        }

        rcu_unlock_domain(d);

        rc = args.nr_done;

        if ( args.preempted )
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh",
                op | (rc << MEMOP_EXTENT_SHIFT), arg);

        break;

    case XENMEM_exchange:
        rc = memory_exchange(guest_handle_cast(arg, xen_memory_exchange_t));
        break;

    case XENMEM_maximum_ram_page:
        rc = max_page;
        break;

    case XENMEM_current_reservation:
    case XENMEM_maximum_reservation:
    case XENMEM_maximum_gpfn:
        if ( copy_from_guest(&domid, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(domid, &d);
        if ( rc )
            return rc;

        rc = xsm_memory_stat_reservation(current->domain, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        switch ( op )
        {
        case XENMEM_current_reservation:
            rc = d->tot_pages;
            break;
        case XENMEM_maximum_reservation:
            rc = d->max_pages;
            break;
        default:
            ASSERT(op == XENMEM_maximum_gpfn);
            rc = domain_get_maximum_gpfn(d);
            break;
        }

        rcu_unlock_domain(d);

        break;

    default:
        rc = arch_memory_op(op, arg);
        break;
    }

	//if (op == XENMEM_hetero_populate_physmap || op == XENMEM_hetero_stop_hotpage_scan) {
	//	printk("do_memory_op: hypercall returns %u\n", rc);
	//}

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
