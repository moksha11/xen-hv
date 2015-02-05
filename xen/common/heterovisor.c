#include <xen/sched.h>
#include <xen/heterovisor.h>
#include <xen/guest_access.h>

long do_myhcall_op(int arg1, int arg2, int arg3, int arg4, int arg5)
{
    /*printk("Inside my hypercall\n");*/
    if(arg1 == 1)
    {
        change_hetero_config(arg2, arg3, arg4, arg5);
    }
    else if(arg1 == 2)
    {
        csched_hetero_init(arg2, arg3, arg4);
    }
    else if(arg1 == 3)
    {
        change_debug_level(arg2);
    }
    else if(arg1 == 4)//enable system-wide enable flag
    {
        enable_hetero_visor(arg2, arg3);
    }
    else if(arg1 == 5)
    {
        change_dom_config(arg2, arg3, arg4, arg5);
    }
    else if(arg1 == 6)
    {
        /*change_estate(arg2, arg3, arg);*/
    }
    return 0;
}

long do_estate_op(int resource, int state, XEN_GUEST_HANDLE(void) ecap)
{
    int ret;
    ret = change_estate(resource, state, ecap);
    return ret;
}

long do_alloc_hetero_op(int pages)
{
    printk("calling do_alloc_hetero_op \n");
    return 0;
}



long do_perfctr_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    read_perfctr(arg);
    return 0;
}

struct frame {
    unsigned int mfn;
};

#define NUM_PAGES 16
static void* shared_page[NUM_PAGES];
static unsigned int frames_ppage = 0;
static volatile unsigned int* lock;

static void setup_page(void *addr_page);
static void *get_new_page(void);
void hsm_add_mfn(unsigned int mfn, unsigned int idx);
int hsm_setup(void);


int hsm_trylock()
{
    if (test_and_set_bit(0, lock) == 0) {
        return 1;
    }

    return 0;
}

int hsm_unlock()
{
    clear_bit(0, lock);
}

static unsigned int cur_idx;

void hsm_reset_idx()
{
    cur_idx = 0;
}

void hsm_add_mfn(unsigned int mfn, unsigned int idx)
{
    struct frame *f;
    unsigned long offset;
    unsigned int max_frames, pidx;

    //if (frames_ppage == 0) {
    //    printk("initialize shared pages first\n");
    //    return;
    //}

    //for (pidx = 0; pidx < NUM_PAGES; ++pidx) {
    //    if (shared_page[pidx] == NULL) {
    //        printk("page %u not initialized\n", pidx);
    //        return;
    //    }
    //}

    cur_idx++;
    max_frames = frames_ppage * NUM_PAGES;
    idx = cur_idx % max_frames;
    pidx = (idx * NUM_PAGES) / max_frames;
    idx = idx - (frames_ppage * pidx); // compute the in-page index
    offset = idx * sizeof(struct frame);

    if (pidx == 0 && idx == 0) // skip mgmt bytes
        return;

    f = (void *)(((unsigned long)shared_page[pidx]) + offset);
    //printk("!hsm_add_mfn() mfn=%u pidx=%u idx=%u f=%p offset=%lu\n", mfn, pidx,
    //                                                        idx, f, offset);

    f->mfn = mfn;
}

static void setup_page(void *addr_page)
{
    unsigned int fidx;
    unsigned long offset;
    struct frame f;
    
    f.mfn = 0;
    offset = 0;
    
    if (addr_page == NULL) {
        printk("initialize shared pages first\n");
        return;
    }

    printk("setup_page\n");

    for (fidx = 0; fidx < frames_ppage; ++fidx)
    {
        offset = fidx * sizeof(struct frame);
        printk("writing frame %u to %p\n", fidx,
                (void *)(((unsigned long)addr_page) + offset));
        memcpy((void *)(((unsigned long)addr_page) + offset),
                                (void *) &f, sizeof(struct frame));
    }
}

/* setup a shared memory page */
static void *get_new_page(void)
{
    void *addr_new_page = alloc_xenheap_page();

    if (addr_new_page == NULL)
        return NULL;

    clear_page(addr_new_page);
    share_xen_page_with_guest(virt_to_page(addr_new_page), current->domain, XENSHARE_writable);

    printk("new page base addr = %p\n", addr_new_page);

    return addr_new_page; 
}

static void setup_mgmt(void *first_page)
{
    lock = (unsigned int *)first_page;
    *lock = 0;
    printk("lock = %p\n", lock);
}

int hsm_setup(void)
{
    int ret;
    unsigned int pidx;

    ret = 0;

    if (frames_ppage != 0) {
        ret = 1;
        printk("shared pages have already been initialized\n");
        goto out;
    }

    for (pidx = 0; pidx < NUM_PAGES; ++pidx) {
        shared_page[pidx] = get_new_page();
        setup_page(shared_page[pidx]);
    }
    
    setup_mgmt(shared_page[0]);
    
    frames_ppage = PAGE_SIZE/sizeof(struct frame);
    printk("hsm initialized\n");

out:
    return ret;
}

/* hypercall */
long do_hsm_get_mfn(XEN_GUEST_HANDLE(uint64_t) guest_mfn)
{
    uint64_t mfn = 0;
    long ret = 0;
    static unsigned int mfn_idx = 0;

    if (frames_ppage == 0) {
        hsm_setup();
    }
   
    if (mfn_idx < NUM_PAGES) {
        mfn = virt_to_mfn(shared_page[mfn_idx]);
        printk("mfn = %" PRIu64 "\n", mfn);
        ++mfn_idx;

        if (copy_to_guest(guest_mfn, &mfn, 1) != 0) {
            ret = -1;
            goto out;
        }
    }

    ret = mfn_idx;
out:
    return ret;
}

int free_page(void *page_addr)
{
    struct page_info *page;

    printk("ptr to free %p\n", page_addr);
    page = virt_to_page(page_addr);

    if (test_and_clear_bit(_PGC_allocated, &(page->count_info)))
        put_page(page);

    if (page->count_info & PGC_count_mask)
        return -EBUSY;

    free_xenheap_page(page_addr);
    return 0;
}

/* hypercall */
long do_hsm_free_mfn(uint64_t mfn)
{
    unsigned int pidx;

    (void)mfn; // ignore

    for(pidx = 0; pidx < NUM_PAGES; ++pidx) {
        printk("freeing page %u\n", pidx);
        free_page(shared_page[pidx]);
    }

    frames_ppage = 0;
    return 0;
}
