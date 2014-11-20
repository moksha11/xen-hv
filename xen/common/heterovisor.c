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
    int ret;

    printk("calling do_alloc_hetero_op \n");
    return ret;
}



long do_perfctr_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    read_perfctr(arg);
    return 0;
}

struct data {
    unsigned int first;
    unsigned int second;
    unsigned int third;
};

void fill_page(char *ptr)
{
    struct data d;
    d.first = 100;
    d.second = 400;
    d.third = 0;

    memcpy(ptr, (void *) &d, sizeof(struct data));
}

long do_hsm_get_mfn(XEN_GUEST_HANDLE(uint64_t) mfn)
{
    void *virt_ptr = NULL;
    uint64_t _mfn = 0;

    virt_ptr = alloc_xenheap_page();

    if (virt_ptr == NULL)
        return 1;

    clear_page(virt_ptr);
    share_xen_page_with_guest(virt_to_page(virt_ptr), current->domain, XENSHARE_writable);

    fill_page((char *) virt_ptr);
    _mfn = virt_to_mfn(virt_ptr);

    printk("_mfn = %" PRIu64 "\n", _mfn);
    printk("ptr alloc'ed = %p\n", virt_ptr);

    if (copy_to_guest(mfn, &_mfn, 1) != 0)
        return 2;

    return 0;
}

long do_hsm_free_mfn(uint64_t mfn)
{
    printk("mfn to free %" PRIu64 "\n", mfn);
    printk("ptr to free %p\n", mfn_to_virt(mfn));
    struct page_info *page = mfn_to_page(mfn);

    if (test_and_clear_bit(_PGC_allocated, &(page->count_info)))
        put_page(page);

    if (page->count_info & PGC_count_mask)
        return -EBUSY;

    free_xenheap_page(mfn_to_virt(mfn));
    printk("mfn %lu freed\n", mfn);
    return 0;
}
