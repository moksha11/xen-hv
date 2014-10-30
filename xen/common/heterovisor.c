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

long do_hypertest(int dummy)
{
	(void)dummy;
	printk("calling do_hypertest\n");
	return 0;
}
