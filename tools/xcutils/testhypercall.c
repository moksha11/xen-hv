#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <xenctrl.h>
#include <xenguest.h>
#include <xc_private.h>


int main(int argc, char **argv){

xc_interface *xch;
int rc;

printf("Attempt to invoke the hypercall: __HYPERVISOR_jeet1\n");

/* Acquire Hypervisor Interface Handle.
 *  * This handle goes as the first argument for the function do_xen_hypercall()
 *   * */

xch = xc_interface_open(0,0,0);
printf ("Acquired handle to Xen Hypervisor:%lu\n",(unsigned long)xch);

if(!xch) return -1;

rc = xc_alloc_heteropg(xch, 0, 1);
printf ("Hypercall Details: %d\n", rc);

xc_interface_close(xch);
printf ("Hypervisor handle closed\n");

return 0;

}

