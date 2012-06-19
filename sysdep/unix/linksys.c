/*
 * BIRD -- Linksys-specific sysdep code
 *
 * (c) 2012 Benjamin Paterson <benjamin@paterson.fr>
 *
 * Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "proto/ospf/ospf.h"

#ifdef ENABLE_SYSCFG
#ifdef OSPFv3

#include <string.h>
#include <stdlib.h>

#define USABLE_PREFIX_LENGTH (STD_ADDRESS_P_LENGTH + 4) /* 39 for IPv6 address, 4 for /length */
static char usable_prefix[USABLE_PREFIX_LENGTH];
static char usable_prefix_addr[STD_ADDRESS_P_LENGTH];

int
update_dhcpv6_usable_prefix(struct proto_ospf *po)
{
  struct ospf_area *oa;
  char *pos;
  struct prefix_node pxn;
  struct prefix_node *n;
  int found = 0;
/*
  syscfg_init();
  syscfg_get(NULL, "ipv6_delegated_prefix", usable_prefix, USABLE_PREFIX_LENGTH);

  if ((pos=strchr(usable_prefix, '/')) != NULL)
  {
    memcpy(usable_prefix_addr, usable_prefix, STD_ADDRESS_P_LENGTH);
    if(ip_pton(usable_prefix_addr, &pxn.px.addr))
    {
      pxn.px.len = atoi(pos + 1);
      pxn.type = OSPF_USP_T_DHCPV6;

      // update usp_list entries of type DHCPV6
      WALK_LIST(n, po->usp_list)
      {
        if(n->type == OSPF_USP_T_DHCPV6)
        {
          if(!ipa_equal(n->px.addr, pxn.px.addr) || n->px.len != pxn.px.len)
          {
            // remove this node
            rem_node(NODE n);
            mb_free(n);
          }
          else found = 1;
        }
      }
      if(!found)
      {
        // add the prefix to the end of the usp_list and schedule AC LSA origination
        ospf_usp_add(po, &pxn);
        WALK_LIST(oa, po->area_list)
          schedule_ac_lsa(oa);
      }
      return 0;
    }
  }
*/
  return -1;
}

#endif /* OSPFv3 */
#endif /* ENABLE_SYSCFG */
