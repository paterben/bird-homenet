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

//#include <syscfg>
#include <string.h>
#include <syscfg/syscfg.h>

#define USABLE_PREFIX_LENGTH (STD_ADDRESS_P_LENGTH + 4) /* 39 for IPv6 address, 4 for /length */
static char usable_prefix[USABLE_PREFIX_LENGTH];
static char usable_prefix_addr[STD_ADDRESS_P_LENGTH];

void
get_dhcpv6_usable_prefix(struct proto_ospf *po)
{
  char *pos;

  syscfg_init();
  syscfg_get(NULL, "ipv6_delegated_prefix", usable_prefix, USABLE_PREFIX_LENGTH);

  if ((pos=strchr(usable_prefix, '/')) != NULL)
  {
    memcpy(usable_prefix_addr, usable_prefix, STD_ADDRESS_P_LENGTH);
    //TODO
  }
}

#endif /* OSPFv3 */
#endif /* ENABLE_SYSCFG */
