/*
 *	BIRD -- Linksys-specific sysdep code
 *
 *	(c) 2012 Benjamin Paterson <benjamin@paterson.fr>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LINKSYS_H_
#define _BIRD_LINKSYS_H_

#ifdef ENABLE_SYSCFG
#ifdef OSPFv3

int update_dhcpv6_usable_prefix(struct proto_ospf *po);
//void linksys_init(void);

#endif /* OSPFv3 */
#endif /* ENABLE_SYSCFG */

#endif /* _BIRD_LINKSYS_H_ */
