/*
 *      BIRD -- OSPF
 *
 *      (c) 2012 Benjamin Paterson <benjamin@paterson.fr>
 *
 *      Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

#ifndef _BIRD_OSPF_PXASSIGN_H_
#define _BIRD_OSPF_PXASSIGN_H_

#ifdef OSPFv3

#define PXCHOOSE_SUCCESS  0
#define PXCHOOSE_FAILURE -1

/* http://tools.ietf.org/html/draft-arkko-homenet-prefix-assignment-01 section 5.3.2 */
#define PXASSIGN_DELAY 5 // not used, delete if it gets removed from draft

void ospf_pxassign(struct proto_ospf *po);
void ospf_pxassign_area(struct ospf_area *oa);
int ospf_pxassign_usp_ifa(struct ospf_iface *ifa, struct ospf_lsa_ac_tlv_v_usp *usp);
//void pxassign_timer_hook(struct timer *timer);
void * find_next_tlv(struct ospf_lsa_ac *lsa, int *offset, unsigned int size, u8 type);
int update_dhcpv6_usable_prefix(struct proto_ospf *po);
u8 ospf_get_pa_priority(struct top_hash_entry *en, u32 id);

#endif /* OSPFv3 */

#endif /* _BIRD_OSPF_PXASSIGN_H_ */
