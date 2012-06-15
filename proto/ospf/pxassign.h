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
#define PXASSIGN_DELAY 5

struct ospf_usp /* (timer, interface, usable prefix) tuple */
{
  node n;
  struct prefix px;
  timer *pxassign_timer;
  struct ospf_iface *ifa;
};

void ospf_pxcr(struct proto_ospf *po);
int ospf_pxcr_area(struct ospf_area *oa);
int ospf_pxcr_asp(struct ospf_area *oa, struct ospf_lsa_ac_tlv_v_asp *asp, u32 rid);
void ospf_pxassign(struct proto_ospf *po);
void ospf_pxassign_area(struct ospf_area *oa);
void ospf_pxassign_resp(struct ospf_usp *usp);
void ospf_pxassign_usp(struct ospf_area *oa, struct ospf_lsa_ac_tlv_v_usp *usp);
void pxassign_timer_hook(struct timer *timer);
void * find_next_tlv(struct ospf_lsa_ac *lsa, int *offset, unsigned int size, u8 type);

#endif /* OSPFv3 */

#endif /* _BIRD_OSPF_PXASSIGN_H_ */
