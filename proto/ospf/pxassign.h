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

struct ospf_usp /* (timer, interface, usable prefix) tuple */
{
  node n;
  timer *pxassign_timer;
  struct ospf_iface *ifa;
  ip_addr ip;
  int pxlen;
};

struct ospf_asp
{
  node n;
  ip_addr ip;
  int pxlen;
};

void ospf_pxassign(struct proto_ospf *po);
void ospf_pxassign_area(struct ospf_area *oa);
void ospf_pxassign_usp(struct ospf_area *oa, struct ospf_lsa_ac_tlv_v_usp *usp);
void pxassign_timer_hook(struct timer *timer);

#endif /* OSPFv3 */

#endif /* _BIRD_OSPF_PXASSIGN_H_ */
