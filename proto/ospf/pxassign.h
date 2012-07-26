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
void * find_next_tlv(void *lsa, int *offset, unsigned int size, u8 type);
int update_dhcpv6_usable_prefix(struct proto_ospf *po);
//u8 ospf_get_pa_priority(struct top_hash_entry *en, u32 id);
void ospf_pxassign_reconfigure_iface(struct ospf_iface *ifa);

#define PARSE_LSA_AC_IFAP_START(ifap,en)                                                  \
if((en = ospf_hash_find_ac_lsa_first(po->gr, oa->areaid)) != NULL)                        \
{                                                                                         \
  do {                                                                                    \
    if(ospf_lsa_ac_is_reachable(po, en))                                                  \
    {                                                                                     \
      struct ospf_lsa_ac *tlv;                                                            \
      unsigned int size = en->lsa.length - sizeof(struct ospf_lsa_header);                \
      unsigned int offset = 0;                                                            \
                                                                                          \
      while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_IFAP)) != NULL)\
      {                                                                                   \
        ifap = (struct ospf_lsa_ac_tlv_v_ifap *)(tlv->value);

#define PARSE_LSA_AC_IFAP_END(en) } } } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL); }
#define PARSE_LSA_AC_IFAP_BREAKIF(x,en) if(x) break; } if(x) break; } } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL); }

#define PARSE_LSA_AC_IFAP_ROUTER_START(rid,ifap,en)                                       \
if((en = ospf_hash_find_router_ac_lsa_first(po->gr, oa->areaid, rid)) != NULL)            \
{                                                                                         \
  do {                                                                                    \
    if(ospf_lsa_ac_is_reachable(po, en))                                                  \
    {                                                                                     \
      struct ospf_lsa_ac *tlv;                                                            \
      unsigned int size = en->lsa.length - sizeof(struct ospf_lsa_header);                \
      unsigned int offset = 0;                                                            \
      while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_IFAP)) != NULL)\
      {                                                                                   \
        ifap = (struct ospf_lsa_ac_tlv_v_ifap *)(tlv->value);

#define PARSE_LSA_AC_IFAP_ROUTER_END(en) } } } while((en = ospf_hash_find_router_ac_lsa_next(en)) != NULL); }
#define PARSE_LSA_AC_IFAP_ROUTER_BREAKIF(x,en) if(x) break; } if(x) break; } } while((en = ospf_hash_find_router_ac_lsa_next(en)) != NULL); }

#define PARSE_LSA_AC_ASP_START(asp,ifap)                                                \
{                                                                                       \
  struct ospf_lsa_ac *tlv2;                                                             \
  unsigned int offset2 = LSA_AC_IFAP_OFFSET;                                            \
  while((tlv2 = find_next_tlv(ifap, &offset2, tlv->length, LSA_AC_TLV_T_ASP)) != NULL)  \
  {                                                                                     \
    asp = (struct ospf_lsa_ac_tlv_v_asp *) tlv2->value;

#define PARSE_LSA_AC_ASP_END } }
#define PARSE_LSA_AC_ASP_BREAKIF(x) if(x) break; } }

#define PARSE_LSA_AC_USP_START(usp,en)                                                    \
if((en = ospf_hash_find_ac_lsa_first(oa->po->gr, oa->areaid)) != NULL)                    \
{                                                                                         \
  do {                                                                                    \
    if(ospf_lsa_ac_is_reachable(po, en))                                                  \
    {                                                                                     \
      struct ospf_lsa_ac *tlv;                                                            \
      unsigned int size = en->lsa.length - sizeof(struct ospf_lsa_header);                \
      unsigned int offset = 0;                                                            \
      while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_USP)) != NULL) \
      {                                                                                   \
        usp = (struct ospf_lsa_ac_tlv_v_usp *)(tlv->value);

#define PARSE_LSA_AC_USP_END(en) } } } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL); }
#define PARSE_LSA_AC_USP_BREAKIF(x,en) if(x) break; } if(x) break; } } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL); }

#endif /* OSPFv3 */

#endif /* _BIRD_OSPF_PXASSIGN_H_ */
