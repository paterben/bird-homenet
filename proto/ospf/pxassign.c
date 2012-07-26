/*
 * BIRD -- OSPF
 *
 * (c) 2012 Benjamin Paterson <benjamin@paterson.fr>
 *
 * Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: prefix assignment
 *
 * This implementation is based off of:
 * http://tools.ietf.org/html/draft-arkko-homenet-prefix-assignment-02
 *
 *
 */

#include "ospf.h"
#include <stdlib.h>
#include <stdio.h>
#include "sysdep/unix/linksys.h"

#ifdef OSPFv3

static struct prefix_node* assignment_find(struct ospf_iface *ifa, struct prefix *usp);
static int compute_reserved_prefix(ip_addr *rsvd_addr, unsigned int *rsvd_len, ip_addr *px_addr, unsigned int *px_len);
static int is_reserved_prefix(ip_addr addr1, unsigned int len1, ip_addr addr2, unsigned int len2);
static void random_prefix(struct prefix *px, struct prefix *pxsub);
static int in_use(struct prefix *px, list used);
static void next_prefix(struct prefix *pxa, struct prefix *pxb);
static int choose_prefix(struct prefix *pxu, struct prefix *px, list used);
static int configure_ifa_add_prefix(ip_addr addr, unsigned int len, struct ospf_iface *ifa);
static int configure_ifa_del_prefix(ip_addr addr, unsigned int len, struct ospf_iface *ifa);
static void find_used(struct ospf_iface *ifa, ip_addr usp_addr, unsigned int usp_len, list *used, ip_addr *steal_addr, unsigned int *steal_len,
                      unsigned int *found_steal);
static void try_reuse(struct ospf_iface *ifa, ip_addr usp_addr, unsigned int usp_len, list *used,
                      unsigned int *pxchoose_success, unsigned int *change, struct prefix_node *self_r_px);
static void try_assign_unused(struct ospf_iface *ifa, ip_addr usp_addr, unsigned int usp_len, list *used,
                              unsigned int *pxchoose_success, unsigned int *change, struct prefix_node *self_r_px);
static void try_assign_specific(struct ospf_iface *ifa, ip_addr usp_addr, unsigned int usp_len, ip_addr *spec_addr, unsigned int *spec_len,
                                unsigned int *pxchoose_success, unsigned int *change, struct prefix_node *self_r_px);

static int
configure_ifa_add_prefix(ip_addr addr, unsigned int len, struct ospf_iface *ifa)
{
  // FIXME need a better way to do this.
  // FIXME #2 BIRD seems to create a new ospf_iface struct when addresses change on an interface.
  // Maybe the interfaces' asp_list should be placed elsewhere than in the ospf_iface struct.
  // FIXME #3 This should probably be in a sysdep file.
  /*char cmd[128];
  char ip6addr[40];
  ip_ntop(addr, ip6addr);
  snprintf(cmd, sizeof(cmd), "ip -6 addr add %s/%d dev %s", ip6addr, len, ifa->iface->name);
  return system(cmd);*/
  return -1;
}

static int
configure_ifa_del_prefix(ip_addr addr, unsigned int len, struct ospf_iface *ifa)
{
  // FIXME need a better way to do this.
  // FIXME #2 BIRD seems to create a new ospf_iface struct when addresses change on an interface.
  // Maybe the interfaces' asp_list should be placed elsewhere than in the ospf_iface struct.
  // FIXME #3 This should probably be in a sysdep file.
  /*char cmd[128];
  char ip6addr[40];
  ip_ntop(addr, ip6addr);
  snprintf(cmd, sizeof(cmd), "ip -6 addr del %s/%d dev %s", ip6addr, len, ifa->iface->name);
  return system(cmd);*/
  return -1;
}

/**
 * compute_reserved_prefix
 *
 * This function computes the reserved prefix (numerically highest
 * contained /64 prefix) for the prefix px.
 * If it is impossible to compute the reserved prefix, returns -1.
 * Returns 0 otherwise.
 */
static int
compute_reserved_prefix(ip_addr *rsvd_addr, unsigned int *rsvd_len, ip_addr *px_addr, unsigned int *px_len)
{
  if(*px_len > PA_PXLEN_D)
    return -1;

  *rsvd_len = PA_PXLEN_D;
  *rsvd_addr = ipa_xor(ipa_mkmask(*px_len), ipa_mkmask(PA_PXLEN_D));
  *rsvd_addr = ipa_or(*rsvd_addr, ipa_and(*px_addr, ipa_mkmask(*px_len)));
  return 0;
}

/**
 * is_reserved_prefix
 *
 * This function determines whether (@addr1, @len1) lies within (@addr2, len2)
 * and whether it is the reserved prefix for that containing prefix.
 */
static int
is_reserved_prefix(ip_addr addr1, unsigned int len1, ip_addr addr2, unsigned int len2)
{
  ip_addr rsvd_addr;
  unsigned int rsvd_len;

  if(compute_reserved_prefix(&rsvd_addr, &rsvd_len, &addr2, &len2) == -1)
    return 0;
  return (ipa_equal(rsvd_addr,addr1) && rsvd_len == len1);
}

/**
 * find_next_tlv - find next TLV of specified type in AC LSA
 * @lsa: A pointer to the beginning of the body
 * @offset: Offset to the beginning of the body to start search
 * (must point to the beginning of a TLV)
 * @size: Size of the body to search
 * @type: The type of TLV to search for
 *
 * Returns a pointer to the beginning of the next TLV of specified type,
 * or null if there are no more TLVs of that type.
 * If @type is set to NULL, returns the next TLV, whatever the type.
 * Updates @offset to point to the next TLV, or to after the last TLV if
 * there are no more TLVs of the specified type.
 */
void *
find_next_tlv(void *lsa, int *offset, unsigned int size, u8 type)
{
  unsigned int bound = size - 4;
  int old_offset;

  u8 *tlv = (u8 *) lsa;
  while(*offset <= bound)
  {
    old_offset = *offset;
    *offset += LSA_AC_TLV_SPACE(((struct ospf_lsa_ac_tlv *)(tlv + *offset))->length);
    if(!type || ((struct ospf_lsa_ac_tlv *)(tlv + old_offset))->type == type)
      return tlv + old_offset;
  }

  return NULL;
}

/**
 * assignment_find - Check if we have already assigned a prefix
 * on this interface from a specified usable prefix, and return a pointer
 * to this assignment in the asp_list if it exists.
 *
 * @ifa: The current ospf_iface
 * @usp: The usable prefix
 */
static struct prefix_node *
assignment_find(struct ospf_iface *ifa, struct prefix *usp)
{
  //struct ospf_iface *ifa = usp->ifa;
  struct prefix_node *aspn;
  struct proto_ospf *po = ifa->oa->po;

  WALK_LIST(aspn, ifa->asp_list)
  {
    if(aspn->rid == po->router_id && net_in_net(aspn->px.addr, aspn->px.len, usp->addr, usp->len))
    {
      return aspn;
    }
  }
  return NULL;
}

/**
 * random_prefix - Select a random sub-prefix of specified length
 * @px: A pointer to the prefix
 * @pxsub: A pointer to the sub-prefix. Length field must be set.
 */
static void
random_prefix(struct prefix *px, struct prefix *pxsub)
{
  if (px->len < 32 && pxsub->len > 0)
    _I0(pxsub->addr) = random_u32();
  if (px->len < 64 && pxsub->len > 32)
    _I1(pxsub->addr) = random_u32();
  if (px->len < 96 && pxsub->len > 64)
    _I2(pxsub->addr) = random_u32();
  if (px->len < 128 && pxsub->len > 96)
    _I3(pxsub->addr) = random_u32();

  // clean up right part of prefix
  if (pxsub->len < 128)
    pxsub->addr.addr[pxsub->len / 32] &= u32_mkmask(pxsub->len % 32);

  // clean up left part of prefix
  pxsub->addr = ipa_and(pxsub->addr, ipa_not(ipa_mkmask(px->len)));

  // set left part of prefix
  pxsub->addr = ipa_or(pxsub->addr, px->addr);
}

/**
 * in_use - Determine if a prefix is already in use
 * @px: The prefix of interest
 * @used: A list of struct prefix_node
 *
 * This function returns 1 if @px is a sub-prefix or super-prefix
 * of any of the prefixes in @used, 0 otherwise.
 */
static int
in_use(struct prefix *px, list used)
{
  struct prefix_node *pxn;

  WALK_LIST(pxn, used){
    if(net_in_net(px->addr, px->len, pxn->px.addr, pxn->px.len)
       || net_in_net(pxn->px.addr, pxn->px.len, px->addr, px->len))
      return 1;
  }
  return 0;
}

/**
 * next_prefix - Increment prefix to next non-covered/non-covering prefix
 * @pxa: The prefix to increment
 * @pxb: The covering/covered prefix
 *
 * This function calculates the next prefix of length
 * @pxa->len that is not covered by @pxb, and stores it in
 * @pxa. If there is no such prefix, stores IPA_NONE in @pxa->addr.
 */
static void
next_prefix(struct prefix *pxa, struct prefix *pxb)
{
  // if pxa is covering prefix
  if(pxa->len < pxb->len)
  {
    unsigned int i = (pxa->len - 1) / 32;
    u64 add; //hack, need a better way to detect overflow

    add = ((u64) pxa->addr.addr[i]) + (0x80000000 >> ((pxa->len -1) % 32));

    if(add < 0xFFFFFFFF)
    {
      pxa->addr.addr[i]  = (u32) add;
      return;
    }

    pxa->addr.addr[i--] = 0x00000000;
    while(i >= 0)
    {
      add = ((u64) pxa->addr.addr[i]) + 0x00000001;
      if(add < 0xFFFFFFFF)
      {
        pxa->addr.addr[i]  = (u32) add;
        return;
      }
      pxa->addr.addr[i--] = 0x00000000;
    }

    pxa->addr = IPA_NONE;
  }

  // otherwise, pxb is covering prefix
  unsigned int i = (pxb->len - 1) / 32;
  u64 add; //hack, need a better way to detect overflow

  add = ((u64) pxb->addr.addr[i]) + (0x80000000 >> ((pxb->len -1) % 32));
  if(add < 0xFFFFFFFF)
  {
    pxa->addr.addr[i]  = (u32) add;
    pxa->addr = ipa_and(pxa->addr, ipa_mkmask(pxb->len));
    return;
  }

  pxa->addr.addr[i--] = 0x00000000;
  while(i >= 0)
  {
    add = ((u64) pxb->addr.addr[i]) + 0x00000001;
    if(add < 0xFFFFFFFF)
    {
      pxa->addr.addr[i]  = (u32) add;
      pxa->addr = ipa_and(pxa->addr, ipa_mkmask(pxb->len));
      return;
    }
    pxa->addr.addr[i--] = 0x00000000;
  }

  pxa->addr = IPA_NONE;
}

/**
 * choose_prefix - Choose a prefix of specified length from
 * a usable prefix and a list of sub-prefixes in use
 * @pxu: The usable prefix
 * @px: A pointer to the prefix structure. Length must be set.
 * @used: The list of sub-prefixes already in use
 *
 * This function stores a unused prefix of specified length from
 * the usable prefix @pxu, and returns PXCHOOSE_SUCCESS,
 * or stores IPA_NONE into @px->ip and returns PXCHOOSE_FAILURE if
 * all prefixes are in use.
 *
 * This function will never select the numerically highest /64 prefix
 * in the usable prefix (it is considered reserved).
 */
static int
choose_prefix(struct prefix *pxu, struct prefix *px, list used)
{
  /* (Stupid) Algorithm:
     - try a random prefix until success or 10 attempts have passed
     - if failure, do:
       * set looped to 0
       * store prefix in start_prefix
       * while looped is 0 or prefix is strictly smaller than start_prefix, do:
         * if prefix is not in usable prefix range, set to
           lowest prefix of range and set looped to 1
         * if prefix is available, return
         * find one of the used prefixes which contains/is contained in this prefix then
           increment prefix to the first prefix of correct length that
           is not covered by that used prefix / does not cover that used prefix */
  struct prefix_node *n;
  int looped;
  struct prefix start_prefix;

  int i;
  for(i=0;i<10;i++)
  {
    random_prefix(pxu, px);
    if(!in_use(px, used))
      if(!is_reserved_prefix(px->addr, px->len, pxu->addr, pxu->len))
        return PXCHOOSE_SUCCESS;
  }

  looped = 0;
  start_prefix = *px;
  while(looped == 0 || ipa_compare(px->addr, start_prefix.addr) < 0)
  {
    if(!net_in_net(px->addr, px->len, pxu->addr, pxu->len))
    {
      px->addr = pxu->addr;
      looped = 1;
    }

    if(!in_use(px, used))
    {
      if(!is_reserved_prefix(px->addr, px->len, pxu->addr, pxu->len))
        return PXCHOOSE_SUCCESS;
      else
        next_prefix(px, pxu);
    }

    WALK_LIST(n, used)
    {
      if(net_in_net(px->addr, px->len, n->px.addr, n->px.len)
         || net_in_net(n->px.addr, n->px.len, px->addr, px->len))
      {
        next_prefix(px, &n->px);
        break;
      }
    }
  }
  return PXCHOOSE_FAILURE;
}

void
ospf_pxassign(struct proto_ospf *po)
{
  struct proto *p = &po->proto;
  struct ospf_area *oa;

  OSPF_TRACE(D_EVENTS, "Starting prefix assignment algorithm");

  WALK_LIST(oa, po->area_list)
  {
    // prefix assignment algorithm
    ospf_pxassign_area(oa);
  }
}

/**
 * ospf_pxassign_area - Run prefix assignment algorithm for
 * usable prefixes advertised by AC LSAs in a specific area.
 *
 * @oa: The area to search for LSAs in. Note that the algorithm
 * may impact interfaces that are not in this area.
 */
void
ospf_pxassign_area(struct ospf_area *oa)
{
  //struct proto *p = &oa->po->proto;
  struct proto_ospf *po = oa->po;
  struct top_hash_entry *en;
  struct ospf_iface *ifa;
  struct prefix_node *asp;
  struct ospf_lsa_ac_tlv_v_usp *usp;
  int change = 0;

  //OSPF_TRACE(D_EVENTS, "Starting prefix assignment algorithm for AC LSAs in area %R", oa->areaid);

  /* mark all this area's iface's assignments as invalid */
  WALK_LIST(ifa, po->iface_list)
  {
    if(ifa->oa == oa)
    {
      WALK_LIST(asp, ifa->asp_list)
      {
        asp->valid = 0;
      }
    }
  }

  // perform the prefix assignment algorithm on each (USP, iface) tuple
  PARSE_LSA_AC_USP_START(usp,en)
  {
    WALK_LIST(ifa, po->iface_list)
    {
      if(ifa->oa == oa)
      {
        change |= ospf_pxassign_usp_ifa(ifa, (struct ospf_lsa_ac_tlv_v_usp *)(usp));
      }
    }
  }
  PARSE_LSA_AC_USP_END(en);

  /* remove all this area's iface's invalid assignments */
  WALK_LIST(ifa, po->iface_list)
  {
    if(ifa->oa == oa)
    {
      WALK_LIST(asp, ifa->asp_list)
      {
        if(!asp->valid)
        {
          configure_ifa_del_prefix(asp->px.addr, asp->px.len, ifa);
          if(asp->rid == po->router_id)
            change = 1;
          rem_node(NODE asp);
          mb_free(asp);
        }
      }
    }
  }

  if(change)
  {
     schedule_ac_lsa(oa);
  }
}

/** ospf_pxassign_usp_ifa - Main prefix assignment algorithm
 *
 * @ifa: The Current Interface
 * @usp: The Current Usable Prefix
 */
int
ospf_pxassign_usp_ifa(struct ospf_iface *ifa, struct ospf_lsa_ac_tlv_v_usp *cusp)
{
  struct top_hash_entry *en;
  struct ospf_area *oa = ifa->oa;
  struct proto_ospf *po = oa->po;
  struct proto *p = &po->proto;
  //struct ospf_neighbor *neigh;
  //struct ospf_usp *usp;
  struct ospf_iface *ifa2;
  struct ospf_lsa_ac_tlv_v_usp *usp2;
  struct ospf_lsa_ac_tlv_v_asp *asp;
  struct ospf_lsa_ac_tlv_v_ifap *ifap;
  struct ospf_neighbor *neigh;
  struct prefix_node *pxn, *n, *self_r_px;
  //timer *pxassign_timer;
  ip_addr usp_addr, usp2_addr, neigh_addr, neigh_r_addr;
  unsigned int usp_len, usp2_len, neigh_len, neigh_r_len;
  u8 usp_pxopts, usp2_pxopts, neigh_pxopts;
  u16 usp_rest, usp2_rest, neigh_rest;
  int change = 0;

  lsa_get_ipv6_prefix((u32 *)cusp, &usp_addr, &usp_len, &usp_pxopts, &usp_rest);

  //OSPF_TRACE(D_EVENTS, "Starting prefix assignment algorithm for prefix %I/%d", ip, pxlen);

  /* 8.5.0 */
  PARSE_LSA_AC_USP_START(usp2, en)
  {
    lsa_get_ipv6_prefix((u32 *)usp2, &usp2_addr, &usp2_len, &usp2_pxopts, &usp2_rest);
    if(net_in_net(usp_addr, usp_len, usp2_addr, usp2_len) && (!ipa_equal(usp_addr, usp2_addr) || usp_len != usp2_len))
      return change;
  }
  PARSE_LSA_AC_USP_END(en);

  /* 8.5.1 */
  /* FIXME I think the draft should say "active neighbors" (state >= Init), that's what I suppose */
  /*int have_neigh = 0;
  WALK_LIST(neigh, ifa->neigh_list)
  {
    if(neigh->state >= NEIGHBOR_INIT)
      have_neigh = 1;
  }*/

  /* 8.5.2a and 8.5.2b */
  int have_highest_link_pa_priority = 0;
  int have_highest_link_pa_pxlen = 0; // only relevant if we have highest priority
  u8 highest_link_pa_priority = 0;
  u8 highest_link_pa_pxlen = 0;
  WALK_LIST(neigh, ifa->neigh_list)
  {
    if(neigh->state >= NEIGHBOR_INIT)
    {
      PARSE_LSA_AC_IFAP_ROUTER_START(neigh->rid, ifap, en)
      {
        if(ifap->id == neigh->iface_id)
        {
          // store for future reference
          neigh->pa_priority = ifap->pa_priority;
          neigh->pa_pxlen = ifap->pa_pxlen;

          if(ifap->pa_priority > highest_link_pa_priority)
          {
            highest_link_pa_priority = ifap->pa_priority;
            highest_link_pa_pxlen = ifap->pa_pxlen;
          }
          if(ifap->pa_priority == highest_link_pa_priority && ifap->pa_pxlen > highest_link_pa_pxlen)
            highest_link_pa_pxlen = ifap->pa_pxlen;
        }
      }
      PARSE_LSA_AC_IFAP_ROUTER_END(en);
    }
  }
  if(highest_link_pa_priority < ifa->pa_priority
     || (highest_link_pa_priority == ifa->pa_priority && highest_link_pa_pxlen <= ifa->pa_pxlen))
  {
    highest_link_pa_pxlen = ifa->pa_pxlen;
    have_highest_link_pa_pxlen = 1;
  }
  if(highest_link_pa_priority <= ifa->pa_priority)
  {
    highest_link_pa_priority = ifa->pa_priority;
    have_highest_link_pa_priority = 1;
  }

  /* 8.5.2c */
  int have_highest_link_rid = 1; // only relevant if have highest priority + pa_pxlen
  WALK_LIST(neigh, ifa->neigh_list)
  {
    if(neigh->state >= NEIGHBOR_INIT
       && neigh->pa_priority == highest_link_pa_priority
       && neigh->pa_pxlen == highest_link_pa_pxlen
       && neigh->rid > po->router_id)
    {
      have_highest_link_rid = 0;
      break;
    }
  }

  /* 8.5.2d */
  int assignment_found = 0;
  u32 neigh_rid = 0; // RID of responsible neighbor, if any
  WALK_LIST(neigh, ifa->neigh_list)
  {
    if(neigh->state >= NEIGHBOR_INIT
       && neigh->pa_priority == highest_link_pa_priority
       && neigh->pa_pxlen == highest_link_pa_pxlen
       && neigh->rid > neigh_rid)
    {
      PARSE_LSA_AC_IFAP_ROUTER_START(neigh->rid, ifap, en)
      {
        if(ifap->id == neigh->iface_id)
        {
          PARSE_LSA_AC_ASP_START(asp, ifap)
          {
            lsa_get_ipv6_prefix((u32 *)(asp), &neigh_addr, &neigh_len, &neigh_pxopts, &neigh_rest);
            if(net_in_net(neigh_addr, neigh_len, usp_addr, usp_len))
            {
              /* a prefix has already been assigned by a neighbor to the link */
              /* we're not sure it is responsible for the link yet, so we store
                 the assigned prefix and keep looking at other neighbors with
                 same priority/pa_pxlen and higher RID */
              neigh_r_addr = neigh_addr;
              neigh_r_len = neigh_len;
              neigh_rid = neigh->rid;
              assignment_found = 1;
              break;
            }
          }
          PARSE_LSA_AC_ASP_BREAKIF(assignment_found);
        }
      }
      PARSE_LSA_AC_IFAP_ROUTER_BREAKIF(assignment_found, en);
    }
  }

  /* 8.5.2e */
  int have_highest_link_assignment = 0;
  if(have_highest_link_pa_priority
     && have_highest_link_pa_pxlen
     && po->router_id > neigh_rid)
  {
    struct prefix usp_px;
    usp_px.addr = usp_addr;
    usp_px.len = usp_len;
    self_r_px = assignment_find(ifa, &usp_px);
    if(self_r_px)
      have_highest_link_assignment = 1;
  }

  /* 8.5.3 */
  // exactly one of the following will be executed:
  // step 4 will be executed if:
  //   have_highest_link_assignment
  // step 5 will be executed if:
  //   !have_highest_link_assignment && assignment_found
  // step 6 will be executed if:
  //   !have_highest_link_assignment && !assignment_found && have_highest_link_pa_priority && have_highest_link_pa_pxlen && have_highest_link_rid
  if(!have_highest_link_assignment && !assignment_found && (!have_highest_link_pa_priority || !have_highest_link_pa_pxlen || !have_highest_link_rid))
    return change; // go to next interface

  /* 8.5.4 */
  // we already have an assignment but must check whether it is valid and whether there is better
  unsigned int deassigned_prefix = 0; // whether we had to remove our own assignment. Causes jump to step 8.5.6.
  if(have_highest_link_assignment)
  {
    PARSE_LSA_AC_IFAP_START(ifap, en)
    {
      if(en->lsa.rt != po->router_id // don't check our own LSAs
         && (ifap->pa_priority > highest_link_pa_priority
             || (ifap->pa_priority == highest_link_pa_priority && ifap->pa_pxlen > highest_link_pa_pxlen)
             || (ifap->pa_priority == highest_link_pa_priority && ifap->pa_pxlen == highest_link_pa_pxlen && en->lsa.rt > po->router_id)))
      {
        PARSE_LSA_AC_ASP_START(asp, ifap)
        {
          ip_addr addr;
          unsigned int len;
          u8 pxopts;
          u16 rest;

          lsa_get_ipv6_prefix((u32 *)(asp), &addr, &len, &pxopts, &rest);

          // test if assigned prefix collides with our assignment
          if(net_in_net(addr, len, self_r_px->px.addr, self_r_px->px.len) || net_in_net(self_r_px->px.addr, self_r_px->px.len, addr, len))
          {
            OSPF_TRACE(D_EVENTS, "Interface %s: assignment %I/%d collides with %I/%d, removing", ifa->iface->name, self_r_px->px.addr, self_r_px->px.len, addr, len);
            configure_ifa_del_prefix(self_r_px->px.addr, self_r_px->px.len, ifa);
            rem_node(NODE self_r_px);
            mb_free(self_r_px);
            deassigned_prefix = 1;
            change = 1;
            break;
          }
        }
        PARSE_LSA_AC_ASP_BREAKIF(deassigned_prefix);
      }
    }
    PARSE_LSA_AC_IFAP_BREAKIF(deassigned_prefix, en);

    // also check other assignments for which we are responsible to see if this one is valid.
    // This should be useless: we should never have made a colliding assignment
    // without deleting this one in the first place
    if(!deassigned_prefix)
    {
      WALK_LIST(ifa2, po->iface_list)
      {
        if(ifa->oa == oa)
        {
          WALK_LIST(n, ifa2->asp_list)
          {
            if(n->rid == po->router_id
               && (ifa2->pa_priority > highest_link_pa_priority
                   || (ifa2->pa_priority == highest_link_pa_priority && ifa2->pa_pxlen >= highest_link_pa_pxlen)))
            {
              if((net_in_net(n->px.addr, n->px.len, self_r_px->px.addr, self_r_px->px.len) || net_in_net(self_r_px->px.addr, self_r_px->px.len, n->px.addr, n->px.len))
                 && (!ipa_equal(self_r_px->px.addr, n->px.addr) || self_r_px->px.len != n->px.len))
              {
                die("Bug in prefix assignment algorithm: forgot to remove a prefix when assigning new one");
                /*OSPF_TRACE(D_EVENTS, "Interface %s: own assignment %I/%d collides with %I/%d, removing", ifa->iface->name, self_r_px->px.addr, self_r_px->px.len, addr, len);
                rem_node(NODE self_r_px);
                mb_free(self_r_px);
                deassigned_prefix = 1;
                change = 1;
                // FIXME deassign prefix from interface
                break;*/
              }
            }
          }
          // if(deassigned_prefix) break;
        }
      }
    }

    unsigned int replaced_prefix = 0; // whether we replaced the current assignment
    if(!deassigned_prefix
       && is_reserved_prefix(self_r_px->px.addr, self_r_px->px.len, usp_addr, usp_len))
    {
      // Our assignment is valid, but it is the reserved /64 prefix.
      // We must try to assign a better /64 by any means (including stealing).
      // To do that we use steps 8.5.6.0a through 8.5.6.0d.
      // Be sure to remove the reserved prefix if an assignment can be made.

      list used; /* list of struct prefix_node */
      init_list(&used);
      ip_addr steal_addr;
      unsigned int steal_len;
      unsigned int found_steal = 0;

      /* re-use 8.5.6.0a */
      // find all used prefixes in LSADB and our own interface's asp_lists
      find_used(ifa, usp_addr, usp_len, &used, &steal_addr, &steal_len, &found_steal);

      /* re-use 8.5.6.0b */
      // see if we can find a /64 in memory that is unused
      try_reuse(ifa, usp_addr, usp_len, &used, &replaced_prefix, &change, self_r_px);

      /* re-use 8.5.6.0c */
      // see if we can find an unused /64
      if(!replaced_prefix)
        try_assign_unused(ifa, usp_addr, usp_len, &used, &replaced_prefix, &change, self_r_px);

      /* re-use 8.5.6.0d */
      // try to steal a /64
      if(!replaced_prefix && found_steal)
        try_assign_specific(ifa, usp_addr, usp_len, &steal_addr, &steal_len, &replaced_prefix, &change, self_r_px);

      WALK_LIST_DELSAFE(n, pxn, used)
      {
        rem_node(NODE n);
        mb_free(n);
      }

    }

    if(!deassigned_prefix && !replaced_prefix)
    {
      self_r_px->valid = 1;
    }
  }

  /* 8.5.5 */
  // we must check whether we are aware of someone else's assignment
  if(!have_highest_link_assignment && assignment_found)
  {
    int found = 0; // whether assignment is already in the ifa's asp_list
    WALK_LIST(n,ifa->asp_list)
    {
      if(ipa_equal(n->px.addr, neigh_r_addr) && n->px.len == neigh_r_len
         && n->rid == neigh_rid && n->pa_priority == highest_link_pa_priority)
      {
        found = 1;
        n->valid = 1;
      }
    }

    // if it's not already there, we must run some extra checks to see if we can assign it.
    // parse all interface's asp_lists twice: once to determine if the new assignment takes
    // priority, second to remove all colliding assignments if it does.
    // cases a colliding existing assignment wins and new one must be refused:
    //   existing has a strictly higher pa_priority
    //   existing has the same pa_priority and a strictly longer prefix
    //   existing has the same pa_priority, same prefix and strictly higher RID
    int refused = 0;
    int collision_found = 0;
    if(!found)
    {
      WALK_LIST(ifa2, po->iface_list)
      {
        if(ifa2->oa == oa)
        {
          WALK_LIST(n, ifa2->asp_list)
          {
            if(net_in_net(n->px.addr, n->px.len, neigh_r_addr, neigh_r_len)
               || net_in_net(neigh_r_addr, neigh_r_len, n->px.addr, n->px.len))
            {
              collision_found = 1;
              if(n->pa_priority > highest_link_pa_priority
                 || (n->pa_priority == highest_link_pa_priority && n->px.len > neigh_r_len)
                 || (n->pa_priority == highest_link_pa_priority && n->px.len == neigh_r_len && n->rid > neigh_rid))
              {
                refused = 1;
                OSPF_TRACE(D_EVENTS, "Interface %s: Refused %R's assignment %I/%d with priority %d, we have interface %s router %R assignment %I/%d with priority %d",
                                     ifa->iface->name, neigh_rid, neigh_r_addr, neigh_r_len, highest_link_pa_priority, ifa2->iface->name, n->rid, n->px.addr, n->px.len, n->pa_priority);
                break;
                // we will have no assignment on this interface, but we don't know who's responsible.
                // if the neighbor is ill-intentioned and never removes his assignment,
                // no prefix will ever be assigned on this interface.
                // it would be possible to run some additional steps to see if we are responsible here.
                // under normal conditions, the neighbor will eventually remove his assignment.
              }
            }
          }
          if(refused) break;
        }
      }
    }
    if(!refused && collision_found)
    {
      // delete all colliding assignments on interfaces
      WALK_LIST(ifa2, po->iface_list)
      {
        if(ifa2->oa == oa)
        {
          WALK_LIST_DELSAFE(n, pxn, ifa2->asp_list)
          {
            if(net_in_net(n->px.addr, n->px.len, neigh_r_addr, neigh_r_len)
               || net_in_net(neigh_r_addr, neigh_r_len, n->px.addr, n->px.len))
            {
              OSPF_TRACE(D_EVENTS, "Interface %s: To add %R's assignment %I/%d with priority %d, must delete interface %s router %R assignment %I/%d with priority %d",
                                   ifa->iface->name, neigh_rid, neigh_r_addr, neigh_r_len, highest_link_pa_priority, ifa2->iface->name, n->rid, n->px.addr, n->px.len, n->pa_priority);
              configure_ifa_del_prefix(n->px.addr, n->px.len, ifa2);
              if(n->rid == po->router_id)
                change = 1;
              rem_node(NODE n);
              mb_free(n);
            }
          }
        }
      }
    }

    if(!found && !refused)
    {
      OSPF_TRACE(D_EVENTS, "Interface %s: Adding %R's assignment %I/%d with priority %d", ifa->iface->name, neigh_rid, neigh_r_addr, neigh_r_len, highest_link_pa_priority);
      pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
      pxn->px.addr = neigh_r_addr;
      pxn->px.len = neigh_r_len;
      pxn->rid = neigh_rid;
      pxn->pa_priority = highest_link_pa_priority;
      pxn->valid = 1;
      add_tail(&ifa->asp_list, NODE pxn);
      configure_ifa_add_prefix(pxn->px.addr, pxn->px.len, ifa);
    }
  }

  /* 8.5.6 */
  // we must assign a new prefix
  if(deassigned_prefix
     || (!have_highest_link_assignment && !assignment_found && have_highest_link_pa_priority && have_highest_link_pa_pxlen && have_highest_link_rid))
  {
    list used; /* list of struct prefix_node */
    init_list(&used);
    ip_addr steal_addr;
    unsigned int steal_len;
    unsigned int found_steal = 0;
    unsigned int pxchoose_success = 0;

    /* 8.5.6a */
    // find all used prefixes in LSADB and our own interface's asp_lists
    find_used(ifa, usp_addr, usp_len, &used, &steal_addr, &steal_len, &found_steal);

    /* 8.5.6b */
    // see if we can find a prefix in memory that is unused
    try_reuse(ifa, usp_addr, usp_len, &used, &pxchoose_success, &change, NULL);

    /* 8.5.6c */
    // see if we can find an unused prefix
    if(!pxchoose_success)
      try_assign_unused(ifa, usp_addr, usp_len, &used, &pxchoose_success, &change, NULL);

    /* 8.5.6d */
    // try to steal a /64
    if(!pxchoose_success && ifa->pa_pxlen == PA_PXLEN_D && found_steal)
    {
      try_assign_specific(ifa, usp_addr, usp_len, &steal_addr, &steal_len, &pxchoose_success, &change, NULL);
    }

    /* 8.5.6e */
    // try to assign the reserved prefix or a /80 from the reserved prefix
    if(!pxchoose_success && ifa->pa_pxlen == PA_PXLEN_D)
    {
      struct prefix rsvd;
      compute_reserved_prefix(&rsvd.addr, &rsvd.len, &usp_addr, &usp_len);
      try_assign_specific(ifa, usp_addr, usp_len, &rsvd.addr, &rsvd.len, &pxchoose_success, &change, NULL);
    }
    if(!pxchoose_success && ifa->pa_pxlen == PA_PXLEN_SUB)
    {
      struct prefix rsvd, px, pxu;
      compute_reserved_prefix(&rsvd.addr, &rsvd.len, &usp_addr, &usp_len);
      px.addr = IPA_NONE;
      px.len = PA_PXLEN_SUB;
      pxu.addr = rsvd.addr;
      pxu.len = rsvd.len;
      list empty_list;
      init_list(&empty_list);
      switch(choose_prefix(&pxu, &px, empty_list))
      {
        case PXCHOOSE_SUCCESS:
          try_assign_specific(ifa, usp_addr, usp_len, &px.addr, &px.len, &pxchoose_success, &change, NULL);
          break;
        case PXCHOOSE_FAILURE: // impossible
          die("bug in prefix assignment algorithm: cannot assign /80 from reserved prefix");
          break;
      }
    }

    /* 8.5.6f */
    if(!pxchoose_success)
      OSPF_TRACE(D_EVENTS, "Interface %s: No prefixes left to assign from prefix %I/%d.", ifa->iface->name, usp_addr, usp_len);

    WALK_LIST_DELSAFE(n, pxn, used)
    {
      rem_node(NODE n);
      mb_free(n);
    }
  }

  return change;
}

/**
 * find_used - Find all already used prefixes
 *
 * Updates list of used prefixes @used.
 * Also updates @steal_addr, @steal_len, @found_steal.
 */
static void
find_used(struct ospf_iface *ifa, ip_addr usp_addr, unsigned int usp_len, list *used, ip_addr *steal_addr, unsigned int *steal_len,
          unsigned int *found_steal)
{
  struct ospf_area *oa = ifa->oa;
  struct proto_ospf *po = oa->po;
  struct top_hash_entry *en;
  struct prefix_node *n, *pxn;
  struct ospf_lsa_ac_tlv_v_ifap *ifap;
  struct ospf_lsa_ac_tlv_v_asp *asp;
  struct ospf_iface *ifa2;

  u8 lowest_pa_priority, lowest_pa_pxlen;
  u32 lowest_rid;

  lowest_pa_priority = ifa->pa_priority;
  lowest_pa_pxlen = ifa->pa_pxlen;
  lowest_rid = po->router_id;

  PARSE_LSA_AC_IFAP_START(ifap, en)
  {
    if(en->lsa.rt != po->router_id) // don't check our own LSAs
    {
      PARSE_LSA_AC_ASP_START(asp, ifap)
      {
        ip_addr addr;
        unsigned int len;
        u8 pxopts;
        u16 rest;

        lsa_get_ipv6_prefix((u32 *)(asp) , &addr, &len, &pxopts, &rest);
        // test if assigned prefix is part of current usable prefix
        if(net_in_net(addr, len, usp_addr, usp_len))
        {
          /* add prefix to list of used prefixes */
          pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
          add_tail(used, NODE pxn);
          pxn->px.addr = addr;
          pxn->px.len = len;
          pxn->pa_priority = ifap->pa_priority;
          pxn->rid = en->lsa.rt;

          if(ifa->pa_pxlen == PA_PXLEN_D)
          {
            // test if assigned prefix is stealable
            if((ifap->pa_priority < lowest_pa_priority
                || (ifap->pa_priority == lowest_pa_priority && ifap->pa_pxlen < lowest_pa_pxlen))
               && (!is_reserved_prefix(addr, len, usp_addr, usp_len)))
            {
              *steal_addr = ipa_and(addr,ipa_mkmask(PA_PXLEN_D));
              *steal_len = PA_PXLEN_D;
              lowest_pa_priority = ifap->pa_priority;
              lowest_pa_pxlen = ifap->pa_pxlen;
              lowest_rid = en->lsa.rt;
              *found_steal = 1;
            }
          }
        }
      }
      PARSE_LSA_AC_ASP_END;
    }
  }
  PARSE_LSA_AC_IFAP_END(en);

  /* we also check our own interfaces for assigned prefixes for which we are responsible */
  WALK_LIST(ifa2, po->iface_list)
  {
    if(ifa2->oa == oa)
    {
      WALK_LIST(n, ifa2->asp_list)
      {
        if(n->rid == po->router_id && net_in_net(n->px.addr, n->px.len, usp_addr, usp_len))
        {
          /* add prefix to list of used prefixes */
          pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
          add_tail(used, NODE pxn);
          pxn->px.addr = n->px.addr;
          pxn->px.len = n->px.len;
          pxn->rid = n->rid;
          pxn->pa_priority = ifa2->pa_priority;

          if(ifa->pa_pxlen == PA_PXLEN_D)
          {
            // test if assigned prefix is stealable
            if((ifa2->pa_priority < lowest_pa_priority
                || (ifa2->pa_priority == lowest_pa_priority && ifa2->pa_pxlen < lowest_pa_pxlen))
               && (!is_reserved_prefix(pxn->px.addr, pxn->px.len, usp_addr, usp_len)))
            {
              *steal_addr = ipa_and(n->px.addr,ipa_mkmask(PA_PXLEN_D));
              *steal_len = PA_PXLEN_D;
              lowest_pa_priority = ifa2->pa_priority;
              lowest_pa_pxlen = ifa2->pa_pxlen;
              lowest_rid = po->router_id;
              *found_steal = 1;
            }
          }
        }
      }
    }
  }
}

/**
 * try_reuse - Try to reuse an unused prefix of specified @length in memory
 */
static void
try_reuse(struct ospf_iface *ifa, ip_addr usp_addr, unsigned int usp_len, list *used,
            unsigned int *pxchoose_success, unsigned int *change, struct prefix_node *self_r_px)
{
  // FIXME implement
}

/**
 * try_assign_unused - Try to assign an unused prefix of specified @length.
 * @self_r_px: if this is not set to NULL and a successful assignment takes place,
 * removes this prefix (this must be the reserved prefix).
 */
static void
try_assign_unused(struct ospf_iface *ifa, ip_addr usp_addr, unsigned int usp_len, list *used, unsigned int *pxchoose_success,
                  unsigned int *change, struct prefix_node *self_r_px)
{
  struct proto_ospf *po = ifa->oa->po;
  struct proto *p = &po->proto;
  struct prefix_node *pxn;

  struct prefix px, pxu;
  px.addr = IPA_NONE;
  px.len = ifa->pa_pxlen;
  if(ifa->pa_pxlen == PA_PXLEN_D)
  {
    pxu.addr = usp_addr;
    pxu.len = usp_len;
  }
  else if(ifa->pa_pxlen == PA_PXLEN_SUB)
  {
    if(compute_reserved_prefix(&pxu.addr, &pxu.len, &usp_addr, &usp_len) == -1)
      die("bug in prefix assignment algorithm: usable prefix too long");
  }
  else die("bug in prefix assignment algorithm: trying to assign nonstandard length");

  switch(choose_prefix(&pxu, &px, *used))
  {
    case PXCHOOSE_SUCCESS:
      if(self_r_px)
      {
        // delete the reserved /64 prefix that is going to be replaced
        configure_ifa_del_prefix(self_r_px->px.addr, self_r_px->px.len, ifa);
        OSPF_TRACE(D_EVENTS, "Interface %s: Replacing prefix %I/%d with prefix %I/%d from usable prefix %I/%d", ifa->iface->name, self_r_px->px.addr, self_r_px->px.len, px.addr, px.len, usp_addr, usp_len);
        rem_node(NODE self_r_px);
        mb_free(self_r_px);
      }
      else {
        OSPF_TRACE(D_EVENTS, "Interface %s: Assigned prefix %I/%d from usable prefix %I/%d", ifa->iface->name, px.addr, px.len, usp_addr, usp_len);
      }
      //FIXME do prefix assignment!
      pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
      add_tail(&ifa->asp_list, NODE pxn);
      pxn->px.addr = px.addr;
      pxn->px.len = px.len;
      pxn->rid = po->router_id;
      pxn->pa_priority = ifa->pa_priority;
      pxn->valid = 1;
      *change = 1;
      *pxchoose_success = 1;
      configure_ifa_add_prefix(pxn->px.addr, pxn->px.len, ifa);
      break;

    case PXCHOOSE_FAILURE:
      //log(L_WARN "%s: No prefixes left to assign to interface %s from prefix %I/%d.", p->name, ifa->iface->name, usp_addr, usp_len);
      break;
  }
}

/**
 * try_assign_specific - Try to assign a specific prefix, used or not.
 * Only check that the assignment is legal
 * when considering the interface's priority and pa_pxlen.
 * If @self_r_px is not NULL and an assignment can be made,
 * the @self_r_px assignment is removed.
 */
static void
try_assign_specific(struct ospf_iface *ifa, ip_addr usp_addr, unsigned int usp_len, ip_addr *spec_addr, unsigned int *spec_len,
                    unsigned int *pxchoose_success, unsigned int *change, struct prefix_node *self_r_px)
{
  struct ospf_area *oa = ifa->oa;
  struct proto_ospf *po = oa->po;
  struct proto *p = &po->proto;
  struct ospf_lsa_ac_tlv_v_ifap *ifap;
  struct ospf_lsa_ac_tlv_v_asp *asp;
  struct top_hash_entry *en;
  struct ospf_iface *ifa2;
  struct prefix_node *n, *pxn;
  unsigned int can_assign = 1;

  // we need to check that no one else has already assigned the specific prefix.
  PARSE_LSA_AC_IFAP_START(ifap, en)
  {
    if(en->lsa.rt != po->router_id // don't check our own LSAs
       && (ifap->pa_priority > ifa->pa_priority
           || (ifap->pa_priority == ifa->pa_priority && ifap->pa_pxlen >= ifa->pa_pxlen)))
    {
      PARSE_LSA_AC_ASP_START(asp, ifap)
      {
        ip_addr addr;
        unsigned int len;
        u8 pxopts;
        u16 rest;

        lsa_get_ipv6_prefix((u32 *)(asp) , &addr, &len, &pxopts, &rest);
        if(net_in_net(addr, len, *spec_addr, *spec_len)
           || net_in_net(*spec_addr, *spec_len, addr, len))
          can_assign = 0;
      }
      PARSE_LSA_AC_ASP_BREAKIF(!can_assign);
    }
  }
  PARSE_LSA_AC_IFAP_BREAKIF(!can_assign, en);

  // we also need to check that we have not already assigned
  // a colliding prefix ourselves
  if(can_assign)
  {
    WALK_LIST(ifa2, po->iface_list)
    {
      if(ifa2->oa == oa)
      {
        WALK_LIST(n, ifa2->asp_list)
        {
          if(n->rid == po->router_id
             && (n->pa_priority > ifa->pa_priority
                 || (n->pa_priority == ifa->pa_priority && n->px.len >= ifa->pa_pxlen)))
          {
            if(net_in_net(n->px.addr, n->px.len, *spec_addr, *spec_len)
               || net_in_net(*spec_addr, *spec_len, n->px.addr, n->px.len))
            {
                can_assign = 0;
            }
          }
        }
      }
    }
  }

  if(can_assign)
  {
    // delete colliding assignments from any other interfaces
    WALK_LIST(ifa2, po->iface_list)
    {
      if(ifa2->oa == oa)
      {
        WALK_LIST_DELSAFE(n, pxn, ifa2->asp_list)
        {
          if((net_in_net(n->px.addr, n->px.len, *spec_addr, *spec_len)
              || net_in_net(*spec_addr, *spec_len, n->px.addr, n->px.len))
             && (!self_r_px
                 || (!ipa_equal(self_r_px->px.addr, n->px.addr)
                     || self_r_px->pa_priority != n->pa_priority
                     || self_r_px->px.len != n->px.len
                     || n->rid != po->router_id)))
                 // self_r_px will be removed in next step if it exists
          {
            OSPF_TRACE(D_EVENTS, "Interface %s: Trying to assign %I/%d, must remove %I/%d from interface %s", ifa->iface->name, *spec_addr, *spec_len, n->px.addr, n->px.len, ifa2->iface->name);
            configure_ifa_del_prefix(n->px.addr, n->px.len, ifa2);
            rem_node(NODE n);
            mb_free(n);
            if(n->rid == po->router_id)
              *change = 1;
          }
        }
      }
    }

    // finally, do the assignment
    if(self_r_px)
    {
      OSPF_TRACE(D_EVENTS, "Interface %s: Replacing prefix %I/%d with prefix %I/%d from usable prefix %I/%d", ifa->iface->name, self_r_px->px.addr, self_r_px->px.len, *spec_addr, *spec_len, usp_addr, usp_len);
      configure_ifa_del_prefix(self_r_px->px.addr, self_r_px->px.len, ifa);
      rem_node(NODE self_r_px);
      mb_free(self_r_px);
    }
    else {
      OSPF_TRACE(D_EVENTS, "Interface %s: Assigned prefix %I/%d from usable prefix %I/%d", ifa->iface->name, *spec_addr, *spec_len, usp_addr, usp_len);
    }
    pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
    add_tail(&ifa->asp_list, NODE pxn);
    pxn->px.addr = *spec_addr;
    pxn->px.len = *spec_len;
    pxn->rid = po->router_id;
    pxn->pa_priority = ifa->pa_priority;
    pxn->valid = 1;
    *change = 1;
    *pxchoose_success = 1;
    configure_ifa_add_prefix(pxn->px.addr, pxn->px.len, ifa);
  }
}

#ifdef ENABLE_SYSEVENT
#define USABLE_PREFIX_LENGTH (STD_ADDRESS_P_LENGTH + 4) /* 39 for IPv6 address, 4 for /length */
static char usable_prefix[USABLE_PREFIX_LENGTH];
#endif

int
update_dhcpv6_usable_prefix(struct proto_ospf *po)
{
#ifdef ENABLE_SYSEVENT
  struct proto *p = &po->proto;
  struct prefix_node pxn;
  struct prefix_node *n;
  struct ospf_area *oa;
  char *pos;
  int have_dhcp_usp = 1;
  int found = 0;
  int change = 0;

  if (bird_sysevent_get(NULL, "ipv6_delegated_prefix", usable_prefix, USABLE_PREFIX_LENGTH) == -1)
  {
    have_dhcp_usp = 0;
  }
  else if ((pos=strchr(usable_prefix, '/')) != NULL)
  {
    *pos = '\0';
    if(ip_pton(usable_prefix, &pxn.px.addr))
    {
      pxn.px.len = atoi(pos + 1);
      pxn.type = OSPF_USP_T_DHCPV6;
    }
    else have_dhcp_usp = 0;
  }
  else have_dhcp_usp = 0;

  // update usp_list entries of type DHCPV6
  WALK_LIST(n, po->usp_list)
  {
    if(n->type == OSPF_USP_T_DHCPV6)
    {
      if(!have_dhcp_usp || !ipa_equal(n->px.addr, pxn.px.addr) || n->px.len != pxn.px.len)
      {
        // remove this node
        OSPF_TRACE(D_EVENTS, "Removing DHCPv6 prefix: %I/%d", n->px.addr, n->px.len);
        rem_node(NODE n);
        mb_free(n);
        change = 1;
      }
      else found = 1;
    }
  }
  if(have_dhcp_usp && !found)
  {
    OSPF_TRACE(D_EVENTS, "Found new DHCPv6 prefix: %I/%d", pxn.px.addr, pxn.px.len);
    ospf_usp_add(po, &pxn);
    change = 1;
  }
  if(change)
  {
    WALK_LIST(oa, po->area_list)
      schedule_ac_lsa(oa);
  }
#endif /* ENABLE_SYSEVENT */
  return 0;
}

void
ospf_pxassign_reconfigure_iface(struct ospf_iface *ifa)
{
  struct prefix_node *n;
  struct proto_ospf *po = ifa->oa->po;

  WALK_LIST(n, ifa->asp_list)
  {
    if(n->rid == po->router_id)
    {
      n->pa_priority = ifa->pa_priority;
    }
  }
}
#endif /* OSPFv3 */
