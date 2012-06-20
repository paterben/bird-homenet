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
 * http://tools.ietf.org/html/draft-arkko-homenet-prefix-assignment-01
 *
 *
 */

#include "ospf.h"
#include <stdlib.h>
#include "sysdep/unix/linksys.h"

#ifdef OSPFv3

/**
 * find_next_tlv - find next TLV of specified type in AC LSA
 * @lsa: A pointer to the beginning of the LSA body
 * @offset: Offset to the beginning of the LSA body to start search
 * (must point to the beginning of a TLV)
 * @size: Size of the LSA body
 * @type: The type of TLV to search for
 *
 * Returns a pointer to the beginning of the next TLV of specified type,
 * or null if there are no more TLVs of that type.
 * Updates @offset to point to the next TLV, or to after the last TLV if
 * there are no more TLVs of the specified type.
 */
void *
find_next_tlv(struct ospf_lsa_ac *lsa, int *offset, unsigned int size, u8 type)
{
  unsigned int bound = size - 4;
  int old_offset;

  u8 *tlv = (u8 *) lsa;
  while(*offset <= bound)
  {
    old_offset = *offset;
    *offset += LSA_AC_TLV_SPACE(((struct ospf_lsa_ac_tlv *)(tlv + *offset))->length);
    if(((struct ospf_lsa_ac_tlv *)(tlv + old_offset))->type == type)
      return tlv + old_offset;
  }

  return NULL;
}

/**
 * is_highest_rid - Determine if we have the highest RID on a link
 * @ifa: The interface on which to perform the check
 */
static int
is_highest_rid(struct ospf_iface *ifa)
{
  struct ospf_neighbor *n;

  WALK_LIST(n, ifa->neigh_list)
  {
    if(n->rid > ifa->oa->po->router_id)
      return 0;
  }
  return 1;
}

/**
 * assignment_exists_resp - Check if we have already assigned a prefix
 * on this interface from a specified usable prefix
 * @ifa: The current ospf_iface
 * @px: The usable prefix
 */
static int
assignment_exists_resp(struct ospf_iface *ifa, struct prefix *px)
{
  //struct ospf_iface *ifa = usp->ifa;
  struct prefix_node *asp;
  struct proto_ospf *po = ifa->oa->po;

  WALK_LIST(asp, ifa->asp_list)
  {
    if(asp->rid == po->router_id && net_in_net(asp->px.addr, asp->px.len, px->addr, px->len))
      return 1;
  }
  return 0;
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
  if (px->len < 128)
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
 * This function returns 1 if @px is a sub-prefix of any
 * of the prefixes in @used, 0 otherwise.
 */
static int
in_use(struct prefix *px, list used)
{
  struct prefix_node *pxn;

  WALK_LIST(pxn, used){
    if(net_in_net(px->addr, px->len, pxn->px.addr, pxn->px.len))
      return 1;
  }
  return 0;
}

/**
 * next_prefix - Increment prefix to next non-covered prefix
 * @pxa: The prefix to increment
 * @pxb: The covering prefix
 *
 * This function calculates the smallest prefix of length
 * @pxa->length that is not covered by @pxb, and stores it in
 * @pxa. If there is no such prefix, stores IPA_NONE in @pxa->addr.
 */
static void
next_prefix(struct prefix *pxa, struct prefix *pxb)
{
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
         * find one of the used prefixes which contains this prefix
         * increment prefix to the first prefix of correct length that
           is not covered by that used prefix
         * if prefix is no longer in usable prefix range, set to
           lowest prefix of range and set looped to 1
         * if prefix is available, return */
  struct prefix_node *n;
  int looped;
  struct prefix start_prefix;

  int i;
  for(i=0;i<10;i++){
    random_prefix(pxu, px);
    if(!in_use(px, used))
      return PXCHOOSE_SUCCESS;
  }

  looped = 0;
  start_prefix = *px;
  while(looped == 0 || ipa_compare(px->addr, start_prefix.addr) < 0)
  {
    WALK_LIST(n, used)
    {
      if(net_in_net(px->addr, px->len, n->px.addr, n->px.len))
      {
        next_prefix(px, &n->px);
        break;
      }
    }

    if(!net_in_net(px->addr, px->len, pxu->addr, pxu->len))
    {
      px->addr = pxu->addr;
      looped = 1;
    }

    if(!in_use(px, used))
      return PXCHOOSE_SUCCESS;
  }

  return PXCHOOSE_FAILURE;
}

void
ospf_pxcr(struct proto_ospf *po)
{
  struct proto *p = &po->proto;
  struct ospf_area *oa;

  OSPF_TRACE(D_EVENTS, "Starting prefix collision recovery algorithm");

  WALK_LIST(oa, po->area_list)
  {
    // prefix collision recovery algorithm
    int change = ospf_pxcr_area(oa);
    if(change)
      schedule_ac_lsa(oa);
  }
}

int
ospf_pxcr_area(struct ospf_area *oa)
{
  //struct proto *p = &oa->po->proto;
  struct top_hash_entry *en;
  struct ospf_lsa_ac_tlv *tlv;
  unsigned int offset;
  unsigned int size;
  int change = 0;

  if((en = ospf_hash_find_ac_lsa_first(oa->po->gr, oa->areaid)) == NULL)
    return 0; /* no LSAs in this area, nothing to do */

  do {
    size = en->lsa.length - sizeof(struct ospf_lsa_header);
    offset = 0;
    while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_ASP)) != NULL)
    {
      change |= ospf_pxcr_asp(oa, (struct ospf_lsa_ac_tlv_v_asp *)(tlv->value), en->lsa.rt);
    }
  } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL);

  return change;
}

int
ospf_pxcr_asp(struct ospf_area *oa, struct ospf_lsa_ac_tlv_v_asp *casp, u32 rid)
{
  struct proto_ospf *po = oa->po;
  struct ospf_iface *ifa;
  struct prefix_node *pxn;
  ip_addr casp_addr;
  unsigned int casp_len;
  u8 casp_pxopts;
  u16 casp_rest;
  int change;

  lsa_get_ipv6_prefix((u32 *)(casp) + 1, &casp_addr, &casp_len, &casp_pxopts, &casp_rest);

  WALK_LIST(ifa, po->iface_list)
  {
    if(ifa->oa == oa)
    {
      WALK_LIST(pxn, ifa->asp_list)
      {
        /* 5.4.1 */
        if(rid == po->router_id)
          return 0;

        /* 5.4.2 */
        if(pxn->rid != po->router_id)
          continue;

        /* 5.4.3 */
        if(ipa_equal(casp_addr, pxn->px.addr) && casp_len == pxn->px.len && rid > po->router_id)
        {
          rem_node(&pxn->n);
          mb_free(pxn);
          change = 1;
        }
      }
    }
  }
  return change;
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
  struct top_hash_entry *en;
  struct ospf_lsa_ac_tlv *tlv;
  unsigned int offset;
  unsigned int size;

  //OSPF_TRACE(D_EVENTS, "Starting prefix assignment algorithm for AC LSAs in area %R", oa->areaid);

  if((en = ospf_hash_find_ac_lsa_first(oa->po->gr, oa->areaid)) == NULL)
    return; /* no LSAs in this area, nothing to do */

  do {
    size = en->lsa.length - sizeof(struct ospf_lsa_header);
    offset = 0;
    while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_USP)) != NULL)
    {
      ospf_pxassign_usp(oa, (struct ospf_lsa_ac_tlv_v_usp *)(tlv->value));
    }
  } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL);
}

/** ospf_pxassign_usp - Main prefix assignment algorithm
 *
 * @oa: The area which the Usable Prefix belongs to
 * @usp: The Current Usable Prefix
 */
void
ospf_pxassign_usp(struct ospf_area *oa, struct ospf_lsa_ac_tlv_v_usp *cusp)
{
  struct top_hash_entry *en;
  struct proto_ospf *po = oa->po;
  struct proto *p = &po->proto;
  //struct ospf_neighbor *neigh;
  struct ospf_iface *ifa, *ifa2;
  struct ospf_usp *usp;
  struct ospf_lsa_ac_tlv *tlv;
  struct ospf_lsa_ac_tlv_v_usp *usp2;
  struct ospf_lsa_ac_tlv_v_asp *asp;
  struct ospf_neighbor *neigh;
  struct prefix_node *pxn, *n;
  timer *pxassign_timer;
  ip_addr usp_addr, usp2_addr, neigh_addr, neigh_r_addr;
  unsigned int usp_len, usp2_len, neigh_len, neigh_r_len;
  u8 usp_pxopts, usp2_pxopts, neigh_pxopts;
  u16 usp_rest, usp2_rest, neigh_rest;

  lsa_get_ipv6_prefix((u32 *)cusp, &usp_addr, &usp_len, &usp_pxopts, &usp_rest);

  //OSPF_TRACE(D_EVENTS, "Starting prefix assignment algorithm for prefix %I/%d", ip, pxlen);

  WALK_LIST(ifa, po->iface_list)
  {
    /* 5.3.0 */
    if((en = ospf_hash_find_ac_lsa_first(oa->po->gr, oa->areaid)) != NULL)
    {
      unsigned int offset;
      unsigned int size;
      do {
        size = en->lsa.length - sizeof(struct ospf_lsa_header);
        offset = 0;
        while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_USP)) != NULL)
        {
          usp2 = (struct ospf_lsa_ac_tlv_v_usp *)(tlv->value);
          lsa_get_ipv6_prefix((u32 *)usp2, &usp2_addr, &usp2_len, &usp2_pxopts, &usp2_rest);
          if(net_in_net(usp_addr, usp_len, usp2_addr, usp2_len))
            return;
        }
      } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL);
    }

    /* 5.3.1 */
    /* FIXME I think the draft should say "adjacent routers" (state >= ExStart), that's what I suppose */
    byte have_neigh = 0;
    WALK_LIST(neigh, ifa->neigh_list)
    {
      if(neigh->state >= NEIGHBOR_EXSTART)
        have_neigh = 1;
    }

    /* 5.3.2 */
    if(!have_neigh)
    {
      /* create a new timer */
      pxassign_timer = tm_new(p->pool);
      pxassign_timer->randomize = 0;
      pxassign_timer->hook = pxassign_timer_hook;
      pxassign_timer->recurrent = 0;
      DBG("%s: Installing prefix assignment timer for interface %s, usable prefix %I/%d.\n",
          p->name, ifa->name, usp_addr, usp_len);
      tm_start(pxassign_timer, PXASSIGN_DELAY);

      /* create a structure to associate the timer, the interface and the usable prefix */
      usp = mb_alloc(ifa->pool, sizeof(struct ospf_usp));
      add_tail(&ifa->usp_list, NODE usp);
      usp->pxassign_timer = pxassign_timer;
      usp->ifa = ifa;
      usp->px.addr = usp_addr;
      usp->px.len = usp_len;

      /* associate timer with interface and usable prefix */
      pxassign_timer->data = usp;

      continue; // next step will be 5.3.5
    }

    /* 5.3.3 */
    byte assignment_found = 0;
    u32 neigh_rid = 0;
    WALK_LIST(neigh, ifa->neigh_list)
    {
      if(neigh->rid > neigh_rid && neigh->state >= NEIGHBOR_EXSTART) //highest rid takes precedence
      {
        if((en = ospf_hash_find_router_ac_lsa_first(oa->po->gr, oa->areaid, neigh->rid)) == NULL)
          continue; /* no AC LSAs emitted by neighor, nothing to do */

        do {
          unsigned int size = en->lsa.length - sizeof(struct ospf_lsa_header);
          unsigned int offset = 0;

          while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_ASP)) != NULL)
          {
            asp = (struct ospf_lsa_ac_tlv_v_asp *)(tlv->value);
            if(asp->id == neigh->iface_id)
            {
              lsa_get_ipv6_prefix((u32 *)(asp) + 1, &neigh_addr, &neigh_len, &neigh_pxopts, &neigh_rest);
              if(net_in_net(neigh_addr, neigh_len, usp_addr, usp_len))
              {
                /* a prefix has already been assigned by a neighbor to the link */
                /* we're not sure it is responsible for the link yet, so we store
                   the assigned prefix and keep looking at other neighbors with higher RID */
                neigh_r_addr = neigh_addr;
                neigh_r_len = neigh_len;
                neigh_rid = neigh->rid;
                assignment_found = 1;
              }
            }
            if(assignment_found) { break; }
          }
          if(assignment_found) { break; }
        } while((en = ospf_hash_find_router_ac_lsa_next(en)) != NULL);
      }
    }

    /* 5.3.3bis */
    /* FIXME this step doesn't exist in algorithm */
    if(po->router_id > neigh_rid)
    {
      struct prefix px;
      px.addr = usp_addr;
      px.len = usp_len;
      if(assignment_exists_resp(ifa, &px))
        continue; // go to next interface
    }

    /* 5.3.3ter */
    /* FIXME this step doesn't exist in algorithm */
    if(assignment_found)
    {
      //struct prefix px;
      //px.addr = usp_addr;
      //px.len = usp_len;
      int found = 0; // whether assignment is already in the ifa's asp_list
      int change = 0; // whether we must reoriginate our AC LSA
      WALK_LIST(ifa2, po->iface_list)
      {
        WALK_LIST(n,ifa2->asp_list)
        {
          if(net_in_net(n->px.addr, n->px.len, usp_addr, usp_len))
          {
            /* search for self-assigned prefixes from this usp, delete the following:
               - same assigned prefix
               - same interface
               if deletion, re-originate AC LSA */
            if(n->rid == po->router_id &&
               (ifa == ifa2 || (ipa_equal(n->px.addr, neigh_r_addr) && n->px.len == neigh_r_len)))
            {
              change = 1;
              rem_node(&n->n);
              mb_free(n);
              // FIXME timeout address?
            }

            /* search for non-self-assigned prefixes from this usp, delete the following:
               - same assigned prefix, different interface
               - same assigned prefix, different router
               - different assigned prefix, same interface */
            if(n->rid != po->router_id)
            {
              if(ipa_equal(n->px.addr, neigh_r_addr) && n->px.len == neigh_r_len)
              {
                if(ifa != ifa2 || n->rid != neigh_rid)
                {
                  rem_node(&n->n);
                  mb_free(n);
                  // FIXME timeout address?
                }
                else
                  found = 1;
              }
              if((!ipa_equal(n->px.addr, neigh_r_addr) || n->px.len != neigh_r_len) && ifa == ifa2)
              {
                  rem_node(&n->n);
                  mb_free(n);
                  // FIXME timeout address?
              }
            }
          }
        }
      }

      /* 5.3.3quater */
      /* FIXME this step doesn't exist in algorithm */
      if(!found)
      {
        pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
        pxn->px.addr = neigh_r_addr;
        pxn->px.len = neigh_r_len;
        pxn->rid = neigh_rid;
        add_tail(&ifa->asp_list, NODE pxn);
        // FIXME do physical prefix assignment
      }

      /* 5.3.3quinquies */
      /* FIXME this step doesn't exist in algorithm */
      if(change)
        schedule_ac_lsa(ifa->oa);
      continue; // go to next interface
    }

    /* 5.3.4 */
    if(is_highest_rid(ifa))
    {
      /* create ospf_usp structure without the timer */
      usp = mb_alloc(ifa->pool, sizeof(struct ospf_usp));
      add_tail(&ifa->usp_list, NODE usp);
      usp->ifa = ifa;
      usp->px.addr = usp_addr;
      usp->px.len = usp_len;

      ospf_pxassign_resp(usp);
      rem_node(NODE usp);
      mb_free(usp);
    }
  }
}

/** ospf_pxassign_resp - Step 5 of prefix assignment algorithm
 *
 * @usp: The tuple representing the Current Usable Prefix, interface,
 * and timer from step 2 of the prefix assignment algorithm
 *
 * In this step of the algorithm, we know we are responsible for
 * assigning a prefix from the Current Usable Prefix to the interface,
 * and it is time to do it.
 */
void
ospf_pxassign_resp(struct ospf_usp *usp)
{
  struct ospf_iface *ifa = usp->ifa;
  struct ospf_iface *ifan;
  struct proto_ospf *po = ifa->oa->po;
  struct proto *p = &po->proto;
  struct ospf_area *oa;
  struct top_hash_entry *en;
  struct ospf_lsa_ac_tlv *tlv;
  struct ospf_lsa_ac_tlv_v_asp *asp;
  struct prefix px_tmp;
  struct prefix_node *n, *pxn;
  list used; /* list of struct prefix_node */

  DBG("%s: I am responsible router for interface %d and USP %I/%d.\n",
          p->name, ifa->iface->name, usp->px.addr, usp->px.len);

  init_list(&used);

  /* 5.3.5alpha */
  /* FIXME this step doesn't exist in algorithm */
  if(assignment_exists_resp(ifa, &usp->px))
    goto finish;

  /* 5.3.5a */
  WALK_LIST(oa, po->area_list)
  {
    if((en = ospf_hash_find_ac_lsa_first(oa->po->gr, oa->areaid)) == NULL)
      continue; /* no LSAs in this area, nothing to do */

    do {
      ip_addr addr;
      unsigned int len;
      u8 pxopts;
      u16 rest;
      unsigned int size = en->lsa.length - sizeof(struct ospf_lsa_header);
      unsigned int offset = 0;

      while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_ASP)) != NULL)
      {

        /* test if assigned prefix is part of current usable prefix */
        asp = (struct ospf_lsa_ac_tlv_v_asp *)(tlv->value);
        lsa_get_ipv6_prefix((u32 *)(asp) + 1, &addr, &len, &pxopts, &rest);
        if(net_in_net(addr, len, usp->px.addr, usp->px.len))
        {
          /* add prefix to list of used prefixes */
          pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
          add_tail(&used, NODE pxn);
          pxn->px.addr = addr;
          pxn->px.len = len;
        }
      }
    } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL);
  }

  /* we also check our own interfaces for assigned prefixes which have not yet had time
     to be inserted in LSADB. Alternative would be to originate AC LSA immediately
     in step 5.3.5d instead of simply scheduling origination. */
  WALK_LIST(ifan, po->iface_list)
  {
    WALK_LIST(n, ifan->asp_list)
    {
      if(net_in_net(n->px.addr, n->px.len, usp->px.addr, usp->px.len))
      {
        /* add prefix to list of used prefixes */
        pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
        add_tail(&used, NODE pxn);
        pxn->px.addr = n->px.addr;
        pxn->px.len = n->px.len;
      }
    }
  }

  /* 5.3.5b */
  /* FIXME implement 5.3.5b */

  /* 5.3.5c */
  px_tmp.addr = IPA_NONE;
  px_tmp.len = LSA_AC_ASP_MAX_PREFIX_LENGTH;
  switch(choose_prefix(&usp->px, &px_tmp, used))
  {
    case PXCHOOSE_FAILURE:
      log(L_WARN "%s: No prefixes left to assign to interface %s from prefix %I/%d.", p->name, ifa->iface->name, usp->px.addr, usp->px.len);
      break;
    case PXCHOOSE_SUCCESS:
      //FIXME do prefix assignment!
      pxn = mb_alloc(ifa->pool, sizeof(struct prefix_node));
      add_tail(&ifa->asp_list, NODE pxn);
      pxn->px.addr = px_tmp.addr;
      pxn->px.len = px_tmp.len;
      pxn->rid = po->router_id;

      OSPF_TRACE(D_EVENTS, "From prefix %I/%d, chose prefix %I/%d to assign to interface %s", usp->px.addr, usp->px.len, px_tmp.addr, px_tmp.len, ifa->iface->name);
      break;
  }

  /* 5.3.5d */
  schedule_ac_lsa(ifa->oa);

  /* when we are finished, we must remove usp from the interface's usp_list
     as well as free up the memory taken by the usp.
     If a timer was allocated, the pxassign_timer_hook function will take
     care of freeing it.
     We must also free up all elements from the used list. */
  finish:
  WALK_LIST_DELSAFE(n, pxn, used)
  {
    rem_node(NODE n);
    mb_free(n);
  }
}

void
pxassign_timer_hook(timer *timer)
{
  struct ospf_usp *usp = (struct ospf_usp *) timer->data;

  ospf_pxassign_resp(usp);
  rem_node(NODE usp);
  mb_free(usp);
  rfree(timer);
}

#define USABLE_PREFIX_LENGTH (STD_ADDRESS_P_LENGTH + 4) /* 39 for IPv6 address, 4 for /length */
static char usable_prefix[USABLE_PREFIX_LENGTH];

int
update_dhcpv6_usable_prefix(struct proto_ospf *po)
{
  struct proto *p = &po->proto;
  struct prefix_node pxn;
  struct prefix_node *n;
  struct ospf_area *oa;
  char *pos;
  int have_dhcp_usp = 1;
  int found = 0;
  int change = 0;

#ifdef ENABLE_SYSEVENT
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
#endif /* OSPFv3 */
