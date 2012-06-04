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
static void *
find_next_tlv(struct ospf_lsa_ac *lsa, int *offset, unsigned int size, u8 type)
{
  unsigned int bound = size - 4;
  int old_offset;

  u8 *tlv = (u8 *) lsa;
  do {
    old_offset = *offset;
    *offset += LSA_AC_TLV_SPACE(((struct ospf_lsa_ac_tlv *)(tlv + *offset))->length);
    if(((struct ospf_lsa_ac_tlv *)(tlv + old_offset))->type == type)
      return tlv + old_offset;
  }
  while (*offset <= bound);

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
 * assignment_exists - Check if an assignment exists on this interface from a usable prefix
 * @usp: The current usable prefix to check (contains a pointer to current interface)
 */
static int
assignment_exists(struct ospf_usp *usp)
{
  struct ospf_iface *ifa = usp->ifa;
  struct prefix_node *asp;

  WALK_LIST(asp, ifa->asp_list)
  {
    if(net_in_net(asp->px.addr, asp->px.len, usp->px.addr, usp->px.len))
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
     - if failure, increment the last prefix attempted until success,
       or until we realize there are no available prefixes */
  int i;
  for(i=0;i<10;i++){
    random_prefix(pxu, px);
    if(!in_use(px, used))
      return PXCHOOSE_SUCCESS;
  }
  // TODO
  return PXCHOOSE_FAILURE;
}

void
ospf_pxassign(struct proto_ospf *po)
{
  struct proto *p = &po->proto;
  struct ospf_area *oa;

  OSPF_TRACE(D_EVENTS, "Starting prefix assignment algorithm");

  WALK_LIST(oa, po->area_list)
    ospf_pxassign_area(oa);

  po->pxassign = 0;
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
  struct ospf_iface *ifa;
  struct ospf_usp *usp;
  struct ospf_lsa_ac_tlv *tlv;
  struct ospf_lsa_ac_tlv_v_asp *asp;
  struct ospf_neighbor *neigh;
  timer *pxassign_timer;
  ip_addr addr;
  unsigned int len;
  u8 pxopts;
  u16 rest;

  lsa_get_ipv6_prefix((u32 *)cusp, &addr, &len, &pxopts, &rest);

  //OSPF_TRACE(D_EVENTS, "Starting prefix assignment algorithm for prefix %I/%d", ip, pxlen);

  WALK_LIST(ifa, po->iface_list)
  {
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
          p->name, ifa->name, addr, len);
      tm_start(pxassign_timer, PXASSIGN_DELAY);

      /* create a structure to associate the timer, the interface and the usable prefix */
      usp = mb_alloc(ifa->pool, sizeof(struct ospf_usp));
      add_tail(&ifa->usp_list, NODE usp);
      usp->pxassign_timer = pxassign_timer;
      usp->ifa = ifa;
      usp->px.addr = addr;
      usp->px.len = len;

      /* associate timer with interface and usable prefix */
      pxassign_timer->data = usp;

      continue; // next step will be 5.3.5
    }

    /* 5.3.3 */
    WALK_LIST(neigh, ifa->neigh_list)
    {
      if(neigh->state >= NEIGHBOR_EXSTART)
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
              ip_addr neigh_addr;
              unsigned int neigh_len;
              u8 neigh_pxopts;
              u16 neigh_rest;
              lsa_get_ipv6_prefix((u32 *)(asp) + 1, &neigh_addr, &neigh_len, &neigh_pxopts, &neigh_rest);
              if(net_in_net(neigh_addr, neigh_len, addr, len))
              {
                /* a prefix has already been assigned by a neighbor to the link */
                // FIXME do physical prefix assignment
                // FIXME find list of assigned prefixes, keep only highest RID's
                return;
              }
            }
          }
        } while((en = ospf_hash_find_router_ac_lsa_next(en)) != NULL);
      }
    }

    /* 5.3.4 */
    if(is_highest_rid(ifa))
    {
      /* create ospf_usp structure without the timer */
      usp = mb_alloc(ifa->pool, sizeof(struct ospf_usp));
      add_tail(&ifa->usp_list, NODE usp);
      usp->ifa = ifa;
      usp->px.addr = addr;
      usp->px.len = len;

      ospf_pxassign_resp(usp);
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

  /* 5.3.5a */
  init_list(&used);
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

  /* 5.3.5a and three quarters */
  /* FIXME this step doesn't exist in algorithm */
  if(assignment_exists(usp))
    return;

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

      OSPF_TRACE(D_EVENTS, "From prefix %I/%d, chose prefix %I/%d to assign to interface %s", usp->px.addr, usp->px.len, px_tmp.addr, px_tmp.len, ifa->iface->name);
      break;
  }

  /* 5.3.5d */
  schedule_ac_lsa(ifa->oa);
}

void
pxassign_timer_hook(timer *timer)
{
  struct ospf_usp *usp = (struct ospf_usp *) timer->data;

  ospf_pxassign_resp(usp);

  // FIXME destroy timer
}
#endif /* OSPFv3 */
