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
static struct ospf_lsa_ac_tlv *
find_next_tlv(struct ospf_lsa_ac *lsa, int *offset, unsigned int size, u8 type)
{
  unsigned int bound = size - 4;
  int old_offset;

  u8 *tlv = (u8 *) lsa;
  do {
    old_offset = *offset;
    *offset += LSA_AC_TLV_SPACE(((struct ospf_lsa_ac_tlv *)(tlv + *offset))->length);
    if(((struct ospf_lsa_ac_tlv *)(tlv + old_offset))->type == type)
      return (struct ospf_lsa_ac_tlv *)(tlv + old_offset);
  }
  while (*offset <= bound);

  return NULL;
}

/**
 * already_assigned - Check if an assignment exists for a usable prefix
 * @usp: The current usable prefix to check (contains a pointer to current interface)
 */
int
already_assigned(struct ospf_usp *usp)
{
  struct ospf_iface *ifa = usp->ifa;
  struct ospf_asp *asp;

  WALK_LIST(asp, ifa->asp_list)
  {
    if(net_in_net(asp->ip, asp->pxlen, usp->ip, usp->pxlen))
      return 1;
  }
  return 0;
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
  struct proto_ospf *po = oa->po;
  struct proto *p = &po->proto;
  //struct ospf_neighbor *neigh;
  struct ospf_iface *ifa;
  struct ospf_usp *usp;
  timer *pxassign_timer;
  ip_addr ip;
  int pxlen;
  u8 pxopts;
  u16 rest;

  lsa_get_ipv6_prefix((u32 *)cusp, &ip, &pxlen, &pxopts, &rest);

  //OSPF_TRACE(D_EVENTS, "Starting prefix assignment algorithm for prefix %I/%d", ip, pxlen);

  WALK_LIST(ifa, po->iface_list)
  {
    /* 5.3.1 */
    /* FIXME I think the draft should say "fully adjacent neighbors", that's what I suppose */
    byte have_neigh = ifa->fadj > 0;

    /* 5.3.2 */
    if(!have_neigh)
    {
      /* create a new timer */
      pxassign_timer = tm_new(p->pool);
      pxassign_timer->randomize = 0;
      pxassign_timer->hook = pxassign_timer_hook;
      pxassign_timer->recurrent = 0;
      DBG("%s: Installing prefix assignment timer for interface %s, usable prefix %I/%d.\n",
          p->name, ifa->name, ip, pxlen);
      tm_start(pxassign_timer, PXASSIGN_DELAY);

      /* create a structure to associate the timer, the interface and the usable prefix */
      usp = mb_alloc(ifa->pool, sizeof(struct ospf_usp));
      add_tail(&ifa->usp_list, NODE usp);
      usp->pxassign_timer = pxassign_timer;
      usp->ifa = ifa;
      usp->ip = ip;
      usp->pxlen = pxlen;

      /* associate timer with interface and usable prefix */
      pxassign_timer->data = usp;

      continue; // next step will be 5.3.5
    }

    /* 5.3.3 */
  }
}

static void
random_prefix(ip_addr *ipu, int pxlenu, int pxlen, ip_addr *ip)
{
  if (pxlenu < 32 && pxlen > 0)
    _I0(*ip) = random_u32();
  if (pxlenu < 64 && pxlen > 32)
    _I1(*ip) = random_u32();
  if (pxlenu < 96 && pxlen > 64)
    _I2(*ip) = random_u32();
  if (pxlenu < 128 && pxlen > 96)
    _I3(*ip) = random_u32();

  // clean up right part of prefix
  if (pxlen < 128)
    ip->addr[pxlen / 32] &= u32_mkmask(pxlen % 32);

  // clean up left part of prefix
  *ip = ipa_and(*ip, ipa_not(ipa_mkmask(pxlenu)));

  // set left part of prefix
  *ip = ipa_or(*ip, *ipu);
}

/**
 * choose_prefix - Choose a prefix from a usable prefix and list of sub-prefixes in use
 * @ipu: The usable prefix
 * @pxlenu: The usable prefix length
 * @pxlen: The length of the prefix to choose
 * @ip: A pointer to the ip_addr to modify
 * @used: The list of sub-prefixes already in use
 *
 * This function stores a unused prefix of specified length from
 * the usable prefix in @ip, and returns PXCHOOSE_SUCCESS,
 * or stores IPA_NONE into @ip and returns PXCHOOSE_FAILURE if
 * all prefixes are in use.
 */
static int
choose_prefix(ip_addr *ipu, int pxlenu, int pxlen, ip_addr *ip, list used)
{
  /* (Stupid) Algorithm:
     - try a random prefix until success or 10 attempts have passed
     - if failure, increment the last prefix attempted until success,
       or until we realize there are no available prefixes */
  //FIXME TODO
  random_prefix(ipu, pxlenu, pxlen, ip);
  return PXCHOOSE_SUCCESS;
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
  struct proto_ospf *po = ifa->oa->po;
  struct proto *p = &po->proto;
  struct ospf_area *oa;
  struct top_hash_entry *en;
  struct ospf_lsa_ac_tlv *tlv;
  struct ospf_lsa_ac_tlv_v_asp *asp;
  struct ospf_asp *self_asp;
  list used; /* list of struct prefix_node */
  unsigned int offset;
  unsigned int size;
  ip_addr ip;
  int pxlen;
  u8 pxopts;
  u16 rest;

  DBG("%s: I am responsible router for interface %d and USP %I/%d.\n",
          p->name, ifa->name, ip, pxlen);

  /* 5.3.5a */
  init_list(&used);
  WALK_LIST(oa, po->area_list)
  {
    if((en = ospf_hash_find_ac_lsa_first(oa->po->gr, oa->areaid)) == NULL)
      continue; /* no LSAs in this area, nothing to do */

    do {
      size = en->lsa.length - sizeof(struct ospf_lsa_header);
      offset = 0;
      while((tlv = find_next_tlv(en->lsa_body, &offset, size, LSA_AC_TLV_T_ASP)) != NULL)
      {
        /* test if assigned prefix is part of current usable prefix */
        asp = (struct ospf_lsa_ac_tlv_v_asp *)(tlv->value);
        lsa_get_ipv6_prefix((u32 *)(asp) + 1, &ip, &pxlen, &pxopts, &rest);
        if(net_in_net(ip, pxlen, usp->ip, usp->pxlen))
        {
          /* add prefix to list of used prefixes */
          struct ospf_asp *px = mb_alloc(ifa->pool, sizeof(struct ospf_asp));
          add_tail(&used, NODE px);
          px->ip = ip;
          px->pxlen = pxlen;
        }
      }
    } while((en = ospf_hash_find_ac_lsa_next(en)) != NULL);
  }

  /* 5.3.5a and three quarters */
  /* FIXME this step doesn't exist in algorithm */
  if(already_assigned(usp))
    return;

  /* 5.3.5b */
  /* FIXME implement 5.3.5b */

  /* 5.3.5c */
  ip = IPA_NONE;
  pxlen = LSA_AC_ASP_MAX_PREFIX_LENGTH;
  switch(choose_prefix(&usp->ip, usp->pxlen, pxlen, &ip, used))
  {
    case PXCHOOSE_FAILURE:
      die("No prefixes left to assign.");
      break;
    case PXCHOOSE_SUCCESS:
      //FIXME do prefix assignment!
      self_asp = mb_alloc(ifa->pool, sizeof(struct ospf_asp));
      add_tail(&ifa->asp_list, NODE self_asp);
      self_asp->ip = ip;
      self_asp->pxlen = pxlen;

      OSPF_TRACE(D_EVENTS, "From prefix %I/%d, chose prefix %I/%d to assign to interface %s", usp->ip, usp->pxlen, ip, pxlen, ifa->iface->name);
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
}
#endif /* OSPFv3 */
