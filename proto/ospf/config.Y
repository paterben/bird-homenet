/*
 *	BIRD -- OSPF Configuration
 *
 *	(c) 1999--2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/ospf/ospf.h"

CF_DEFINES

#define OSPF_CFG ((struct ospf_config *) this_proto)
#define OSPF_PATT ((struct ospf_iface_patt *) this_ipatt)

static struct ospf_area_config *this_area;
static struct nbma_node *this_nbma;
static list *this_nets;
static struct area_net_config *this_pref;
static struct ospf_stubnet_config *this_stubnet;
static struct prefix_node *this_usp;

#ifdef OSPFv2
static void
ospf_iface_finish(void)
{
  struct ospf_iface_patt *ip = OSPF_PATT;

  if (ip->deadint == 0)
    ip->deadint = ip->deadc * ip->helloint;

  ip->passwords = get_passwords();

  if ((ip->autype == OSPF_AUTH_CRYPT) && (ip->helloint < 5))
    log(L_WARN "Hello or poll interval less that 5 makes cryptographic authenication prone to replay attacks");

  if ((ip->autype == OSPF_AUTH_NONE) && (ip->passwords != NULL))
    log(L_WARN "Password option without authentication option does not make sense");
}
#endif

#ifdef OSPFv3
static void
ospf_iface_finish(void)
{
  struct ospf_iface_patt *ip = OSPF_PATT;

  if (ip->deadint == 0)
    ip->deadint = ip->deadc * ip->helloint;

  if ((ip->autype != OSPF_AUTH_NONE) || (get_passwords() != NULL))
    cf_error("Authentication not supported in OSPFv3");
}
#endif

static void
ospf_area_finish(void)
{
  if ((this_area->areaid == 0) && (this_area->type != OPT_E))
    cf_error("Backbone area cannot be stub/NSSA");

  if (this_area->summary && (this_area->type == OPT_E))
    cf_error("Only Stub/NSSA areas can use summary propagation");

  if (this_area->default_nssa && ((this_area->type != OPT_N) || ! this_area->summary))
    cf_error("Only NSSA areas with summary propagation can use NSSA default route");

  if ((this_area->default_cost & LSA_EXT_EBIT) && ! this_area->default_nssa)
    cf_error("Only NSSA default route can use type 2 metric");
}

static void
ospf_proto_start(int class)
{
  this_proto = proto_config_new(&proto_ospf, sizeof(struct ospf_config), class);
  init_list(&OSPF_CFG->area_list);
  init_list(&OSPF_CFG->vlink_list);
  OSPF_CFG->rfc1583 = DEFAULT_RFC1583;
  OSPF_CFG->tick = DEFAULT_OSPFTICK;
#ifdef OSPFv3
  OSPF_CFG->dridd = DEFAULT_OSPFDRIDD;
  OSPF_CFG->pxassignment = DEFAULT_OSPFPXASSIGNMENT;
  init_list(&OSPF_CFG->usp_list);
#endif
}

static void
ospf_proto_finish(void)
{
  struct ospf_config *cf = OSPF_CFG;

  if (EMPTY_LIST(cf->area_list))
    cf_error( "No configured areas in OSPF");

  int areano = 0;
  int backbone = 0;
  struct ospf_area_config *ac;
  WALK_LIST(ac, cf->area_list)
  {
    areano++;
    if (ac->areaid == 0)
     backbone = 1;
  }
  cf->abr = areano > 1;

  if (cf->abr && !backbone)
  {
    struct ospf_area_config *ac = cfg_allocz(sizeof(struct ospf_area_config));
    add_head(&cf->area_list, NODE ac);
    init_list(&ac->patt_list);
    init_list(&ac->net_list);
    init_list(&ac->enet_list);
    init_list(&ac->stubnet_list);
  }

  if (!cf->abr && !EMPTY_LIST(cf->vlink_list))
    cf_error( "Vlinks cannot be used on single area router");

}

static void
ospf_pxassignment_start(int b)
{
#ifdef OSPFv3
  OSPF_CFG->pxassignment = b;
#else /* OSPFv2 */
  cf_error( "Prefix assignment can only be used with IPv6");
#endif
}

static void
ospf_pxassignment_finish(void)
{
  /* FIXME tests needed? */
}

static void
ospf_dridd_start(int b)
{
#ifdef OSPFv3
  OSPF_CFG->dridd = b;
#else /* OSPFv2 */
  cf_error( "Duplicate Router ID detection can only be used with IPv6");
#endif
}

static void
ospf_dridd_finish(void)
{
  /* FIXME tests needed? */
}

static void
ospf_usp_start(void)
{
#ifdef OSPFv3
  /* anything to do? */
#else /* OSPFv2 */
  cf_error( "Usable prefixes can only be specified with IPv6");
#endif
}

static void
ospf_usp_finish(void)
{
  /* FIXME tests needed? */
}

static void
ospf_usp_add_manual(struct prefix px)
{
  if(px.len < LSA_AC_USP_MIN_PREFIX_LENGTH || px.len > LSA_AC_USP_MAX_PREFIX_LENGTH)
    cf_error( "Usable prefixes must be longer than %d \
               bits and shorter than %d bits",
               LSA_AC_USP_MIN_PREFIX_LENGTH, LSA_AC_USP_MAX_PREFIX_LENGTH);
  this_usp = cfg_allocz(sizeof(struct prefix_node));
  add_tail(&OSPF_CFG->usp_list, NODE this_usp);
  this_usp->px.addr = px.addr;
  this_usp->px.len = px.len;
  this_usp->type = OSPF_USP_T_MANUAL;
}

static inline void
check_defcost(int cost)
{
  if ((cost <= 0) || (cost >= LSINFINITY))
   cf_error("Default cost must be in range 1-%d", LSINFINITY-1);
}

static inline void
set_instance_id(unsigned id)
{
#ifdef OSPFv3
  OSPF_PATT->instance_id = id;
#else
  cf_error("Instance ID requires OSPFv3");
#endif
}

static inline void
set_pa_priority(unsigned p)
{
#ifdef OSPFv3
  OSPF_PATT->pa_priority = p;
  if(p < 1 || p > 255) cf_error("Prefix assignment priority must be in range 1-255");
#else
  cf_error("Prefix assignment priority requires OSPFv3");
#endif
}

static inline void
set_pa_pxlen(unsigned p)
{
#ifdef OSPFv3
  OSPF_PATT->pa_pxlen = p;
  if(p != PA_PXLEN_D && p != PA_PXLEN_SUB) cf_error("Prefix assignment length must be %d or %d", PA_PXLEN_D, PA_PXLEN_SUB);
#else
  cf_error("Prefix assignment length requires OSPFv3");
#endif
}

CF_DECLS

CF_KEYWORDS(OSPF, AREA, OSPF_METRIC1, OSPF_METRIC2, OSPF_TAG, OSPF_ROUTER_ID)
CF_KEYWORDS(NEIGHBORS, RFC1583COMPAT, STUB, TICK, COST, COST2, RETRANSMIT)
CF_KEYWORDS(HELLO, TRANSMIT, PRIORITY, DEAD, TYPE, BROADCAST, BCAST)
CF_KEYWORDS(NONBROADCAST, NBMA, POINTOPOINT, PTP, POINTOMULTIPOINT, PTMP)
CF_KEYWORDS(NONE, SIMPLE, AUTHENTICATION, STRICT, CRYPTOGRAPHIC)
CF_KEYWORDS(ELIGIBLE, POLL, NETWORKS, HIDDEN, VIRTUAL, CHECK, LINK)
CF_KEYWORDS(RX, BUFFER, LARGE, NORMAL, STUBNET, HIDDEN, SUMMARY, TAG, EXTERNAL)
CF_KEYWORDS(WAIT, DELAY, LSADB, ECMP, LIMIT, WEIGHT, NSSA, TRANSLATOR, STABILITY)
CF_KEYWORDS(GLOBAL, LSID, ROUTER, SELF, INSTANCE, REAL)
CF_KEYWORDS(DUPLICATE, RID, DETECTION, USABLEPREFIX, ASSIGNMENT, LENGTH)

%type <t> opttext
%type <ld> lsadb_args
%type <g> pxassign_file

CF_GRAMMAR

CF_ADDTO(proto, ospf_proto '}' { ospf_proto_finish(); } )

ospf_proto_start: proto_start OSPF { ospf_proto_start($1) }
 ;

ospf_proto:
   ospf_proto_start proto_name '{'
 | ospf_proto ospf_proto_item ';'
 ;

ospf_proto_item:
   proto_item
 | RFC1583COMPAT bool { OSPF_CFG->rfc1583 = $2; }
 | ospf_dridd
 | ospf_pxassignment
 | remember_pxassign
 | ospf_usp
 | ECMP bool { OSPF_CFG->ecmp = $2 ? DEFAULT_ECMP_LIMIT : 0; }
 | ECMP bool LIMIT expr { OSPF_CFG->ecmp = $2 ? $4 : 0; if ($4 < 0) cf_error("ECMP limit cannot be negative"); }
 | TICK expr { OSPF_CFG->tick = $2; if($2<=0) cf_error("Tick must be greater than zero"); }
 | ospf_area
 ;

ospf_area_start: AREA idval {
  this_area = cfg_allocz(sizeof(struct ospf_area_config));
  add_tail(&OSPF_CFG->area_list, NODE this_area);
  this_area->areaid = $2;
  this_area->default_cost = DEFAULT_STUB_COST;
  this_area->type = OPT_E;
  this_area->transint = DEFAULT_TRANSINT;

  init_list(&this_area->patt_list);
  init_list(&this_area->net_list);
  init_list(&this_area->enet_list);
  init_list(&this_area->stubnet_list);
 }
 ;

ospf_area: ospf_area_start '{' ospf_area_opts '}' { ospf_area_finish(); }
 ;

ospf_area_opts:
   /* empty */
 | ospf_area_opts ospf_area_item ';'
 ;

ospf_area_item:
   STUB bool { this_area->type = $2 ? 0 : OPT_E; /* We should remove the option */ }
 | NSSA { this_area->type = OPT_N; }
 | SUMMARY bool { this_area->summary = $2; }
 | DEFAULT NSSA bool { this_area->default_nssa = $3; }
 | DEFAULT COST expr { this_area->default_cost = $3; check_defcost($3); }
 | DEFAULT COST2 expr { this_area->default_cost = $3 | LSA_EXT_EBIT; check_defcost($3); }
 | STUB COST expr { this_area->default_cost = $3;  check_defcost($3); }
 | TRANSLATOR bool { this_area->translator = $2; }
 | TRANSLATOR STABILITY expr { this_area->transint = $3; }
 | NETWORKS { this_nets = &this_area->net_list; } '{' pref_list '}'
 | EXTERNAL { this_nets = &this_area->enet_list; } '{' pref_list '}'
 | STUBNET ospf_stubnet
 | INTERFACE ospf_iface
 | ospf_vlink
 ;

ospf_stubnet:
   ospf_stubnet_start '{' ospf_stubnet_opts '}'
 | ospf_stubnet_start
 ;

ospf_stubnet_start:
   prefix {
     this_stubnet = cfg_allocz(sizeof(struct ospf_stubnet_config));
     add_tail(&this_area->stubnet_list, NODE this_stubnet);
     this_stubnet->px = $1;
     this_stubnet->cost = COST_D;
   }
 ;

ospf_stubnet_opts:
   /* empty */
 | ospf_stubnet_opts ospf_stubnet_item ';'
 ;

ospf_stubnet_item:
   HIDDEN bool { this_stubnet->hidden = $2; }
 | SUMMARY bool { this_stubnet->summary = $2; }
 | COST expr { this_stubnet->cost = $2; }
 ;

ospf_vlink:
   ospf_vlink_start ospf_instance_id '{' ospf_vlink_opts '}' { ospf_iface_finish(); }
 | ospf_vlink_start ospf_instance_id { ospf_iface_finish(); }
 ;

ospf_vlink_opts:
   /* empty */
 | ospf_vlink_opts ospf_vlink_item ';'
 ;

ospf_vlink_item:
 | HELLO expr { OSPF_PATT->helloint = $2 ; if (($2<=0) || ($2>65535)) cf_error("Hello interval must be in range 1-65535"); }
 | RETRANSMIT expr { OSPF_PATT->rxmtint = $2 ; if ($2<=0) cf_error("Retransmit int must be greater than zero"); }
 | TRANSMIT DELAY expr { OSPF_PATT->inftransdelay = $3 ; if (($3<=0) || ($3>65535)) cf_error("Transmit delay must be in range 1-65535"); }
 | WAIT expr { OSPF_PATT->waitint = $2 ; }
 | DEAD expr { OSPF_PATT->deadint = $2 ; if ($2<=1) cf_error("Dead interval must be greater than one"); }
 | DEAD COUNT expr { OSPF_PATT->deadc = $3 ; if ($3<=1) cf_error("Dead count must be greater than one"); }
 | AUTHENTICATION NONE { OSPF_PATT->autype = OSPF_AUTH_NONE ; }
 | AUTHENTICATION SIMPLE { OSPF_PATT->autype = OSPF_AUTH_SIMPLE ; }
 | AUTHENTICATION CRYPTOGRAPHIC { OSPF_PATT->autype = OSPF_AUTH_CRYPT ; }
 | password_list
 ;

ospf_vlink_start: VIRTUAL LINK idval
 {
  if (this_area->areaid == 0) cf_error("Virtual link cannot be in backbone");
  this_ipatt = cfg_allocz(sizeof(struct ospf_iface_patt));
  add_tail(&OSPF_CFG->vlink_list, NODE this_ipatt);
  init_list(&this_ipatt->ipn_list);
  OSPF_PATT->voa = this_area->areaid;
  OSPF_PATT->vid = $3;
  OSPF_PATT->helloint = HELLOINT_D;
  OSPF_PATT->rxmtint = RXMTINT_D;
  OSPF_PATT->inftransdelay = INFTRANSDELAY_D;
  OSPF_PATT->waitint = WAIT_DMH*HELLOINT_D;
  OSPF_PATT->deadc = DEADC_D;
  OSPF_PATT->deadint = 0;
  OSPF_PATT->type = OSPF_IT_VLINK;
  init_list(&OSPF_PATT->nbma_list);
  OSPF_PATT->autype = OSPF_AUTH_NONE;
  reset_passwords();
 }
;

ospf_iface_item:
   COST expr { OSPF_PATT->cost = $2 ; if (($2<=0) || ($2>65535)) cf_error("Cost must be in range 1-65535"); }
 | HELLO expr { OSPF_PATT->helloint = $2 ; if (($2<=0) || ($2>65535)) cf_error("Hello interval must be in range 1-65535"); }
 | POLL expr { OSPF_PATT->pollint = $2 ; if ($2<=0) cf_error("Poll int must be greater than zero"); }
 | RETRANSMIT expr { OSPF_PATT->rxmtint = $2 ; if ($2<=0) cf_error("Retransmit int must be greater than zero"); }
 | WAIT expr { OSPF_PATT->waitint = $2 ; }
 | DEAD expr { OSPF_PATT->deadint = $2 ; if ($2<=1) cf_error("Dead interval must be greater than one"); }
 | DEAD COUNT expr { OSPF_PATT->deadc = $3 ; if ($3<=1) cf_error("Dead count must be greater than one"); }
 | TYPE BROADCAST { OSPF_PATT->type = OSPF_IT_BCAST ; }
 | TYPE BCAST { OSPF_PATT->type = OSPF_IT_BCAST ; }
 | TYPE NONBROADCAST { OSPF_PATT->type = OSPF_IT_NBMA ; }
 | TYPE NBMA { OSPF_PATT->type = OSPF_IT_NBMA ; }
 | TYPE POINTOPOINT { OSPF_PATT->type = OSPF_IT_PTP ; }
 | TYPE PTP { OSPF_PATT->type = OSPF_IT_PTP ; }
 | TYPE POINTOMULTIPOINT { OSPF_PATT->type = OSPF_IT_PTMP ; }
 | TYPE PTMP { OSPF_PATT->type = OSPF_IT_PTMP ; }
 | REAL BROADCAST bool { OSPF_PATT->real_bcast = $3; if (OSPF_VERSION != 2) cf_error("Real broadcast option requires OSPFv2"); }
 | TRANSMIT DELAY expr { OSPF_PATT->inftransdelay = $3 ; if (($3<=0) || ($3>65535)) cf_error("Transmit delay must be in range 1-65535"); }
 | PRIORITY expr { OSPF_PATT->priority = $2 ; if (($2<0) || ($2>255)) cf_error("Priority must be in range 0-255"); }
 | STRICT NONBROADCAST bool { OSPF_PATT->strictnbma = $3 ; }
 | STUB bool { OSPF_PATT->stub = $2 ; }
 | CHECK LINK bool { OSPF_PATT->check_link = $3; }
 | ECMP WEIGHT expr { OSPF_PATT->ecmp_weight = $3 - 1; if (($3<1) || ($3>256)) cf_error("ECMP weight must be in range 1-256"); }
 | NEIGHBORS '{' ipa_list '}'
 | AUTHENTICATION NONE { OSPF_PATT->autype = OSPF_AUTH_NONE ; }
 | AUTHENTICATION SIMPLE { OSPF_PATT->autype = OSPF_AUTH_SIMPLE ; }
 | AUTHENTICATION CRYPTOGRAPHIC { OSPF_PATT->autype = OSPF_AUTH_CRYPT ; }
 | RX BUFFER LARGE { OSPF_PATT->rxbuf = OSPF_RXBUF_LARGE ; }
 | RX BUFFER NORMAL { OSPF_PATT->rxbuf = OSPF_RXBUF_NORMAL ; }
 | RX BUFFER expr { OSPF_PATT->rxbuf = $3 ; if (($3 < OSPF_RXBUF_MINSIZE) || ($3 > OSPF_MAX_PKT_SIZE)) cf_error("Buffer size must be in range 256-65535"); }
 | password_list
 | PREFIX ASSIGNMENT PRIORITY expr { set_pa_priority($4); }
 | PREFIX ASSIGNMENT LENGTH expr { set_pa_pxlen($4); }
 ;

pref_list:
 /* empty */
 | pref_list pref_item
 ;

pref_item: pref_base pref_opt ';' ;

pref_base: prefix
 {
   this_pref = cfg_allocz(sizeof(struct area_net_config));
   add_tail(this_nets, NODE this_pref);
   this_pref->px.addr = $1.addr;
   this_pref->px.len = $1.len;
 }
;

pref_opt:
 /* empty */
 | HIDDEN { this_pref->hidden = 1; }
 | TAG expr { this_pref->tag = $2; }
 ;

ipa_list:
 /* empty */
 | ipa_list ipa_item
 ;

ipa_item:
    ipa_el
  | ipa_ne;

ipa_el: IPA ';'
 {
   this_nbma = cfg_allocz(sizeof(struct nbma_node));
   add_tail(&OSPF_PATT->nbma_list, NODE this_nbma);
   this_nbma->ip=$1;
   this_nbma->eligible=0;
 }
;

ipa_ne: IPA ELIGIBLE ';'
 {
   this_nbma = cfg_allocz(sizeof(struct nbma_node));
   add_tail(&OSPF_PATT->nbma_list, NODE this_nbma);
   this_nbma->ip=$1;
   this_nbma->eligible=1;
 }
;

ospf_iface_start:
 {
  this_ipatt = cfg_allocz(sizeof(struct ospf_iface_patt));
  add_tail(&this_area->patt_list, NODE this_ipatt);
  init_list(&this_ipatt->ipn_list);
  OSPF_PATT->cost = COST_D;
  OSPF_PATT->helloint = HELLOINT_D;
  OSPF_PATT->pollint = POLLINT_D;
  OSPF_PATT->rxmtint = RXMTINT_D;
  OSPF_PATT->inftransdelay = INFTRANSDELAY_D;
  OSPF_PATT->priority = PRIORITY_D;
  OSPF_PATT->pa_priority = PA_PRIORITY_D;
  OSPF_PATT->pa_pxlen = PA_PXLEN_D;
  OSPF_PATT->waitint = WAIT_DMH*HELLOINT_D;
  OSPF_PATT->deadc = DEADC_D;
  OSPF_PATT->deadint = 0;
  OSPF_PATT->type = OSPF_IT_UNDEF;
  init_list(&OSPF_PATT->nbma_list);
  OSPF_PATT->autype = OSPF_AUTH_NONE;
  reset_passwords();
 }
;

ospf_instance_id:
   /* empty */
 | INSTANCE expr { set_instance_id($2); }
 ;

ospf_iface_opts:
   /* empty */
 | ospf_iface_opts ospf_iface_item ';'
 ;

ospf_iface_opt_list:
   /* empty */
 | '{' ospf_iface_opts '}'
 ;

ospf_iface:
  ospf_iface_start iface_patt_list ospf_instance_id ospf_iface_opt_list { ospf_iface_finish(); }
 ;

ospf_pxassignment:
   ospf_pxassignment_start '{' ospf_pxassignment_opts '}' { ospf_pxassignment_finish(); }
 | ospf_pxassignment_start { ospf_pxassignment_finish(); }
 ;

ospf_pxassignment_start: PREFIX ASSIGNMENT bool
 {
  ospf_pxassignment_start($3);
 }
;

ospf_pxassignment_opts:
   /* empty */
 | ospf_pxassignment_opts ospf_pxassignment_item ';'
 ;

ospf_pxassignment_item:
  /* empty for the moment */
;

remember_pxassign: PREFIX ASSIGNMENT REMEMBER pxassign_file
 {
  OSPF_CFG->pxassign_file = $4;
 }
;

pxassign_file: TEXT
 {
#ifdef OSPFv3
  /* no pool available, we will call track_file during ospf_start */
  FILE *f = fopen($1, "r+");
  if (!f)
    f = fopen($1, "w+");
  if (!f)
    cf_error("Unable to open prefix assignment file `%s': %m", $1);
  $$ = f;
#else /*OSPFv2 */
  cf_error( "Prefix assignment can only be used with IPv6");
#endif
 }
;

ospf_dridd:
   ospf_dridd_start '{' ospf_dridd_opts '}' { ospf_dridd_finish(); }
 | ospf_dridd_start { ospf_dridd_finish(); }
 ;

ospf_dridd_start: DUPLICATE RID DETECTION bool
 {
  ospf_dridd_start($4);
 }
;

ospf_dridd_opts:
   /* empty */
 | ospf_dridd_opts ospf_dridd_item ';'
 ;

ospf_dridd_item:
  /* empty for the moment */
;

ospf_usp:
   ospf_usp_start '{' ospf_usp_opts '}' { ospf_usp_finish(); }
 | ospf_usp_start { ospf_usp_finish(); }
 ;

ospf_usp_start: USABLEPREFIX { ospf_usp_start(); }
;

ospf_usp_opts:
   /* empty */
 | ospf_usp_item ospf_usp_opts
 ;

ospf_usp_item: prefix ';' { ospf_usp_add_manual($1); }
;

opttext:
    TEXT
 | /* empty */ { $$ = NULL; }
 ;

CF_ADDTO(dynamic_attr, OSPF_METRIC1 { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_OSPF_METRIC1); })
CF_ADDTO(dynamic_attr, OSPF_METRIC2 { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_OSPF_METRIC2); })
CF_ADDTO(dynamic_attr, OSPF_TAG { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_OSPF_TAG); })
CF_ADDTO(dynamic_attr, OSPF_ROUTER_ID { $$ = f_new_dynamic_attr(EAF_TYPE_ROUTER_ID | EAF_TEMP, T_QUAD, EA_OSPF_ROUTER_ID); })

CF_CLI_HELP(SHOW OSPF, ..., [[Show information about OSPF protocol]]);
CF_CLI(SHOW OSPF, optsym, [<name>], [[Show information about OSPF protocol XXX]])
{ ospf_sh(proto_get_named($3, &proto_ospf)); };

CF_CLI(SHOW OSPF NEIGHBORS, optsym opttext, [<name>] [\"<interface>\"], [[Show information about OSPF neighbors]])
{ ospf_sh_neigh(proto_get_named($4, &proto_ospf), $5); };

CF_CLI(SHOW OSPF USABLE, optsym, [<name>], [[Show information about usable prefixes]])
{ ospf_sh_usp(proto_get_named($4, &proto_ospf)); };

CF_CLI(SHOW OSPF ASSIGNED, optsym, [<name>], [[Show information about assigned prefixes]])
{ ospf_sh_asp(proto_get_named($4, &proto_ospf)); };

CF_CLI(SHOW OSPF PRIORITIES, optsym, [<name>], [[Show information about Interface Prefixes TLVs]])
{ ospf_sh_pa_priorities(proto_get_named($4, &proto_ospf)); };

CF_CLI(SHOW OSPF INTERFACE, optsym opttext, [<name>] [\"<interface>\"], [[Show information about interface]])
{ ospf_sh_iface(proto_get_named($4, &proto_ospf), $5); };

CF_CLI_HELP(SHOW OSPF TOPOLOGY, [all] [<name>], [[Show information about OSPF network topology]])

CF_CLI(SHOW OSPF TOPOLOGY, optsym opttext, [<name>], [[Show information about reachable OSPF network topology]])
{ ospf_sh_state(proto_get_named($4, &proto_ospf), 0, 1); };

CF_CLI(SHOW OSPF TOPOLOGY ALL, optsym opttext, [<name>], [[Show information about all OSPF network topology]])
{ ospf_sh_state(proto_get_named($5, &proto_ospf), 0, 0); };

CF_CLI_HELP(SHOW OSPF STATE, [all] [<name>], [[Show information about OSPF network state]])

CF_CLI(SHOW OSPF STATE, optsym opttext, [<name>], [[Show information about reachable OSPF network state]])
{ ospf_sh_state(proto_get_named($4, &proto_ospf), 1, 1); };

CF_CLI(SHOW OSPF STATE ALL, optsym opttext, [<name>], [[Show information about all OSPF network state]])
{ ospf_sh_state(proto_get_named($5, &proto_ospf), 1, 0); };

CF_CLI_HELP(SHOW OSPF LSADB, ..., [[Show content of OSPF LSA database]]);
CF_CLI(SHOW OSPF LSADB, lsadb_args, [global | area <id> | link] [type <num>] [lsid <id>] [self | router <id>] [<proto>], [[Show content of OSPF LSA database]])
{ ospf_sh_lsadb($4); };

lsadb_args:
   /* empty */ {
     $$ = cfg_allocz(sizeof(struct lsadb_show_data));
   }
 | lsadb_args GLOBAL { $$ = $1; $$->scope = LSA_SCOPE_AS; }
 | lsadb_args AREA idval { $$ = $1; $$->scope = LSA_SCOPE_AREA; $$->area = $3 }
 | lsadb_args LINK { $$ = $1; $$->scope = 1; /* hack, 0 is no filter */ }
 | lsadb_args TYPE NUM { $$ = $1; $$->type = $3; }
 | lsadb_args LSID idval { $$ = $1; $$->lsid = $3; }
 | lsadb_args SELF { $$ = $1; $$->router = SH_ROUTER_SELF; }
 | lsadb_args ROUTER idval { $$ = $1; $$->router = $3; }
 | lsadb_args SYM { $$ = $1; $$->name = $2; }
 ;

CF_CODE

CF_END
