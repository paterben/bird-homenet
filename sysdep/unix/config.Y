/*
 *	BIRD -- UNIX Configuration
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "lib/unix.h"
#include <stdio.h>

CF_DECLS

CF_KEYWORDS(LOG, SYSLOG, ALL, DEBUG, TRACE, INFO, REMOTE, WARNING, ERROR, AUTH, FATAL, BUG, STDERR, SOFT)
CF_KEYWORDS(TIMEFORMAT, ISO, SHORT, LONG, BASE, NAME)
CF_KEYWORDS(REMEMBER)

%type <i> log_mask log_mask_list log_cat
%type <g> log_file rid_file
%type <t> cfg_name
%type <tf> timeformat_which
%type <t> syslog_name

CF_GRAMMAR

CF_ADDTO(conf, log_config)

log_config: LOG log_file log_mask ';' {
    struct log_config *c = cfg_allocz(sizeof(struct log_config));
    c->fh = $2;
    c->mask = $3;
    add_tail(&new_config->logfiles, &c->n);
  }
 ;

syslog_name:
   NAME TEXT { $$ = $2; }
 | { $$ = bird_name; }
 ;

log_file:
   TEXT {
     FILE *f = tracked_fopen(new_config->pool, $1, "a");
     if (!f) cf_error("Unable to open log file `%s': %m", $1);
     $$ = f;
   }
 | SYSLOG syslog_name { $$ = NULL; new_config->syslog_name = $2; }
 | STDERR { $$ = stderr; }
 ;

log_mask:
   ALL { $$ = ~0; }
 | '{' log_mask_list '}' { $$ = $2; }
 ;

log_mask_list:
   log_cat { $$ = 1 << $1; }
 | log_mask_list ',' log_cat { $$ = $1 | (1 << $3); }
 ;

log_cat:
   DEBUG { $$ = L_DEBUG[0]; }
 | TRACE { $$ = L_TRACE[0]; }
 | INFO { $$ = L_INFO[0]; }
 | REMOTE { $$ = L_REMOTE[0]; }
 | WARNING { $$ = L_WARN[0]; }
 | ERROR { $$ = L_ERR[0]; }
 | AUTH { $$ = L_AUTH[0]; }
 | FATAL { $$ = L_FATAL[0]; }
 | BUG { $$ = L_BUG[0]; }
 ;

CF_ADDTO(conf, remember_rid)

remember_rid: ROUTER ID REMEMBER rid_file ';'
 {
  new_config->rid_file = $4;
 }
;

rid_file: TEXT
 {
  FILE *f = tracked_fopen(new_config->pool, $1, "r+");
  if (!f)
    f = tracked_fopen(new_config->pool, $1, "w+");
  if (!f)
    cf_error("Unable to open router ID file `%s': %m", $1);
  $$ = f;
 }
;

CF_ADDTO(conf, mrtdump_base)

mrtdump_base:
   MRTDUMP PROTOCOLS mrtdump_mask ';' { new_config->proto_default_mrtdump = $3; }
 | MRTDUMP TEXT ';' {
     FILE *f = tracked_fopen(new_config->pool, $2, "a");
     if (!f) cf_error("Unable to open MRTDump file '%s': %m", $2);
     new_config->mrtdump_file = fileno(f);
   }
 ;

CF_ADDTO(conf, timeformat_base)

timeformat_which:
   ROUTE { $$ = &new_config->tf_route; }
 | PROTOCOL { $$ = &new_config->tf_proto; }
 | BASE { $$ = &new_config->tf_base; }
 | LOG { $$ = &new_config->tf_log; }

timeformat_spec:
   timeformat_which TEXT { *$1 = (struct timeformat){$2, NULL, 0}; }
 | timeformat_which TEXT expr TEXT { *$1 = (struct timeformat){$2, $4, $3}; }
 | timeformat_which ISO SHORT { *$1 = (struct timeformat){"%T", "%F", 20*3600}; }
 | timeformat_which ISO LONG  { *$1 = (struct timeformat){"%F %T", NULL, 0}; }
 ;

timeformat_base:
   TIMEFORMAT timeformat_spec ';'
 ;

/* Unix specific commands */

CF_CLI_HELP(CONFIGURE, [soft] [\"<file>\"], [[Reload configuration]])

CF_CLI(CONFIGURE, cfg_name, [\"<file>\"], [[Reload configuration]])
{ cmd_reconfig($2, RECONFIG_HARD); } ;

CF_CLI(CONFIGURE SOFT, cfg_name, [\"<file>\"], [[Reload configuration and ignore changes in filters]])
{ cmd_reconfig($3, RECONFIG_SOFT); } ;

CF_CLI(DOWN,,, [[Shut the daemon down]])
{ cmd_shutdown(); } ;

cfg_name:
   /* empty */ { $$ = NULL; }
 | TEXT
 ;

CF_CODE

CF_END
