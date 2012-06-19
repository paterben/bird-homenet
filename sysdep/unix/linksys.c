/*
 * BIRD -- Linksys-specific sysdep code
 *
 * (c) 2012 Benjamin Paterson <benjamin@paterson.fr>
 *
 * Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "proto/ospf/ospf.h"

#ifdef ENABLE_SYSCFG

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int
bird_syscfg_get(const char *ns, const char *name, char *out_value, int outbufsz)
{
  char cmd[64];
  FILE *pfile = NULL;
  char *pos;

  if(ns)
    snprintf(cmd,sizeof(cmd),"/sbin/syscfg get %s::%s", ns, name);
  else
    snprintf(cmd,sizeof(cmd),"/sbin/syscfg get %s", name);

  pfile = popen(cmd,"r");
  if(pfile == NULL)
  {
    return -1;
  }

  if(fgets(out_value, outbufsz, pfile) == NULL)
  {
    pclose(pfile);
    return -1;
  }
  if((pos=strchr(out_value, '\n')) != NULL)
    *pos = '\0';
  pclose(pfile);
  return 0;
}

#endif /* ENABLE_SYSCFG */
