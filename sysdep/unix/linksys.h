/*
 *	BIRD -- Linksys-specific sysdep code
 *
 *	(c) 2012 Benjamin Paterson <benjamin@paterson.fr>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LINKSYS_H_
#define _BIRD_LINKSYS_H_

#include "nest/bird.h"

#ifdef ENABLE_SYSCFG

int bird_syscfg_get(const char *ns, const char *name, char *out_value, int outbufsz);

#endif /* ENABLE_SYSCFG */

#endif /* _BIRD_LINKSYS_H_ */
