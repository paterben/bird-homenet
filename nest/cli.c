/*
 *	BIRD Internet Routing Daemon -- Command-Line Interface
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/string.h"
#include "nest/cli.h"

pool *cli_pool;

void
cli_printf(cli *c, int code, char *msg, ...)
{
  va_list args;
  byte buf[1024];
  int cd = code;
  int size, cnt;
  struct cli_out *o;

  va_start(args, msg);
  if (cd < 0)
    {
      cd = -cd;
      if (cd == c->last_reply)
	size = bsprintf(buf, " ");
      else
	size = bsprintf(buf, "%04d-", cd);
    }
  else
    size = bsprintf(buf, "%04d ", cd);
  c->last_reply = cd;
  cnt = bvsnprintf(buf+size, sizeof(buf)-size-1, msg, args);
  if (cnt < 0)
    {
      cli_printf(c, code < 0 ? -8000 : 8000, "<line overflow>");
      return;
    }
  size += cnt;
  buf[size++] = '\n';
  if (!(o = c->tx_write) || o->wpos + size > o->end)
    {
      if (!o && c->tx_buf)
	o = c->tx_buf;
      else
	{
	  o = mb_alloc(c->pool, sizeof(struct cli_out) + CLI_TX_BUF_SIZE);
	  if (c->tx_write)
	    c->tx_write->next = o;
	  else
	    c->tx_buf = o;
	  o->next = NULL;
	  o->wpos = o->outpos = o->buf;
	  o->end = o->buf + CLI_TX_BUF_SIZE;
	}
      c->tx_write = o;
      if (!c->tx_pos)
	c->tx_pos = o;
    }
  memcpy(o->wpos, buf, size);
  o->wpos += size;
}

static void
cli_hello(cli *c)
{
  cli_printf(c, 1, "BIRD " BIRD_VERSION " ready.");
  c->cont = NULL;
}

static void
cli_free_out(cli *c)
{
  struct cli_out *o, *p;

  if (o = c->tx_buf)
    {
      c->tx_write = NULL;
      o->wpos = o->outpos = o->buf;
      while (p = o->next)
	{
	  o->next = p->next;
	  mb_free(p);
	}
    }
}

static int
cli_event(void *data)
{
  cli *c = data;
  int err;

  if (c->tx_pos)
    ;
  else if (c->cont)
    c->cont(c);
  else
    {
      err = cli_get_command(c);
      if (!err)
	return 0;
      if (err < 0)
	cli_printf(c, 9000, "Command too long");
      else
	{
	  cli_printf(c, -9001, "Parse error in:");
	  cli_printf(c, 9001, c->rx_buf);
	}
    }
  if (cli_write(c))
    {
      cli_free_out(c);
      return 1;
    }
  return 0;
}

cli *
cli_new(void *priv)
{
  pool *p = rp_new(cli_pool, "CLI");
  cli *c = mb_alloc(p, sizeof(cli));

  c->pool = p;
  c->priv = priv;
  c->event = ev_new(p);
  c->event->hook = cli_event;
  c->event->data = c;
  c->tx_buf = c->tx_pos = c->tx_write = NULL;
  c->cont = cli_hello;
  c->last_reply = 0;
  ev_schedule(c->event);
  return c;
}

void
cli_kick(cli *c)
{
  if (!c->cont && !c->tx_pos)
    ev_schedule(c->event);
}

void
cli_written(cli *c)
{
  cli_free_out(c);
  ev_schedule(c->event);
}

void
cli_free(cli *c)
{
  rfree(c->pool);
}

void
cli_init(void)
{
  cli_pool = rp_new(&root_pool, "CLI");
}