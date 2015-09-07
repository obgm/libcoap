#ifndef _COAP_TIMER_H_
#define _COAP_TIMER_H_

#include "coap_time.h"

struct coap_timer_t;
typedef struct coap_timer_t coap_timer_t;

void coap_timer_init(void);

typedef void (*CoapTimerCallback)(void *data);

coap_timer_t *coap_new_timer(CoapTimerCallback cb, void *data);

void coap_free_timer(coap_timer_t *timer);

void coap_timer_set(coap_timer_t *timer, coap_tick_t num_ticks);

char coap_timer_is_set(coap_timer_t *timer);

void coap_timer_unset(coap_timer_t *timer);

#endif /* _COAP_TIMER_H_ */

#if 0

#ifdef WITH_LWIP
#include <lwip/timers.h>
#endif

#ifdef WITH_CONTIKI

PROCESS(coap_retransmit_process, "message retransmit process");

#ifdef WITH_CONTIKI
  { /* (re-)initialize retransmission timer */
    process_post(&coap_retransmit_process, PROCESS_EVENT_MSG, context);
  }
#endif /* WITH_CONTIKI */

#ifdef WITH_LWIP

#include <lwip/memp.h>

static void coap_retransmittimer_execute(void *arg);
static void coap_retransmittimer_restart(coap_context_t *ctx);

#endif /* WITH_LWIP */




/*---------------------------------------------------------------------------*/
/* CoAP message retransmission */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(coap_retransmit_process, ev, data)
{
  coap_tick_t now;
  coap_queue_t *nextpdu;
  coap_context_t *context = NULL;

  PROCESS_BEGIN();

  debug("Started retransmit process\r\n");

  while(1) {
    PROCESS_YIELD();

    if (ev == PROCESS_EVENT_MSG) {
      context = data;
    } else if (ev == PROCESS_EVENT_TIMER)  {
#ifndef WITHOUT_OBSERVE
      if (etimer_expired(&context->notify_timer)) {
        coap_check_notify(context);
        etimer_reset(context->notify_timer);
      }
      if (!etimer_expired(&context->retransmit_timer)) {
        continue;
      }
#endif /* WITHOUT_OBSERVE */
      assert(etimer_expired(&context->retransmit_timer));
    } else {
      // Toss out events we're not interested in
      continue;
    }

    nextpdu = coap_peek_next(context);

    coap_ticks(&now);
    while (nextpdu && nextpdu->t <= now) {
      coap_retransmit(context, coap_pop_next(context));
      nextpdu = coap_peek_next(context);
    }

    /* need to set timer to some value even if no nextpdu is available */
    etimer_set(&context->retransmit_timer,
	nextpdu ? nextpdu->t - now : 0xFFFF);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

#endif /* WITH_CONTIKI */

#ifdef WITH_LWIP
/* FIXME: retransmits that are not required any more due to incoming packages
 * do *not* get cleared at the moment, the wakeup when the transmission is due
 * is silently accepted. this is mainly due to the fact that the required
 * checks are similar in two places in the code (when receiving ACK and RST)
 * and that they cause more than one patch chunk, as it must be first checked
 * whether the sendqueue item to be dropped is the next one pending, and later
 * the restart function has to be called. nothing insurmountable, but it can
 * also be implemented when things have stabilized, and the performance
 * penality is minimal
 *
 * also, this completely ignores COAP_RESOURCE_CHECK_TIME.
 * */

static void coap_retransmittimer_execute(void *arg)
{
	coap_context_t *ctx = (coap_context_t*)arg;
	coap_tick_t now;
	coap_tick_t elapsed;
	coap_queue_t *nextinqueue;

	ctx->timer_configured = 0;

	coap_ticks(&now);

	elapsed = now - ctx->sendqueue_basetime; /* that's positive for sure, and unless we haven't been called for a complete wrapping cycle, did not wrap */

	nextinqueue = coap_peek_next(ctx);
	while (nextinqueue != NULL)
	{
		if (nextinqueue->t > elapsed) {
			nextinqueue->t -= elapsed;
			break;
		} else {
			elapsed -= nextinqueue->t;
			coap_retransmit(ctx, coap_pop_next(ctx));
			nextinqueue = coap_peek_next(ctx);
		}
	}

	ctx->sendqueue_basetime = now;

	coap_retransmittimer_restart(ctx);
}

static void coap_retransmittimer_restart(coap_context_t *ctx)
{
	coap_tick_t now, elapsed, delay;

	if (ctx->timer_configured)
	{
		printf("clearing\n");
		sys_untimeout(coap_retransmittimer_execute, (void*)ctx);
		ctx->timer_configured = 0;
	}
	if (ctx->sendqueue != NULL)
	{
		coap_ticks(&now);
		elapsed = now - ctx->sendqueue_basetime;
		if (ctx->sendqueue->t >= elapsed) {
			delay = ctx->sendqueue->t - elapsed;
		} else {
			/* a strange situation, but not completely impossible.
			 *
			 * this happens, for example, right after
			 * coap_retransmittimer_execute, when a retransmission
			 * was *just not yet* due, and the clock ticked before
			 * our coap_ticks was called.
			 *
			 * not trying to retransmit anything now, as it might
			 * cause uncontrollable recursion; let's just try again
			 * with the next main loop run.
			 * */
			delay = 0;
		}

		printf("scheduling for %d ticks\n", delay);
		sys_timeout(delay, coap_retransmittimer_execute, (void*)ctx);
		ctx->timer_configured = 1;
	}
}
#endif

#endif
