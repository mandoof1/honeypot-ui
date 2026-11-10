import { useEffect, useState } from 'react'
import { api } from '../services/api'

/*
 * What this deployment can actually do.
 *
 * Sign-up and password reset both finish with a code sent by e-mail. On a
 * deployment with no mail server they start, promise a code, and can never
 * complete, and the alert thresholds offered an "Email" channel that
 * delivered nothing. /auth/capabilities says which of these work, and the
 * console offers only what does.
 *
 * When the answer cannot be had (an older API without the route, or the API
 * unreachable) nothing is assumed to work: `known` is false and every
 * capability reads false, so no flow is offered on a guess.
 */

const UNKNOWN = Object.freeze({
  status: 'unknown', known: false, email_delivery: false, signup: false, password_reset: false,
})

const LOADING = Object.freeze({ ...UNKNOWN, status: 'loading' })

// One request per page load is enough; only a successful answer is kept.
let cached = null

function load() {
  if (!cached) {
    cached = api.auth.capabilities().catch((error) => {
      cached = null
      throw error
    })
  }
  return cached
}

export function useCapabilities() {
  const [state, setState] = useState(LOADING)

  useEffect(() => {
    let cancelled = false
    load()
      .then((answer) => {
        if (cancelled) return
        setState({
          status: 'ready',
          known: true,
          email_delivery: answer?.email_delivery === true,
          signup: answer?.signup === true,
          password_reset: answer?.password_reset === true,
        })
      })
      .catch(() => {
        if (!cancelled) setState(UNKNOWN)
      })
    return () => {
      cancelled = true
    }
  }, [])

  return state
}
