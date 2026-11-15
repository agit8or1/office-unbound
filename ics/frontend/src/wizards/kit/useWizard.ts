// Wizard state machine: ordered steps, per-step validation, back/next with preserved state.
// Rule: forward movement requires the current step to validate; goto() reaches only steps already reached
// and re-validates every step it skips over.
import { computed, reactive } from 'vue'
import type { Errors } from './validate'
import { isEmpty } from './validate'

export interface StepDef<S> {
  id: string
  title: string
  /** Return field -> message; empty object means valid. */
  validate?: (state: S) => Errors
}

export function useWizard<S>(steps: StepDef<S>[], state: S) {
  const m = reactive({ index: 0, reached: 0, errors: {} as Errors })
  const current = computed(() => steps[m.index])
  const isLast = computed(() => m.index === steps.length - 1)

  function validateCurrent(): boolean {
    m.errors = steps[m.index].validate?.(state) ?? {}
    return isEmpty(m.errors)
  }
  function next(): boolean {
    if (isLast.value || !validateCurrent()) return false
    m.index += 1
    m.reached = Math.max(m.reached, m.index)
    m.errors = {}
    return true
  }
  function back(): boolean {
    if (m.index === 0) return false
    m.index -= 1
    m.errors = {}
    return true
  }
  function goto(i: number): boolean {
    if (i < 0 || i >= steps.length || i > m.reached || i === m.index) return false
    for (let k = m.index; k < i; k++) {
      const e = steps[k].validate?.(state) ?? {}
      if (!isEmpty(e)) { m.index = k; m.errors = e; return false }
    }
    m.index = i
    m.errors = {}
    return true
  }
  /** Inputs of an earlier step changed after later steps were reached (e.g. a plan preview is now stale). */
  function truncateReached(i: number) { m.reached = Math.min(m.reached, Math.max(i, m.index)) }
  return { m, steps, current, isLast, next, back, goto, validateCurrent, truncateReached }
}
export type Wizard<S> = ReturnType<typeof useWizard<S>>
