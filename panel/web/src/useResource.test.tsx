import { act, renderHook } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { useResource } from './useResource'

afterEach(() => vi.useRealTimers())

it('retains the last successful response and timestamp on repeated refresh errors', async () => {
  const load = vi.fn().mockResolvedValueOnce({ count: 7 }).mockRejectedValue(new Error('offline'))
  const { result } = renderHook(() => useResource(load))
  await act(async () => {})
  const updatedAt = result.current.updatedAt
  for (let i = 0; i < 2; i++) {
    await act(async () => result.current.refresh())
    expect(result.current.data).toEqual({ count: 7 })
    expect(result.current.updatedAt).toBe(updatedAt)
    expect(result.current.error).toBeTruthy()
    expect(result.current.loading).toBe(false)
  }
})

it('coalesces refresh and never overlaps polling; unmount aborts pending work', async () => {
  vi.useFakeTimers()
  const resolves: ((value: number) => void)[] = []
  const signals: AbortSignal[] = []
  const load = vi.fn((signal: AbortSignal) => { signals.push(signal); return new Promise<number>(resolve => resolves.push(resolve)) })
  const { result, unmount } = renderHook(() => useResource(load, 1000))
  act(() => { result.current.refresh(); result.current.refresh() })
  await act(async () => { await vi.advanceTimersByTimeAsync(4000) })
  expect(load).toHaveBeenCalledTimes(1)
  await act(async () => resolves[0](1))
  expect(load).toHaveBeenCalledTimes(2)
  await act(async () => { await vi.advanceTimersByTimeAsync(4000) })
  expect(load).toHaveBeenCalledTimes(2)
  unmount()
  expect(signals[1].aborted).toBe(true)
  await act(async () => resolves[1](2))
  await vi.advanceTimersByTimeAsync(5000)
  expect(load).toHaveBeenCalledTimes(2)
})

it('drops data and late callbacks when the source identity changes', async () => {
  let oldResolve: (s: string) => void = () => {}
  let oldSignal: AbortSignal | undefined
  const first = (signal: AbortSignal) => { oldSignal = signal; return new Promise<string>(resolve => { oldResolve = resolve }) }
  const second = async () => 'second account'
  const { result, rerender } = renderHook(({ load }) => useResource(load), { initialProps: { load: first } })
  rerender({ load: second })
  await act(async () => {})
  expect(oldSignal?.aborted).toBe(true)
  expect(result.current.data).toBe('second account')
  await act(async () => oldResolve('old private data'))
  expect(result.current.data).toBe('second account')
})
