import { beforeEach, describe, expect, test, vi } from 'vitest'

const create = vi.fn()
const put = vi.fn()

vi.mock('axios', () => ({
  default: {
    create: (config) => {
      create(config)
      return {
        put,
        post: vi.fn(),
        delete: vi.fn(),
        get: vi.fn(),
        interceptors: {
          request: { use: vi.fn() },
          response: { use: vi.fn() },
        },
      }
    },
  },
}))

const store = new Map()
globalThis.localStorage = {
  getItem: (key) => (store.has(key) ? store.get(key) : null),
  setItem: (key, value) => store.set(key, String(value)),
  removeItem: (key) => store.delete(key),
}

const { CSRF_HEADERS, changePassword, forceChangePassword } = await import('./client')

describe('CSRF header', () => {
  test('every API request carries the anti-CSRF header', () => {
    expect(CSRF_HEADERS).toEqual({ 'X-Requested-With': 'pokecollector' })
    expect(create.mock.calls[0][0].headers).toMatchObject(CSRF_HEADERS)
  })
})

describe('password change token rotation', () => {
  beforeEach(() => {
    store.clear()
    put.mockReset()
  })

  test('stores the replacement token for a logged-in browser', async () => {
    store.set('token', 'old')
    put.mockResolvedValue({ data: { message: 'ok', access_token: 'new' } })
    await changePassword({ current_password: 'a', new_password: 'b' })
    expect(store.get('token')).toBe('new')

    put.mockResolvedValue({ data: { message: 'ok', access_token: 'newer' } })
    await forceChangePassword('c')
    expect(store.get('token')).toBe('newer')
  })

  test('does not create a token in single-user mode', async () => {
    put.mockResolvedValue({ data: { message: 'ok', access_token: 'new' } })
    await changePassword({ current_password: 'a', new_password: 'b' })
    expect(store.has('token')).toBe(false)
  })
})
