import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h, nextTick } from 'vue'
import DesktopDownload from './DesktopDownload.vue'
import { DESKTOP_WINDOWS_HREF, desktopWarning, humanSize, type DesktopWindows } from './desktop'

const W: DesktopWindows = { product: 'Office Unbound Desktop', platform: 'windows-x64', version: '0.1.0', file: 'OfficeUnbound-Desktop-0.1.0-x64-setup.exe',
  sha256: 'a'.repeat(64), size: 23 * 1024 * 1024, unsigned: true, stage: 'alpha', url: 'https://evil.test/x.exe' }

async function mounted(body: unknown) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })))
  const el = document.createElement('div')
  createApp({ render: () => h(DesktopDownload) }).mount(el)
  for (let i = 0; i < 5; i++) { await new Promise((r) => setTimeout(r, 0)); await nextTick() }
  return el
}

afterEach(() => { vi.unstubAllGlobals() })

describe('Office Unbound Desktop download in the console', () => {
  it('formats size and warns while the installer is not code-signed', () => {
    expect(humanSize(23 * 1024 * 1024)).toBe('23.0 MB')
    expect(humanSize(10)).toBe('1 KB')
    expect(desktopWarning(W)).toBe('Alpha, not code-signed: Windows SmartScreen will warn')
    expect(desktopWarning({ ...W, unsigned: false, stage: 'stable' })).toBeNull()
  })

  it('links to the console API only, with version, size and sha256', async () => {
    const el = await mounted({ windows: W })
    const a = el.querySelector('[data-test="desktop-download"]') as HTMLAnchorElement
    expect(a.getAttribute('href')).toBe(DESKTOP_WINDOWS_HREF)
    expect(DESKTOP_WINDOWS_HREF).toBe('/api/v1/downloads/desktop/windows')
    expect(a.hasAttribute('download')).toBe(true)
    expect(el.textContent).toContain('0.1.0')
    expect(el.textContent).toContain('23.0 MB')
    expect(el.textContent).toContain('a'.repeat(64))
    expect(el.querySelector('[data-test="desktop-warning"]')?.textContent).toContain('SmartScreen will warn')
    expect(el.innerHTML).not.toContain('evil.test')
  })

  it('says not available when the server has no installer', async () => {
    const el = await mounted({ windows: null })
    expect(el.querySelector('[data-test="desktop-download"]')).toBeNull()
    expect(el.querySelector('[data-test="desktop-none"]')?.textContent).toBe('Not available yet.')
  })
})
