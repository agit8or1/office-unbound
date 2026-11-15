import { defineConfig } from '@playwright/test'

export const VIEWPORTS = {
  desktop: { width: 1440, height: 900 },
  tablet: { width: 1024, height: 768 },
  mobile: { width: 400, height: 860 },
} as const

// Specs read E2E_STATE (written by harness/launcher.py). Backend: http://127.0.0.1:8108, served UI at /ui/.
export default defineConfig({
  testDir: '.',
  testMatch: ['setup/*.setup.ts', 'specs/*.spec.ts'],
  outputDir: 'results/artifacts',
  timeout: 90_000,
  expect: { timeout: 10_000 },
  workers: 2,
  retries: 0,
  reporter: [['list'], ['json', { outputFile: 'results/report.json' }]],
  use: { baseURL: 'http://127.0.0.1:8108', trace: 'off', actionTimeout: 10_000 },
  projects: [
    { name: 'setup', testMatch: /setup\/.*\.setup\.ts/ },
    // read-only specs at every viewport
    ...Object.entries(VIEWPORTS).map(([name, viewport]) => ({
      name, dependencies: ['setup'], testMatch: /specs\/0[2-8].*\.spec\.ts/,
      use: { browserName: 'chromium' as const, viewport },
    })),
    // mutating specs (login/enrollment, approvals, forms): run.sh executes this project in a second pass, after the read-only ones
    // (a Playwright project dependency would be skipped whenever a read-only spec reports a defect). Needs the auth files from `setup`.
    { name: 'flows', testMatch: /specs\/(01|09).*\.spec\.ts/,
      use: { browserName: 'chromium' as const, viewport: VIEWPORTS.desktop } },
  ],
})
