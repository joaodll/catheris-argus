/**
 * The M7 visual walk: signs in, visits every screen and state the design specifies, and fails on
 * any console error, uncaught exception, failed request (other than the ones a step provokes),
 * or WCAG A/AA violation found by axe. Screenshots land in e2e/screens/ for a person to review.
 *
 * It only reads, except where noted: no step changes a connection or schedule, and the one step
 * that saves a setting puts the old value back.
 */
import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const PASSWORD = process.env.ARGUS_E2E_PASSWORD ?? ''
const SHOTS = 'e2e/screens'

const problems: string[] = []
let allowed: RegExp[] = []

test.beforeEach(({ page }) => {
  problems.length = 0
  allowed = []
  page.on('console', (m) => {
    if (m.type() === 'error' && !allowed.some((a) => a.test(m.text()))) problems.push(`console: ${m.text()}`)
  })
  page.on('pageerror', (e) => problems.push(`exception: ${e.message}`))
  page.on('response', (r) => {
    if (r.status() >= 400 && !allowed.some((a) => a.test(`${r.status()} ${r.url()}`))) problems.push(`${r.status()} ${r.url()}`)
  })
})

test.afterEach(() => {
  expect(problems, 'console errors or failed requests').toEqual([])
})

async function signIn(page: Page): Promise<void> {
  expect(PASSWORD, 'set ARGUS_E2E_PASSWORD').not.toBe('')
  allowed.push(/401 .*\/api\/v1\/auth\/session/, /status of 401/)
  await page.goto('/')
  await expect(page).toHaveURL(/\/sign-in/)
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible()
}

async function axe(page: Page, label: string): Promise<void> {
  // Audit what a person sees at rest: let entrances (a map node's fade-in) finish first.
  // Endless animations (a spinner, the live pulse) are left running.
  await page.waitForFunction(() =>
    document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity),
  )
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze()
  // The first node's own message says why (a contrast ratio and its colours, for example).
  const found = results.violations.map(
    (v) => `${label}: ${v.id} (${v.nodes.length}) ${v.help} → ${v.nodes[0]?.target.join(' ')} · ${v.nodes[0]?.failureSummary?.split('\n').slice(1, 2).join('').trim() ?? ''}`,
  )
  expect(found, `accessibility violations on ${label}`).toEqual([])
}

async function shot(page: Page, name: string): Promise<void> {
  // No screen ever scrolls sideways (design-system.md, Table).
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow, `${name}: the page scrolls sideways`).toBeLessThanOrEqual(0)
  await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true })
}

test('sign in: wrong password, then the real one', async ({ page }) => {
  allowed.push(/401 /, /status of 401/)
  await page.goto('/sign-in')
  await axe(page, 'sign in')
  await shot(page, '01-sign-in')
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password', { exact: true }).fill('not-the-password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('alert')).toContainText('Wrong username or password.')
  await shot(page, '02-sign-in-wrong')
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/$/)
})

test('overview: every block, current state only', async ({ page }) => {
  await signIn(page)
  const blocks = [
    'Monitored assets',
    'Score · 6 months',
    'Check results and failed findings',
    'Findings severity over time',
    'Month over month',
    'Attack paths by category',
    'Inventory',
    'Assets by type, per provider',
  ]
  for (const text of blocks) await expect(page.getByText(text, { exact: true }).first()).toBeVisible()
  await expect(page.getByText('No data')).toHaveCount(0)
  await axe(page, 'overview')
  await expect(page.getByText('Showing data as of')).toBeVisible()
  await expect(page.getByLabel('Point in time')).toHaveCount(0)
  await expect(page.getByText(/\bvs [A-Z][a-z]{2} \d/)).toHaveCount(0)
  await expect(page.getByRole('list', { name: 'AWS assets by type' })).toBeVisible()
  await expect(page.getByText('not covered')).not.toHaveCount(0)
  await shot(page, '10-overview-now')

  // The strip's framework (2026-10-15): ThreatScore by default; a framework is kept in the URL
  // and in this browser, and its link opens that framework.
  const stripPicker = page.getByLabel('Framework', { exact: true })
  await expect(stripPicker).toHaveValue('')
  await expect(page.getByText("Prowler's weighted score")).toBeVisible()
  await expect(stripPicker.getByRole('option', { name: 'CIS 6.0', exact: true })).toHaveCount(1) // short names
  await stripPicker.selectOption('cis_6.0_aws')
  await expect(page).toHaveURL(/strip=cis_6\.0_aws/)
  await expect(page.getByText('Requirements passed ÷ assessed')).toBeVisible()
  await expect(page.getByRole('list', { name: /CIS .* at the end of each month/ })).toBeVisible()
  await expect(page.getByRole('link', { name: /^CIS .*: show the framework$/ })).toHaveAttribute('href', /\/posture\/compliance\/cis_6\.0_aws/)
  await axe(page, 'overview, CIS strip')
  await shot(page, '11-overview-strip-cis')
  await page.goto('/')
  await expect(page).toHaveURL(/strip=cis_6\.0_aws/) // remembered in this browser
  await page.getByLabel('Framework', { exact: true }).selectOption('')
  await expect(page).not.toHaveURL(/strip=/)

  for (const range of ['3M', '1M']) {
    await page.getByRole('button', { name: new RegExp(range === '3M' ? 'Three months' : 'One month') }).click()
    await page.waitForLoadState('networkidle')
    await shot(page, `12-overview-range-${range}`)
  }

  // Wide screen: content capped and centred, the chart keeps its size, a range change keeps the scroll.
  await page.setViewportSize({ width: 2560, height: 1200 })
  // main is centred in .content, the shell's second grid column (from the sidebar's edge on).
  const gaps = await page.locator('main').evaluate((m) => {
    const box = m.getBoundingClientRect()
    const column = m.parentElement?.getBoundingClientRect() ?? box
    return { width: box.width, left: box.left - column.left, right: column.right - box.right }
  })
  expect(gaps.width).toBeLessThanOrEqual(1480)
  expect(Math.abs(gaps.left - gaps.right)).toBeLessThanOrEqual(1)
  const trend = page.getByRole('img', { name: /Open failed findings by severity over/ })
  await expect(trend).toHaveAttribute('height', '270')
  expect((await trend.boundingBox())?.height).toBe(270)
  await trend.scrollIntoViewIfNeeded()
  const scrolled = await page.evaluate(() => window.scrollY)
  expect(scrolled).toBeGreaterThan(0)
  await page.getByRole('button', { name: 'Six months, month-end' }).click()
  await page.waitForLoadState('networkidle')
  expect(await page.evaluate(() => window.scrollY)).toBe(scrolled)
  await shot(page, '14-overview-wide')
  await page.setViewportSize({ width: 1440, height: 900 })

  await page.getByLabel('Accounts').selectOption({ index: 1 })
  await page.waitForLoadState('networkidle')
  await shot(page, '13-overview-one-connection')

  // Numbers lead to the list that holds them, with the filters that reproduce them.
  await page.getByRole('link', { name: /^High: .* open, show in Findings$/ }).click()
  await expect(page).toHaveURL(/\/investigate\/findings\?severity=high&connection=\d+&tool=prowler&result=FAIL&muted=hide$/)
  await expect(page.getByRole('heading', { level: 1, name: 'Findings' })).toBeVisible()
  await page.goBack()
  await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: /^Open critical findings: .* Show in Findings$/ })).toHaveAttribute('href', /severity=critical/)
  // An inventory group opens in place to its largest types; a type opens Resources.
  const compute = page.getByRole('button', { name: /^Compute: / })
  await compute.click()
  await expect(compute).toHaveAttribute('aria-expanded', 'true')
  const types = page.getByRole('list', { name: 'Compute: largest types' })
  await expect(types.getByRole('link').first()).toBeVisible()
  await axe(page, 'overview inventory group open')
  await shot(page, '15-overview-inventory-open')
  await types.getByRole('link').first().click()
  await expect(page).toHaveURL(/\/investigate\/resources/)
  await expect(page.getByRole('table')).toBeVisible()
})

/** Opens a sidebar module (if closed) and one of its pages, as a user would. */
async function navTo(page: Page, module: string, item: string): Promise<void> {
  const nav = page.getByRole('navigation', { name: 'Primary' })
  const header = nav.getByRole('button', { name: module, exact: true })
  if ((await header.getAttribute('aria-expanded')) !== 'true') await header.click()
  await nav.getByRole('link', { name: item, exact: true }).click()
}

// A top-level item (Investigate and Operate hold no modules).
async function navLink(page: Page, item: string): Promise<void> {
  await page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: item, exact: true }).click()
}

test('administration and scans: connections, schedules, runs, settings', async ({ page }) => {
  await signIn(page)
  await navTo(page, 'Administration', 'Connections')
  await expect(page).toHaveURL(/\/admin\/connections$/)
  await expect(page.getByRole('heading', { level: 2, name: 'Connections' })).toBeVisible()
  await expect(page.getByRole('switch').first()).toBeVisible()
  await axe(page, 'connections')
  await shot(page, '20-connections')

  await page.getByRole('button', { name: 'Add connection' }).first().click()
  const sheet = page.getByRole('dialog', { name: 'Add connection' })
  await expect(sheet).toBeVisible()
  await sheet.getByText('AWS · Assume role').click()
  await expect(sheet.getByLabel('Role ARN')).toBeVisible()
  await axe(page, 'add connection sheet')
  await shot(page, '21-add-connection-assume-role')
  // Access keys are always a choice (ADR-0024, amended 2026-10-24).
  await sheet.getByText('AWS · Access key').click()
  await expect(sheet.getByLabel('Access key ID')).toBeVisible()
  await shot(page, '22-add-connection-access-key')
  await page.keyboard.press('Escape')
  await expect(sheet).toBeHidden()

  await navLink(page, 'Schedules')
  await expect(page).toHaveURL(/\/scans\/schedules$/)
  await expect(page.getByRole('heading', { level: 2, name: 'Run now' })).toBeVisible()
  await page.getByLabel('Search', { exact: true }).fill('no such schedule')
  await expect(page.getByText('No schedules match "no such schedule".')).toBeVisible()
  await page.getByRole('button', { name: 'Clear filters' }).first().click()
  await expect(page.getByRole('heading', { level: 2, name: 'Queue' })).toBeVisible()
  await axe(page, 'schedules')
  await shot(page, '30-schedules')
  await page.getByRole('button', { name: 'New schedule' }).first().click()
  const scheduleSheet = page.getByRole('dialog', { name: 'New schedule' })
  await scheduleSheet.getByRole('button', { name: 'Every 6 hours' }).click()
  await expect(scheduleSheet.getByText('Next runs (UTC)')).toBeVisible()
  await shot(page, '31-new-schedule')
  allowed.push(/422 .*\/schedules\/preview/, /status of 422/)
  await scheduleSheet.getByLabel('When (cron, UTC)').fill('*/5 * * * *')
  await expect(scheduleSheet.getByText('the minimum interval is 60 minutes')).toBeVisible()
  await shot(page, '32-new-schedule-too-often')
  // Closing with unsaved changes asks with the browser's confirm(), as in CatherIs Platform.
  // The key press returns only once the dialog is answered, so a handler answers it.
  let question: { type: string; message: string } | null = null
  page.once('dialog', async (d) => {
    question = { type: d.type(), message: d.message() }
    await d.accept()
  })
  await page.keyboard.press('Escape')
  await expect.poll(() => question).toEqual({ type: 'confirm', message: expect.stringMatching(/^Discard your changes\?/) })
  await expect(scheduleSheet).toBeHidden()

  await navLink(page, 'Runs')
  await expect(page.getByRole('heading', { level: 1, name: 'Runs' })).toBeVisible()
  await expect(page.getByRole('navigation', { name: 'Pagination' })).toBeVisible()
  await page.getByRole('button', { name: /^Started \(UTC\), sorted newest first/ }).click()
  await expect(page.getByRole('button', { name: /^Started \(UTC\), sorted oldest first/ })).toBeVisible()
  await page.getByLabel('Status').selectOption('partial')
  // A click anywhere on the row opens it; the chevron says so.
  await page.locator('.runs-table tr.row').first().locator('td[data-label="Connection"]').click()
  await expect(page.getByRole('button', { name: /Hide details of run/ }).first()).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByText('Log tail').first()).toBeVisible()
  await axe(page, 'runs')
  await shot(page, '40-runs-partial-expanded')

  await navTo(page, 'Administration', 'Settings')
  await expect(page.getByRole('heading', { level: 2, name: 'Collection and throttling' })).toBeVisible()
  // The page lists its cards (2026-10-14); a link brings its card into view.
  const toc = page.getByRole('navigation', { name: 'On this page' })
  await expect(toc.getByRole('link')).toHaveCount(4)
  await axe(page, 'settings')
  await shot(page, '50-settings')
  // Pages from before 2026-10-06 still open.
  await page.goto('/admin/runs')
  await expect(page).toHaveURL(/\/scans\/runs$/)
})

test('settings: saving one card keeps the edits in another; leaving asks once', async ({ page }) => {
  // Changes the Start window and saves it, then saves the original value back.
  await signIn(page)
  await page.goto('/admin/settings')
  const collection = page.getByRole('region', { name: 'Collection and throttling' })
  const retention = page.getByRole('region', { name: 'Retention' })
  const window = collection.getByLabel('Start window')
  const demoRaw = retention.getByLabel('Demo raw files')
  const original = await window.inputValue()
  const demoOriginal = await demoRaw.inputValue()

  await demoRaw.fill(String(Number(demoOriginal) + 1))
  await expect(retention.getByText('Unsaved changes')).toBeVisible()
  // The page's list marks the card too (2026-10-14).
  await expect(page.getByRole('navigation', { name: 'On this page' }).getByRole('link', { name: 'Retention (unsaved)' })).toBeVisible()
  await window.fill(String(Number(original) + 1))
  await collection.getByRole('button', { name: 'Save collection settings' }).click()
  await expect(collection.getByText('Unsaved changes')).toBeHidden()
  // The Retention edit survived the Collection save.
  await expect(retention.getByText('Unsaved changes')).toBeVisible()
  await expect(demoRaw).toHaveValue(String(Number(demoOriginal) + 1))

  // Two edited cards, one question, with the browser's confirm(). Staying keeps the edit.
  await collection.getByLabel('Start window').fill(original)
  const questions: string[] = []
  const stay = (dialog: import('@playwright/test').Dialog) => {
    questions.push(dialog.message())
    void dialog.dismiss()
  }
  page.on('dialog', stay)
  await navLink(page, 'Runs')
  await expect(page).toHaveURL(/\/admin\/settings$/)
  expect(questions).toHaveLength(1)
  expect(questions[0]).toMatch(/^Discard unsaved changes\?/)
  page.off('dialog', stay)
  await expect(demoRaw).toHaveValue(String(Number(demoOriginal) + 1))

  // Put the saved value back, drop the unsaved one, and leave without a question.
  await collection.getByRole('button', { name: 'Save collection settings' }).click()
  await expect(collection.getByText('Unsaved changes')).toBeHidden()
  await retention.getByRole('button', { name: 'Discard' }).click()
  page.on('dialog', stay) // nothing is unsaved: no question
  await navLink(page, 'Runs')
  await expect(page.getByRole('heading', { level: 1, name: 'Runs' })).toBeVisible()
  expect(questions).toHaveLength(1)
})

test('investigate: findings and resources, read-only', async ({ page }) => {
  await signIn(page)
  await navLink(page, 'Findings')
  await expect(page).toHaveURL(/\/investigate\/findings/)
  await expect(page.getByRole('heading', { level: 1, name: 'Findings' })).toBeVisible()
  const findings = page.getByRole('table')
  await expect(findings).toBeVisible()
  await axe(page, 'findings')
  await shot(page, '70-findings')
  // Each finding names its cloud.
  await expect(findings.locator('tbody tr').first().getByText('AWS', { exact: true })).toBeVisible()
  // A finding's details open from anywhere on its row (and its chevron), and close the same way.
  const title = findings.locator('tbody tr.row').first().locator('.title')
  await title.click()
  await expect(page.getByText('Remediation', { exact: true })).toBeVisible()
  await expect(findings.getByRole('button', { name: /^Hide details of / }).first()).toBeVisible()
  await axe(page, 'finding details')
  await shot(page, '71-finding-details')
  await title.click()
  await expect(page.getByText('Remediation', { exact: true })).toHaveCount(0)
  // A search that matches nothing says so, and Clear filters brings the list back.
  await page.getByLabel('Search', { exact: true }).fill('no-such-finding-anywhere')
  await expect(page.getByText('No findings match these filters.')).toBeVisible()
  await page.getByRole('button', { name: 'Clear filters' }).first().click()
  await expect(findings).toBeVisible()
  // Prowler-style filters: several values at once, kept in the URL, restored on reload.
  // (The table's Severity sort button shares the name, so the filter is found by its id.)
  await page.locator('#f-sev').click()
  const severities = page.getByRole('listbox', { name: 'Severity' })
  await severities.getByRole('option', { name: 'Critical' }).click()
  await severities.getByRole('option', { name: 'High' }).click()
  await axe(page, 'severity filter open')
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/severity=critical&severity=high/)
  await page.getByRole('button', { name: /^More filters/ }).click()
  await page.locator('#f-result').click()
  await page.getByRole('listbox', { name: 'Result' }).getByRole('option', { name: 'Fail' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/result=FAIL/)
  await page.locator('#f-provider').click()
  await page.getByRole('listbox', { name: 'Provider' }).getByRole('option', { name: 'AWS' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/provider=aws/)
  await page.reload()
  await expect(page.locator('#f-sev')).toContainText('+1')
  await expect(page.getByRole('button', { name: /^More filters/ })).toHaveAttribute('aria-expanded', 'true')
  await axe(page, 'findings filtered')
  await shot(page, '74-findings-filters')
  await page.getByRole('button', { name: 'Clear filters' }).first().click()
  await expect(page).not.toHaveURL(/severity=/)

  await navLink(page, 'Resources')
  await expect(page).toHaveURL(/\/investigate\/resources/)
  const resources = page.getByRole('table')
  await expect(resources).toBeVisible()
  await axe(page, 'resources')
  await shot(page, '72-resources')
  // The sheet opens from the name, lives in the URL, and Escape closes it.
  const first = resources.locator('tbody tr').first().getByRole('link')
  await first.click()
  await expect(page).toHaveURL(/open=\d+/)
  const sheet = page.getByRole('dialog')
  for (const block of ['Steampipe', 'Prowler', 'CloudFox', 'Attack paths through it', 'Connections']) {
    await expect(sheet.getByRole('heading', { level: 3, name: new RegExp(`^${block}`) })).toBeVisible()
  }
  await expect(sheet.getByRole('link', { name: 'Open in map' })).toBeVisible()
  await axe(page, 'resource sheet')
  await shot(page, '73-resource-sheet')
  await page.keyboard.press('Escape')
  await expect(page).not.toHaveURL(/open=/)
  await expect(first).toBeFocused()
  // A bucket's sheet shows CloudFox's commands (ADR-0038): labelled, copy only, never run.
  await page.goto('/investigate/resources?type=aws_s3_bucket')
  await resources.locator('tbody tr').first().getByRole('link').click()
  const commands = sheet.getByRole('region', { name: 'Commands (CloudFox)' })
  await expect(commands).toBeVisible()
  await expect(commands.getByText('Argus never runs these. Run them only with written authorization.')).toBeVisible()
  await expect(commands.getByRole('heading', { level: 4, name: 'Check' })).toBeVisible()
  for (const button of await commands.getByRole('button').all()) {
    await expect(button).toHaveAccessibleName(/^Copy /)
  }
  await axe(page, 'resource sheet commands')
  await shot(page, '73b-resource-sheet-commands')
  await page.keyboard.press('Escape')
})

test('investigate: resource map and attack paths, read-only', async ({ page }) => {
  await signIn(page)
  await navLink(page, 'Resource map')
  await expect(page).toHaveURL(/\/investigate\/map/)
  await expect(page.getByRole('heading', { level: 1, name: 'Resource map' })).toBeVisible()
  // Start state (argus_v11): one list of front doors, every reach, open doors first. No mode switch.
  await expect(page.getByRole('heading', { name: 'Start from what the internet reaches' })).toBeVisible()
  await expect(page.getByRole('group', { name: 'Mode' })).toHaveCount(0)
  const doors = page.getByRole('table')
  await expect(doors.locator('tbody tr').first()).toBeVisible()
  await expect(doors.getByRole('columnheader', { name: 'Reach' })).toBeVisible()
  await expect(doors.getByText('Reachable', { exact: true }).first()).toBeVisible()
  await axe(page, 'map front doors')
  await shot(page, '90-map-front-doors')
  // Search (2026-10-15): a word narrows the doors by name, ARN or type, in any case.
  const doorType = (await doors.locator('tbody tr').first().locator('td[data-label="Type"]').innerText()).trim()
  const word = doorType.split('_')[1] ?? doorType
  await page.getByLabel('Search', { exact: true }).fill(word.toUpperCase())
  await expect(page).toHaveURL(new RegExp(`[?&]q=${word.toUpperCase()}`))
  await expect(doors.locator('td[data-label="Type"]', { hasText: doorType }).first()).toBeVisible()
  await axe(page, 'map front doors, searched')
  await shot(page, '90a-map-search')
  await page.getByLabel('Search', { exact: true }).fill('no-such-door')
  await expect(page.getByText('No front doors match these filters.')).toBeVisible()
  await page.getByRole('button', { name: 'Clear filters' }).first().click()
  await expect(page).not.toHaveURL(/[?&]q=/)
  await expect(page.getByLabel('Search', { exact: true })).toHaveValue('')
  await expect(doors.locator('tbody tr').first()).toBeVisible()
  // Reach filter, kept in the URL: the restricted doors say why.
  await page.locator('#doors-reach').click()
  await page.getByRole('listbox', { name: 'Reach' }).getByRole('option', { name: 'Restricted' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/reach=restricted/)
  await expect(doors.getByText('Restricted', { exact: true }).first()).toBeVisible()
  await expect(doors.getByText(/^Security groups admit only/).first()).toBeVisible()
  await axe(page, 'map restricted front doors')
  await shot(page, '90b-map-restricted')
  // Unknown doors name what Argus is missing to judge them (ADR-0035, second amendment).
  const reaches = page.getByRole('listbox', { name: 'Reach' })
  await page.locator('#doors-reach').click()
  await reaches.getByRole('option', { name: 'Unknown' }).click()
  await reaches.getByRole('option', { name: 'Restricted' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/reach=unknown/)
  await expect(doors.getByText(/^Argus can't tell: route table for subnet-/).first()).toBeVisible()
  await axe(page, 'map unknown front doors')
  await shot(page, '90c-map-unknown')
  await page.locator('#doors-reach').click()
  await reaches.getByRole('option', { name: 'Restricted' }).click()
  await reaches.getByRole('option', { name: 'Unknown' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/reach=restricted/)
  await expect(page).not.toHaveURL(/reach=unknown/)
  // Region filter: the connection's regions; the first door's keeps it in the list.
  const region = (await doors.locator('tbody tr').first().locator('td[data-label="Region"]').innerText()).trim()
  await page.locator('#doors-region').click()
  await page.getByRole('listbox', { name: 'Region' }).getByRole('option', { name: region }).click()
  await page.keyboard.press('Escape')
  await expect(doors.locator('tbody tr').first()).toBeVisible()
  await expect(page).toHaveURL(/region=/)
  // A door opens its flow; Front doors comes back to the same filtered list.
  await doors.locator('tbody tr').first().getByRole('link').first().click() // the name; the row may also link its Prowler checks
  await expect(page).toHaveURL(/flow=\d+/)
  const flowCanvas = page.getByRole('application', { name: /^Resource map, \d+ resources/ })
  await expect(flowCanvas).toBeVisible()
  await expect(page.getByRole('status').filter({ hasText: 'Flow from' })).toBeVisible()
  await axe(page, 'map flow')
  await shot(page, '91-map-flow')
  await page.getByRole('link', { name: 'Front doors' }).click()
  await expect(page).not.toHaveURL(/flow=/)
  await expect(page).toHaveURL(/reach=restricted/)
  await expect(page).toHaveURL(new RegExp(`region=${encodeURIComponent(region === 'Global' ? 'global' : region)}`))
  await expect(page.locator('#doors-reach')).toContainText('Restricted')
  // From the menu, every door again; the first (reachable) one's flow.
  await navLink(page, 'Resource map')
  await expect(page).not.toHaveURL(/reach=/)
  await doors.locator('tbody tr').first().getByRole('link').click()
  await expect(page).toHaveURL(/flow=\d+/)
  await expect(flowCanvas).toBeVisible()
  // A node of the flow: its panel offers Explore around, which opens its neighbourhood.
  await flowCanvas.focus()
  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('Enter')
  const flowPanel = page.getByRole('complementary', { name: 'Resource panel' })
  await expect(flowPanel.getByRole('button', { name: 'Explore around' })).toBeVisible()
  // Sample B (2026-10-14): the panel starts with the chain from the internet to the node.
  await expect(flowPanel.getByRole('heading', { level: 3, name: 'Path from the internet' })).toBeVisible()
  await axe(page, 'map flow with a resource')
  await shot(page, '91b-map-flow-resource')
  await flowPanel.getByRole('button', { name: 'Explore around' }).click()
  await expect(page).toHaveURL(/focus=/)
  await expect(page).not.toHaveURL(/flow=/)
  const canvas = page.getByRole('application', { name: /^Resource map, \d+ resources/ })
  await expect(canvas).toBeVisible()
  await expect(page.getByRole('group', { name: 'Depth' })).toBeVisible()
  await page.getByRole('button', { name: 'Reset' }).click()
  // Nothing selected: no panel, the map has the whole width.
  await expect(page.getByRole('complementary', { name: 'Resource panel' })).toHaveCount(0)
  await axe(page, 'map')
  await shot(page, '91-map')
  // The keyboard: the arrow keys move between nodes, Enter opens the panel, E expands.
  await canvas.focus()
  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('Enter')
  const panel = page.getByRole('complementary', { name: 'Resource panel' })
  await expect(panel.getByRole('button', { name: 'Expand' })).toBeVisible()
  const before = await canvas.getAttribute('aria-label')
  if (await panel.getByRole('button', { name: 'Expand' }).isEnabled()) {
    await panel.getByRole('button', { name: 'Expand' }).click()
    await expect(canvas).not.toHaveAttribute('aria-label', before ?? '')
  }
  for (const block of ['Steampipe', 'Prowler', 'CloudFox', 'Attack paths through it']) {
    await expect(panel.getByRole('heading', { level: 3, name: new RegExp(`^${block}`) })).toBeVisible()
  }
  await axe(page, 'map with a resource')
  await shot(page, '92-map-resource')
  // The same picture as tables.
  await page.getByRole('group', { name: 'View' }).getByRole('button', { name: 'List' }).click()
  await expect(page).toHaveURL(/view=list/)
  await expect(page.getByRole('heading', { level: 3, name: 'Connections' }).first()).toBeVisible()
  await axe(page, 'map list view')
  await shot(page, '93-map-list')

  await navLink(page, 'Attack paths')
  await expect(page).toHaveURL(/\/investigate\/attack-paths/)
  const paths = page.getByRole('table')
  await expect(paths.locator('tbody tr').first()).toBeVisible()
  // One search (ADR-0037): every path says how sure Argus is; the filter narrows to one level.
  await expect(paths.getByRole('columnheader', { name: 'Confidence' })).toBeVisible()
  await expect(page.locator('#ap-rule')).toHaveCount(0)
  await axe(page, 'attack paths')
  await shot(page, '94-attack-paths')
  await page.locator('#ap-conf').click()
  await page.getByRole('listbox', { name: 'Confidence' }).getByRole('option', { name: 'Unknown' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/confidence=unknown/)
  await expect(paths.locator('tbody tr').first().getByText('Unknown', { exact: true })).toBeVisible()
  await paths.locator('tbody tr').first().getByRole('link').first().click()
  await expect(page).toHaveURL(/path=\d+/)
  await expect(page.getByRole('heading', { level: 2, name: 'Steps' })).toBeVisible()
  // A detail page (2026-10-14): a breadcrumb back to the list and the path's name as the h1.
  await expect(page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('link', { name: 'Attack paths' })).toBeVisible()
  await expect(page.getByRole('heading', { level: 1 })).not.toHaveText('Attack paths')
  await expect(page.getByText(/^Confidence: Unknown, its weakest step\./)).toBeVisible()
  // The first link's evidence: Argus could not judge the entry.
  await page.getByRole('button', { name: 'Evidence and fix' }).first().click()
  const evidence = page.getByRole('region', { name: /^Evidence and fix for the link: / })
  await expect(evidence).toBeVisible()
  await expect(evidence.getByText(/^rule internet-unverified@/)).toBeVisible()
  await expect(evidence.getByText(/^Break this link:/)).toBeVisible()
  await axe(page, 'attack path')
  await shot(page, '95-attack-path')
  // Open in map: the path's steps lit on the canvas.
  await page.getByRole('link', { name: 'Open in map' }).click()
  await expect(page).toHaveURL(/\/investigate\/map\?.*path=\d+/)
  await expect(page.getByRole('status').filter({ hasText: 'Showing attack path' })).toBeVisible()
  await axe(page, 'map with a path')
  await shot(page, '96-map-path')
})

test('posture: compliance frameworks and one framework, read-only', async ({ page }) => {
  await signIn(page)
  await navLink(page, 'Compliance')
  await expect(page).toHaveURL(/\/posture\/compliance$/)
  await expect(page.getByRole('heading', { level: 1, name: 'Compliance' })).toBeVisible()
  const frameworks = page.getByRole('table')
  await expect(frameworks).toBeVisible()
  await expect(frameworks.getByText('Not assessed')).toHaveCount(0) // the Demo estate scores both
  await axe(page, 'compliance')
  await shot(page, '80-compliance')
  // A search with no match says so, and Clear filters brings the list back.
  await page.getByLabel('Search', { exact: true }).fill('no-such-framework')
  await expect(page.getByText('No frameworks match these filters.')).toBeVisible()
  await page.getByRole('button', { name: 'Clear filters' }).first().click()
  await expect(frameworks).toBeVisible()
  // Provider (2026-10-15): AWS keeps every framework; GCP alone, not covered yet, matches none.
  await page.locator('#c-provider').click()
  await page.getByRole('listbox', { name: 'Provider' }).getByRole('option', { name: /^GCP/ }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/provider=gcp/)
  await expect(page.getByText('No frameworks match these filters.')).toBeVisible()
  await page.reload()
  await expect(page.getByText('No frameworks match these filters.')).toBeVisible()
  await page.getByRole('button', { name: 'Clear filters' }).first().click()
  await expect(page).toHaveURL(/\/posture\/compliance$/)
  await expect(frameworks).toBeVisible()

  // One framework: history with its ranges, accounts month by month, requirements.
  await frameworks.getByRole('link').first().click()
  await expect(page).toHaveURL(/\/posture\/compliance\/[^/?]+/)
  const nav = page.getByRole('navigation', { name: 'Primary' })
  await expect(nav.getByRole('link', { name: 'Compliance', exact: true })).toHaveAttribute('aria-current', 'page')
  // A detail page (2026-10-14): breadcrumb, header card with its facts, stat tiles.
  await expect(page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('link', { name: 'Compliance' })).toBeVisible()
  await expect(page.locator('dt', { hasText: 'Data through' })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Key metrics' }).getByText('Failing requirements')).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Score over time' })).toBeVisible()
  await expect(page.locator('svg[role="img"]').first()).toHaveAttribute('height', '270')
  await expect(page.getByRole('heading', { level: 2, name: 'Accounts, month over month' })).toBeVisible()
  // The panel names its framework and day, so a screenshot of it alone reads (2026-10-15).
  const accounts = page.getByRole('region', { name: 'Accounts, month over month' })
  await expect(accounts.getByText('Under 60')).toBeVisible()
  await expect(accounts.locator('.fw-line .fw-name')).not.toBeEmpty()
  await axe(page, 'framework')
  await shot(page, '81-framework')
  for (const range of ['Three months, weekly', 'One month, daily']) {
    await page.getByRole('button', { name: range }).click()
    await expect(page.getByRole('button', { name: range })).toHaveAttribute('aria-pressed', 'true')
  }
  // Choosing an account switches the page to it and keeps it in the URL.
  const account = page.getByRole('region', { name: 'Accounts, month over month' }).getByRole('button', { pressed: false }).first()
  await account.click()
  await expect(page).toHaveURL(/connection=\d+/)
  await expect(page.getByRole('region', { name: 'Accounts, month over month' }).getByRole('button', { pressed: true })).toHaveCount(1)
  await page.getByRole('group', { name: 'Status' }).getByRole('button', { name: 'Fail' }).click()
  await expect(page).toHaveURL(/status=FAIL/)
  await axe(page, 'framework, one account, failing requirements')
  await shot(page, '82-framework-one-account')
  await page.reload()
  await expect(page.getByRole('group', { name: 'Status' }).getByRole('button', { name: 'Fail' })).toHaveAttribute('aria-pressed', 'true')
  await page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('link', { name: 'Compliance' }).click()
  await expect(page).toHaveURL(/\/posture\/compliance\?connection=\d+$/)
})

test('phone width: overview and connections', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await signIn(page)
  await shot(page, '60-phone-overview')
  const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth)
  expect(scrollWidth, 'no horizontal page scroll').toBeLessThanOrEqual(390)
  await page.goto('/admin/connections')
  await expect(page.getByRole('heading', { level: 2, name: 'Connections' })).toBeVisible()
  await shot(page, '61-phone-connections')
  // The menu is a drawer behind the top bar's button; Escape returns focus to it.
  const menu = page.getByRole('button', { name: 'Open menu' })
  await menu.click()
  await expect(page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: 'Connections' })).toBeVisible()
  await axe(page, 'phone drawer')
  await shot(page, '62-phone-drawer')
  await page.keyboard.press('Escape')
  await expect(menu).toBeFocused()
  // A framework page fits too: its wide tables scroll inside their cards.
  await page.goto('/posture/compliance/cis_6.0_aws')
  await expect(page.getByRole('heading', { level: 2, name: 'Requirements' })).toBeVisible()
  const frameworkWidth = await page.evaluate(() => document.documentElement.scrollWidth)
  expect(frameworkWidth, 'no horizontal page scroll on a framework').toBeLessThanOrEqual(390)
  await shot(page, '63-phone-framework')
})

test('light theme: every screen passes axe, and the toggle cycles', async ({ page }) => {
  // The OS prefers light, so System (the default) draws the light theme (2026-10-14).
  await page.emulateMedia({ colorScheme: 'light' })
  await signIn(page)
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  const screens: [string, string, string][] = [
    ['/', 'Overview', 'L10-overview'],
    ['/posture/compliance', 'Compliance', 'L80-compliance'],
    ['/posture/compliance/cis_6.0_aws', 'CIS Amazon Web Services Foundations Benchmark v6.0.0', 'L81-framework'],
    ['/investigate/findings', 'Findings', 'L70-findings'],
    ['/investigate/resources', 'Resources', 'L72-resources'],
    ['/investigate/attack-paths', 'Attack paths', 'L94-attack-paths'],
    ['/scans/schedules', 'Schedules', 'L30-schedules'],
    ['/scans/runs', 'Runs', 'L40-runs'],
    ['/admin/connections', 'Connections', 'L20-connections'],
    ['/admin/settings', 'Settings', 'L50-settings'],
  ]
  for (const [path, heading, name] of screens) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible()
    await page.waitForLoadState('networkidle')
    await axe(page, `light ${heading}`)
    await shot(page, name)
  }
  // The map: a door's flow, and a selected node's path.
  await page.goto('/investigate/map')
  await page.getByRole('table').locator('tbody tr').first().getByRole('link').click()
  const flow = page.getByRole('application', { name: /^Resource map, \d+ resources/ })
  await expect(flow).toBeVisible()
  await flow.focus()
  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('Enter')
  await expect(page.getByRole('complementary', { name: 'Resource panel' })).toBeVisible()
  await axe(page, 'light map')
  await shot(page, 'L91-map')
  // The footer button cycles Light → Dark → System, and the page follows it.
  const theme = page.getByRole('button', { name: /^Theme: / })
  await expect(theme).toHaveAccessibleName('Theme: System — click to change')
  await theme.click()
  await expect(theme).toHaveAccessibleName('Theme: Light — click to change')
  await theme.click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await theme.click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
})

/** A user an admin adds signs in, must choose their own password, then sees only what their
 * role allows (ADR-0041). Both users are deleted at the end, so the walk leaves nothing behind. */
test('users and roles: a viewer and an operator, each limited to their role', async ({ page }) => {
  const stamp = Date.now()
  const first = 'set by the admin, e2e only'
  const own = 'chosen by the user, e2e only'
  const people = [
    { username: `e2e-viewer-${stamp}`, role: 'Viewer' },
    { username: `e2e-operator-${stamp}`, role: 'Operator' },
  ]

  await signIn(page)
  await navTo(page, 'Administration', 'Users')
  await expect(page).toHaveURL(/\/admin\/users$/)
  await expect(page.getByRole('cell', { name: /\(you\)/ })).toBeVisible()
  await axe(page, 'users')
  await shot(page, '70-users')
  for (const p of people) {
    await page.getByRole('button', { name: 'Add user' }).click()
    const add = page.getByRole('dialog', { name: 'Add user' })
    await add.getByLabel('Username').fill(p.username)
    await add.getByText(p.role, { exact: true }).click()
    await add.getByLabel('Password', { exact: true }).fill(first)
    if (p.role === 'Viewer') await axe(page, 'add user modal')
    await add.getByRole('button', { name: 'Add user' }).click()
    await expect(page.getByRole('status').filter({ hasText: `${p.username} added as ${p.role}` })).toBeVisible()
  }
  await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Sign out' }).click()

  for (const p of people) {
    await page.getByLabel('Username').fill(p.username)
    await page.getByLabel('Password', { exact: true }).fill(first)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Choose a new password' })).toBeVisible()
    if (p.role === 'Viewer') {
      await axe(page, 'choose a new password')
      await shot(page, '71-new-password')
    }
    await page.getByLabel('Current password').fill(first)
    await page.getByLabel('New password', { exact: true }).fill(own)
    await page.getByLabel('Repeat new password').fill(own)
    await page.getByRole('button', { name: 'Save and continue' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible()
    const nav = page.getByRole('navigation', { name: 'Primary' })
    await expect(nav.getByText(p.role, { exact: true })).toBeVisible()

    // Settings and Users are an admin's: not in the menu, and the address leads to the Overview.
    await navTo(page, 'Administration', 'Connections')
    await expect(nav.getByRole('link', { name: 'Settings', exact: true })).toHaveCount(0)
    await expect(nav.getByRole('link', { name: 'Users', exact: true })).toHaveCount(0)
    const canOperate = p.role === 'Operator'
    await expect(page.getByRole('button', { name: 'Add connection' })).toHaveCount(canOperate ? 1 : 0)
    if (canOperate) await expect(page.getByRole('switch').first()).toBeVisible()
    else await expect(page.getByRole('switch')).toHaveCount(0)
    if (!canOperate) {
      await axe(page, 'connections as a viewer')
      await shot(page, '72-connections-viewer')
    }
    await navLink(page, 'Schedules')
    await expect(page.getByRole('heading', { level: 2, name: 'Run now' })).toHaveCount(canOperate ? 1 : 0)
    await page.goto('/admin/settings')
    await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible()
    await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Sign out' }).click()
  }

  // Clean up: deactivate, then delete each one.
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await page.goto('/admin/users')
  page.on('dialog', (d) => void d.accept())
  for (const p of people) {
    await page.getByRole('button', { name: p.username, exact: true }).click()
    const edit = page.getByRole('dialog', { name: p.username })
    await edit.getByRole('switch').click()
    await edit.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByRole('status').filter({ hasText: `${p.username} saved.` })).toBeVisible()
    await page.getByRole('button', { name: p.username, exact: true }).click()
    await page.getByRole('dialog', { name: p.username }).getByRole('button', { name: 'Delete user' }).click()
    await expect(page.getByRole('status').filter({ hasText: `${p.username} deleted.` })).toBeVisible()
  }
})
