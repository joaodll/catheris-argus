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
  // Audit what a person sees at rest: let entrances finish first.
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
  // Before two points of history (a new install's first month), words instead of lone dots, and
  // no "±0 pts" (2026-10-31 review).
  const notYet = page.getByText(/^Not enough history yet:/)
  await expect(notYet.or(page.getByRole('img', { name: /Open failed findings by severity over/ }))).toBeVisible()
  if (await notYet.isVisible()) await expect(page.getByText('Needs two months of history').first()).toBeVisible()

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
  await page.getByRole('link', { name: /^High: .* open, show in Misconfigurations$/ }).click()
  await expect(page).toHaveURL(/\/investigate\/misconfigurations\?severity=high&connection=\d+&tool=prowler&result=FAIL&muted=hide$/)
  await expect(page.getByRole('heading', { level: 1, name: 'Misconfigurations' })).toBeVisible()
  await page.goBack()
  await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: /^Open critical findings: .* Show in Misconfigurations$/ })).toHaveAttribute('href', /severity=critical/)
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
  // Run now ticks Vulnerabilities only where it has run (owner's decision, 2026-10-31): with no
  // connection chosen it is not ticked; every Demo connection has run it; a hand-made change
  // stays when the connections change.
  const runNow = page.getByRole('region', { name: 'Run now' })
  const vulnerabilitiesTick = runNow.getByRole('checkbox', { name: 'Vulnerabilities' })
  await expect(runNow.getByRole('checkbox', { name: 'Steampipe' })).toBeChecked()
  await expect(vulnerabilitiesTick).not.toBeChecked()
  await runNow.getByRole('button', { name: 'Select all' }).click()
  await expect(vulnerabilitiesTick).toBeChecked()
  await runNow.getByRole('checkbox', { name: 'CloudFox' }).uncheck()
  await runNow.getByRole('checkbox').first().uncheck()
  await expect(runNow.getByRole('checkbox', { name: 'CloudFox' })).not.toBeChecked()
  await shot(page, '29-run-now-ticks')
  await page.reload()
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

test('investigate: misconfigurations, vulnerabilities and resources, read-only', async ({ page }) => {
  await signIn(page)
  await navLink(page, 'Misconfigurations')
  await expect(page).toHaveURL(/\/investigate\/misconfigurations/)
  await expect(page.getByRole('heading', { level: 1, name: 'Misconfigurations' })).toBeVisible()
  // Summary | List (owner's decision 2026-11-05): the bare screen opens the summary, and every
  // number opens the list that reproduces it.
  const tabs = page.getByRole('tablist', { name: 'Misconfigurations views' })
  await expect(tabs.getByRole('tab', { name: 'Summary' })).toHaveAttribute('aria-selected', 'true')
  const severe = page.locator('.stat-card').filter({ hasText: 'Critical + high' })
  await expect(severe.locator('.stat-value')).toHaveText(/^[\d,]+$/)
  await expect(page.getByRole('heading', { level: 2, name: 'By category' })).toBeVisible()
  await page.waitForLoadState('networkidle')
  await axe(page, 'misconfigurations summary')
  await shot(page, '69-misconfigurations-summary')
  const severeCount = (await severe.locator('.stat-value').innerText()).trim()
  await severe.getByRole('link', { name: /Show in list$/ }).click()
  await expect(page).toHaveURL(/tab=list/)
  await expect(page).toHaveURL(/severity=critical&severity=high/)
  await expect(tabs.getByRole('tab', { name: 'List' })).toHaveAttribute('aria-selected', 'true')
  await expect(page.locator('.panel-foot .total')).toHaveText(new RegExp(`^${severeCount} records?$`))
  // An age column opens the list with the first-seen range that reproduces it.
  await tabs.getByRole('tab', { name: 'Summary' }).click()
  const age = page.getByRole('link', { name: /^Under 30 days: / })
  const ageCount = ((await age.getAttribute('aria-label')) ?? '').match(/^Under 30 days: ([\d,]+) open/)?.[1] ?? 'missing'
  await age.click()
  await expect(page).toHaveURL(/first_seen_from=/)
  await expect(page.locator('.panel-foot .total')).toHaveText(new RegExp(`^${ageCount} records?$`))
  // The arrow keys move between the tabs; the list keeps its account.
  await tabs.getByRole('tab', { name: 'List' }).focus()
  await page.keyboard.press('ArrowLeft')
  await expect(tabs.getByRole('tab', { name: 'Summary' })).toBeFocused()
  await expect(page).toHaveURL(/tab=summary/)
  await tabs.getByRole('tab', { name: 'List' }).click()
  await expect(page).toHaveURL(/tab=list/)
  // The list steps below start from a fresh list (More filters closed).
  await page.goto('/investigate/misconfigurations?tab=list')
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
  // By check (2026-10-31): each check once, with its findings; a group opens the list
  // filtered to its check, as many findings as it counted.
  await page.getByRole('group', { name: 'View' }).getByRole('button', { name: 'By check' }).click()
  await expect(page).toHaveURL(/view=checks/)
  await expect(page.getByRole('heading', { level: 2, name: 'Checks with findings' })).toBeVisible()
  const byCheck = page.getByRole('table')
  await expect(byCheck.getByRole('columnheader', { name: 'Accounts' })).toBeVisible()
  await axe(page, 'findings by check')
  await shot(page, '75-findings-by-check')
  const group = byCheck.locator('tbody tr').first()
  const counted = (await group.locator('td[data-label="Findings"]').innerText()).trim()
  await group.locator('.group-link').click()
  await expect(page).not.toHaveURL(/view=checks/)
  await expect(page).toHaveURL(/check=/)
  await expect(page.locator('.panel-foot')).toContainText(new RegExp(`(^|\\D)${counted} records?`))
  await page.getByRole('button', { name: 'Clear filters' }).first().click()
  await expect(page).not.toHaveURL(/check=/)

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
  for (const block of ['Steampipe', 'Prowler', 'CloudFox', 'Connections']) {
    await expect(sheet.getByRole('heading', { level: 3, name: new RegExp(`^${block}`) })).toBeVisible()
  }
  await axe(page, 'resource sheet')
  await shot(page, '73-resource-sheet')
  await page.keyboard.press('Escape')
  await expect(page).not.toHaveURL(/open=/)
  await expect(first).toBeFocused()
  // A resource facing the internet: the sheet shows its verdict and evidence.
  await page.getByLabel('Search', { exact: true }).fill('prod-edge-alb')
  await resources.locator('tbody tr', { hasText: 'prod-edge-alb' }).first().getByRole('link').click()
  await expect(sheet.getByRole('heading', { level: 3, name: 'From the internet' })).toBeVisible()
  // The why-line reads the rule's evidence.
  await expect(sheet.getByText(/^tcp\/443 · IPv4 and IPv6/)).toBeVisible()
  await shot(page, '73a-resource-sheet-reach')
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
  // CVEs (ADR-0042): the Vulnerabilities filter, then a resource's Vulnerabilities block, which
  // names the provider's scanner (AWS Inspector on the Demo estate).
  await page.goto('/investigate/resources')
  await page.getByLabel('Vulnerabilities').selectOption('exploitable')
  await expect(resources.locator('tbody tr').first().getByText('Exploit')).toBeVisible()
  await axe(page, 'resources with an exploitable CVE')
  await shot(page, '73c-resources-vulnerabilities')
  await resources.locator('tbody tr').first().getByRole('link').click()
  const vulns = sheet.getByRole('region', { name: /^Vulnerabilities/ })
  await expect(vulns.getByRole('heading', { level: 3, name: /^Vulnerabilities/ })).toBeVisible()
  await expect(vulns.getByText(/by AWS Inspector/).first()).toBeVisible()
  await expect(vulns.getByRole('link', { name: /^See all \d+ vulnerabilit(y|ies)/ })).toBeVisible()
  await axe(page, 'resource sheet vulnerabilities')
  await shot(page, '73d-resource-sheet-vulnerabilities')
  // Its "See all" opens Vulnerabilities on the resource.
  await vulns.getByRole('link', { name: /^See all \d+ vulnerabilit(y|ies)/ }).click()
  await expect(page).toHaveURL(/\/investigate\/vulnerabilities\?resource=\d+$/)
  await expect(page.getByRole('button', { name: 'Remove resource filter' })).toBeVisible()

  // Vulnerabilities (owner's decision, 2026-10-31): CVEs apart from Misconfigurations.
  await navLink(page, 'Vulnerabilities')
  await expect(page).toHaveURL(/\/investigate\/vulnerabilities$/)
  await expect(page.getByRole('heading', { level: 1, name: 'Vulnerabilities' })).toBeVisible()
  const cves = page.getByRole('table')
  await expect(cves.locator('tbody tr.row').first()).toContainText(/CVE-\d{4}-\d+|CWE-/)
  await axe(page, 'vulnerabilities')
  await shot(page, '75-vulnerabilities')
  // A row's details name the scanner and the vulnerable package.
  await cves.locator('tbody tr.row').first().locator('.lead').click()
  await expect(page.getByText('Scanner', { exact: true })).toBeVisible()
  await expect(page.getByText('AWS Inspector', { exact: true }).first()).toBeVisible()
  await axe(page, 'vulnerability details')
  await shot(page, '75b-vulnerability-details')
  // Public exploit and Fix filter on the vulnerability's own facts, kept in the URL.
  await page.getByLabel('Public exploit').check()
  await expect(page).toHaveURL(/exploit=1/)
  await expect(cves.locator('tbody tr.row').first().getByText('Exploit')).toBeVisible()
  await page.getByRole('group', { name: 'Fix' }).getByRole('button', { name: 'Available' }).click()
  await expect(page).toHaveURL(/fix=available/)
  // By CVE: each CVE once; a CVE opens the list filtered to it.
  await page.getByRole('group', { name: 'View' }).getByRole('button', { name: 'By CVE' }).click()
  await expect(page.getByRole('heading', { level: 2, name: 'CVEs with findings' })).toBeVisible()
  await axe(page, 'vulnerabilities by CVE')
  await shot(page, '75c-vulnerabilities-by-cve')
  await page.getByRole('button', { name: /^Show the \d+ findings? of / }).first().click()
  await expect(page).toHaveURL(/check=/)
  await expect(page.getByRole('button', { name: 'Remove CVE filter' })).toBeVisible()
  // A link from before the split lands on the right list.
  await page.goto('/investigate/findings?tool=vulnerabilities')
  await expect(page).toHaveURL(/\/investigate\/vulnerabilities\?tool=vulnerabilities$/)
  await page.goto('/investigate/findings')
  await expect(page).toHaveURL(/\/investigate\/misconfigurations$/)
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
    ['/investigate/misconfigurations', 'Misconfigurations', 'L70-misconfigurations'],
    ['/investigate/misconfigurations?tab=list', 'Misconfigurations', 'L71-misconfigurations-list'],
    ['/investigate/vulnerabilities', 'Vulnerabilities', 'L75-vulnerabilities'],
    ['/investigate/resources', 'Resources', 'L72-resources'],
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
    await add.getByLabel('Email address').fill(`${p.username}@example.com`)
    await add.getByText(p.role, { exact: true }).click()
    await add.getByLabel('Password', { exact: true }).fill(first)
    if (p.role === 'Viewer') await axe(page, 'add user modal')
    await add.getByRole('button', { name: 'Add user' }).click()
    await expect(page.getByRole('status').filter({ hasText: `${p.username} added as ${p.role}` })).toBeVisible()
    await expect(page.getByRole('cell', { name: `${p.username}@example.com` })).toBeVisible()
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

    // Users is an admin's, and Settings is not a viewer's: not in the menu, and the address leads
    // to the Overview. An operator's Settings holds the Collection card alone.
    await navTo(page, 'Administration', 'Connections')
    const canOperate = p.role === 'Operator'
    await expect(nav.getByRole('link', { name: 'Settings', exact: true })).toHaveCount(canOperate ? 1 : 0)
    await expect(nav.getByRole('link', { name: 'Users', exact: true })).toHaveCount(0)
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
    if (canOperate) {
      await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible()
      await expect(page.getByRole('region', { name: 'Collection and throttling' })).toBeVisible()
      for (const other of ['Retention', 'Raw output storage', 'Platform identity']) {
        await expect(page.getByRole('region', { name: other })).toHaveCount(0)
      }
      await axe(page, 'settings as an operator')
      await shot(page, '73-settings-operator')
    } else {
      await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible()
    }
    await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Sign out' }).click()
  }

  // Clean up: deactivate, then delete each one. Signed in first: leaving the page before the
  // sign-in answers would cancel it.
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible()
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
