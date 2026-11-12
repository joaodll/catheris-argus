/**
 * The SSO walk (ADR-0048), against the `sso` profile's Keycloak: Argus on localhost:8080, the
 * identity provider on 127.0.0.1:8180, two sites, so the IdP's answer is a real cross-site post and
 * the browser's state cookie must cross with it. Run by the `e2e-sso` service, with the API started
 * with the SSO variables of docs/sso.md (Keycloak, development). Skipped without
 * ARGUS_E2E_SSO_PASSWORD, so the main walk can run without the IdP.
 *
 * It signs in as the realm's four users: alice (argus-admins), bob (argus-operators), carol
 * (argus-viewers, with a long email address) and dave (in no group).
 */
import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const SSO_PASSWORD = process.env.ARGUS_E2E_SSO_PASSWORD ?? ''
const SHOTS = 'e2e/screens'

test.skip(!SSO_PASSWORD, 'set ARGUS_E2E_SSO_PASSWORD and run the e2e-sso service')

const problems: string[] = []

test.beforeEach(({ page }) => {
  problems.length = 0
  page.on('console', (m) => {
    // Signed out, the app asks who it is once (401), as on the password walk.
    if (m.type() === 'error' && !/status of 401/.test(m.text())) problems.push(`console: ${m.text()}`)
  })
  page.on('pageerror', (e) => problems.push(`exception: ${e.message}`))
  page.on('response', (r) => {
    const url = r.url()
    if (r.status() >= 400 && !/127\.0\.0\.1:8180/.test(url) && !/401 .*\/api\/v1\/auth\/session/.test(`${r.status()} ${url}`)) {
      problems.push(`${r.status()} ${url}`)
    }
  })
})

test.afterEach(() => {
  expect(problems, 'console errors or failed requests').toEqual([])
})

async function axe(page: Page, label: string): Promise<void> {
  await page.waitForFunction(() =>
    document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity),
  )
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze()
  expect(
    results.violations.map((v) => `${label}: ${v.id} ${v.help} → ${v.nodes[0]?.target.join(' ')}`),
    `accessibility violations on ${label}`,
  ).toEqual([])
}

async function noSidewaysScroll(page: Page, name: string): Promise<void> {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow, `${name}: the page scrolls sideways`).toBeLessThanOrEqual(0)
  await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true })
}

/** From Argus's sign-in page, through the IdP's form, back to Argus. */
async function ssoSignIn(page: Page, user: string, start = '/'): Promise<void> {
  // Signing out of Argus doesn't sign out of the IdP (no single logout, ADR-0048): forget the
  // IdP's session, or it signs the last user straight back in.
  await page.context().clearCookies({ domain: '127.0.0.1' })
  await page.goto(start)
  await expect(page).toHaveURL(/\/sign-in/)
  await page.getByRole('link', { name: 'Sign in with SSO' }).click()
  await expect(page).toHaveURL(/127\.0\.0\.1:8180\/realms\/argus\//)
  await page.locator('#username').fill(user)
  await page.locator('#password').fill(SSO_PASSWORD)
  await page.locator('#kc-login').click()
}

test('sign in with SSO: each group gives its role, a user in none is refused', async ({ page }) => {
  await page.goto('/sign-in')
  await expect(page.getByRole('link', { name: 'Sign in with SSO' })).toBeVisible()
  await expect(page.getByRole('form', { name: 'Sign in with a password' })).toBeVisible()
  await axe(page, 'sign in with SSO on')
  await noSidewaysScroll(page, '80-sign-in-sso')

  // Where the user was going survives the trip through the IdP.
  await ssoSignIn(page, 'alice', '/admin/users')
  await expect(page).toHaveURL(/\/admin\/users$/)
  await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible()
  const alice = page.getByRole('row').filter({ hasText: 'alice@example.test' })
  await expect(alice).toContainText('SSO')
  await expect(alice).toContainText('from group argus-admins')
  await expect(page.getByRole('button', { name: 'Change password' })).toHaveCount(0)
  await axe(page, 'users with an SSO user')
  await noSidewaysScroll(page, '81-users-sso')

  await alice.getByRole('button').first().click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('Single sign-on. Their email address is their username.')).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Set a new password' })).toHaveCount(0)
  await expect(dialog.getByRole('radio').first()).toBeDisabled()
  await axe(page, 'edit an SSO user')
  await dialog.getByRole('button', { name: 'Cancel' }).click()

  await page.goto('/admin/settings')
  const card = page.getByRole('region', { name: 'Sign-in' })
  await expect(card).toContainText('On, with SAML')
  await expect(card).toContainText('http://localhost:8080/api/v1/auth/saml/acs')
  await expect(card.getByRole('cell', { name: 'argus-operators' })).toBeVisible()
  await axe(page, 'settings sign-in card')
  // A new theme is read at load, as the main walk's light test does.
  await page.emulateMedia({ colorScheme: 'light' })
  await page.reload()
  await expect(card).toContainText('On, with SAML')
  await axe(page, 'settings sign-in card, light')
  await page.emulateMedia({ colorScheme: 'dark' })
  await page.reload()
  await expect(card).toContainText('On, with SAML')
  await noSidewaysScroll(page, '82-settings-sign-in')
  await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/sign-in\?reason=signed-out/)

  for (const [user, role] of [['bob', 'Operator'], ['carol', 'Viewer']] as const) {
    await ssoSignIn(page, user)
    await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible()
    await expect(page.getByRole('navigation', { name: 'Primary' })).toContainText(role)
    await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Sign out' }).click()
    await expect(page).toHaveURL(/\/sign-in\?reason=signed-out/)
  }

  await ssoSignIn(page, 'dave')
  await expect(page).toHaveURL(/\/sign-in\?reason=sso-no-group/)
  await expect(page.getByRole('alert')).toContainText('in no group that grants access to Argus')
  await axe(page, 'sign in refused, no group')
  await page.emulateMedia({ colorScheme: 'light' })
  await page.reload()
  await expect(page.getByRole('alert')).toContainText('in no group that grants access to Argus')
  await axe(page, 'sign in refused, no group, light')
  await noSidewaysScroll(page, '83-sign-in-sso-no-group')
})

test('phone width: the sign-in page and a long SSO email in Users', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/sign-in')
  await noSidewaysScroll(page, '84-sign-in-sso-phone')
  await ssoSignIn(page, 'alice', '/admin/users')
  await expect(page.getByText('carol.with.a.rather.long.address@sub.example.test').first()).toBeVisible()
  await axe(page, 'users at phone width')
  await noSidewaysScroll(page, '85-users-sso-phone')
})
