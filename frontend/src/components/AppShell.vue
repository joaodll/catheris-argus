<script setup lang="ts">
/**
 * The page frame: CatherIs Platform's shell in Titanium Signal colours (design-system.md, Shell;
 * ADR-0028, fifth amendment). Section labels, modules whose children are pages, an icon rail
 * collapsed from a round button on the sidebar's edge (≥ 768 px), a drawer behind a menu button
 * (< 768 px), the user block with an avatar, and the aurora behind the content.
 */
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { openModule, openModules, railMode, toggleModule } from '@/composables/useNavState'
import { ROLE_LABEL, can, session, signOut, username, type Role } from '@/composables/useSession'
import { cycleTheme, themeChoice, themeLabel } from '@/composables/useTheme'
import AppIcon from './AppIcon.vue'
import ChangePasswordModal from './ChangePasswordModal.vue'
import type { IconName } from './icons'

const route = useRoute()
const router = useRouter()

// `role`: shown only to that role and above (ADR-0041); the router refuses the page anyway.
type Child = { name: string; label: string; icon: IconName; role?: Role }
type Entry =
  | { kind: 'item'; name: string; label: string; icon: IconName }
  | { kind: 'section'; label: string }
  | { kind: 'module'; id: string; label: string; icon: IconName; children: Child[] }

const NAV: Entry[] = [
  { kind: 'item', name: 'overview', label: 'Overview', icon: 'overview' },
  { kind: 'section', label: 'Posture' },
  { kind: 'item', name: 'compliance', label: 'Compliance', icon: 'checklist' },
  { kind: 'section', label: 'Investigate' },
  { kind: 'item', name: 'misconfigurations', label: 'Misconfigurations', icon: 'flag' },
  { kind: 'item', name: 'vulnerabilities', label: 'Vulnerabilities', icon: 'bug' },
  { kind: 'item', name: 'resources', label: 'Resources', icon: 'stack' },
  { kind: 'item', name: 'resource-map', label: 'Resource map', icon: 'graph' },
  { kind: 'item', name: 'attack-paths', label: 'Attack paths', icon: 'route' },
  { kind: 'section', label: 'Operate' },
  { kind: 'item', name: 'schedules', label: 'Schedules', icon: 'calendar' },
  { kind: 'item', name: 'runs', label: 'Runs', icon: 'scans' },
  { kind: 'section', label: 'Administration' },
  {
    kind: 'module',
    id: 'admin',
    label: 'Administration',
    icon: 'admin',
    children: [
      { name: 'connections', label: 'Connections', icon: 'plug' },
      { name: 'settings', label: 'Settings', icon: 'admin', role: 'admin' },
      { name: 'users', label: 'Users', icon: 'users', role: 'admin' },
    ],
  },
]
const nav = computed(() =>
  NAV.map((e) => (e.kind === 'module' ? { ...e, children: e.children.filter((c) => !c.role || can(c.role)) } : e)),
)
const roleLabel = computed(() => (session.value ? ROLE_LABEL[session.value.role] : ''))
const displayName = computed(() => session.value?.display_name || username.value)
const changingPassword = ref(false)

// The rail exists only where the sidebar does (design-system.md, Breakpoints).
const sidebar = ref(true)
let media: MediaQueryList | null = null
const onMedia = (): void => {
  sidebar.value = media?.matches ?? true
}
const rail = computed(() => railMode.value && sidebar.value)
const drawerOpen = ref(false)
const flyout = ref<string | null>(null) // in the rail, the module whose children are shown
const navEl = ref<HTMLElement | null>(null)
const menuButton = ref<HTMLButtonElement | null>(null)

const currentModule = computed(() => {
  for (const e of nav.value) if (e.kind === 'module' && e.children.some((c) => c.name === route.name)) return e.id
  return null
})
/** A page under an item (a framework under Compliance) keeps that item current. */
function itemCurrent(name: string): boolean {
  return route.name === name || route.meta.navItem === name
}
const pageTitle = computed(() => String(route.meta.title ?? '').split(' · ')[0])
const initial = computed(() => (displayName.value ?? '?').slice(0, 1).toUpperCase())

function isOpen(id: string): boolean {
  return rail.value ? flyout.value === id : openModules.value.has(id)
}

function onModule(id: string): void {
  if (rail.value) flyout.value = flyout.value === id ? null : id
  else toggleModule(id)
}

watch(
  () => route.fullPath,
  () => {
    if (currentModule.value) openModule(currentModule.value)
    flyout.value = null
    // A chosen page closes the drawer; the router moves focus to the new page's heading.
    drawerOpen.value = false
  },
  { immediate: true },
)
watch(rail, () => (flyout.value = null))

function focusables(): HTMLElement[] {
  return [...(navEl.value?.querySelectorAll<HTMLElement>('a[href], button:not([disabled])') ?? [])].filter(
    (el) => el.offsetParent !== null && !el.closest('[inert]'),
  )
}

async function openDrawer(): Promise<void> {
  drawerOpen.value = true
  await nextTick()
  focusables()[0]?.focus()
}

function closeDrawer(): void {
  drawerOpen.value = false
  void nextTick(() => menuButton.value?.focus())
}

function onNavKey(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    if (flyout.value) flyout.value = null
    else if (drawerOpen.value) closeDrawer()
    return
  }
  if (event.key !== 'Tab' || !drawerOpen.value) return
  // The drawer traps focus while it is open.
  const items = focusables()
  const first = items[0]
  const last = items[items.length - 1]
  if (!first || !last) return
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}

function onPointerDown(event: PointerEvent): void {
  if (flyout.value && !navEl.value?.contains(event.target as Node)) flyout.value = null
}

onMounted(() => {
  media = window.matchMedia('(min-width: 768px)')
  onMedia()
  media.addEventListener('change', onMedia)
  document.addEventListener('pointerdown', onPointerDown)
})
onBeforeUnmount(() => {
  media?.removeEventListener('change', onMedia)
  document.removeEventListener('pointerdown', onPointerDown)
})

async function doSignOut(): Promise<void> {
  await signOut()
  await router.push({ name: 'sign-in', query: { reason: 'signed-out' } })
}
</script>

<template>
  <a class="skip" href="#main">Skip to content</a>
  <div class="shell" :class="{ 'is-rail': rail }">
    <header class="topbar">
      <button
        ref="menuButton"
        type="button"
        class="icon-btn menu"
        :aria-expanded="drawerOpen"
        aria-controls="primary-nav"
        aria-label="Open menu"
        @click="openDrawer"
      >
        <AppIcon name="menu" :size="20" />
      </button>
      <span class="mark small"><AppIcon name="shield" :size="15" :stroke="2" /></span>
      <span class="top-title">{{ pageTitle }}</span>
    </header>
    <div v-if="drawerOpen" class="backdrop" aria-hidden="true" @click="closeDrawer"></div>

    <nav id="primary-nav" ref="navEl" class="side" :class="{ 'is-open': drawerOpen }" aria-label="Primary" @keydown="onNavKey">
      <div class="brand">
        <span class="mark"><AppIcon name="shield" :size="16" :stroke="2" /></span>
        <span class="brand-text">
          <span class="name">CatherIs</span>
          <span class="product">Argus</span>
        </span>
      </div>

      <div class="links">
        <template v-for="entry in nav" :key="entry.kind === 'section' ? `s-${entry.label}` : entry.label">
          <template v-if="entry.kind === 'section'">
            <span class="navsec">{{ entry.label }}</span>
            <hr class="navrule">
          </template>
          <RouterLink
            v-else-if="entry.kind === 'item'"
            class="navlink"
            :class="{ 'is-current': itemCurrent(entry.name) }"
            :aria-current="itemCurrent(entry.name) ? 'page' : undefined"
            :to="{ name: entry.name }"
            :title="rail ? entry.label : undefined"
            :aria-label="rail ? entry.label : undefined"
          >
            <AppIcon :name="entry.icon" :size="15" /><span class="label">{{ entry.label }}</span>
          </RouterLink>
          <div v-else class="module">
            <button
              type="button"
              class="navlink modhead"
              :class="{ 'is-current': currentModule === entry.id }"
              :aria-expanded="isOpen(entry.id)"
              :aria-controls="`nav-${entry.id}`"
              :title="rail ? entry.label : undefined"
              :aria-label="rail ? entry.label : undefined"
              @click="onModule(entry.id)"
            >
              <AppIcon :name="entry.icon" :size="15" /><span class="label">{{ entry.label }}</span>
              <span class="chev"><AppIcon name="chevron" :size="13" :stroke="2.2" /></span>
            </button>
            <div :id="`nav-${entry.id}`" class="children" :class="{ 'is-open': isOpen(entry.id) }" :inert="!isOpen(entry.id)">
              <ul>
                <li v-for="c in entry.children" :key="c.name">
                  <RouterLink class="navlink child" :to="{ name: c.name }"><AppIcon :name="c.icon" :size="15" /><span>{{ c.label }}</span></RouterLink>
                </li>
              </ul>
            </div>
          </div>
        </template>
      </div>

      <div class="user">
        <span class="avatar" aria-hidden="true">{{ initial }}</span>
        <span class="who">
          <span class="who-name">{{ displayName }}</span>
          <span class="who-role">{{ roleLabel }}</span>
        </span>
        <button type="button" class="foot-btn" :title="themeLabel" :aria-label="themeLabel" @click="cycleTheme">
          <AppIcon :name="themeChoice === 'light' ? 'sun' : themeChoice === 'dark' ? 'moon' : 'monitor'" :size="14" />
        </button>
        <button type="button" class="foot-btn" title="Change password" aria-label="Change password" @click="changingPassword = true">
          <AppIcon name="key" :size="14" />
        </button>
        <button type="button" class="foot-btn" title="Sign out (signs out after 30 minutes idle)" aria-label="Sign out" @click="doSignOut">
          <AppIcon name="signout" :size="14" />
        </button>
      </div>
    </nav>
    <button
      type="button"
      class="railbtn"
      :aria-pressed="railMode"
      :aria-label="railMode ? 'Expand menu' : 'Collapse menu'"
      :title="railMode ? 'Expand menu' : 'Collapse menu'"
      @click="railMode = !railMode"
    >
      <AppIcon name="chevron" :size="12" :stroke="2.4" />
    </button>

    <div class="content">
      <div class="aurora" aria-hidden="true"></div>
      <main id="main" class="main"><slot /></main>
    </div>
  </div>
  <ChangePasswordModal v-if="changingPassword" @close="changingPassword = false" />
</template>

<style scoped>
.skip {
  position: absolute;
  left: -9999px;
  top: 8px;
  z-index: 100;
  padding: var(--s-8) var(--s-12);
  background: var(--accent);
  color: var(--on-accent);
  border-radius: var(--r-control);
}

.skip:focus {
  left: 8px;
}

.shell {
  --nav-w: var(--sidebar-w);

  display: grid;
  grid-template-columns: var(--nav-w) minmax(0, 1fr);
  min-height: 100vh;
  /* The nav column's colour and edge run the full page, under the sticky panel. */
  background: linear-gradient(
    to right,
    var(--bg-nav) calc(var(--nav-w) - 1px),
    var(--nav-border) calc(var(--nav-w) - 1px),
    var(--nav-border) var(--nav-w),
    transparent var(--nav-w)
  );
  transition: grid-template-columns 220ms ease-out;
}

.shell.is-rail {
  --nav-w: var(--rail-w);
}

.topbar,
.backdrop {
  display: none;
}

.side {
  position: sticky;
  top: 0;
  z-index: 20;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: var(--nav-wash), var(--bg-nav);
  border-right: 1px solid var(--nav-border);
}

.brand {
  display: flex;
  align-items: center;
  gap: var(--s-10);
  padding: var(--s-16) var(--s-14);
  border-bottom: 1px solid var(--nav-border);
}

.mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  flex-shrink: 0;
  border-radius: 8px;
  background: var(--accent-wash);
  border: 1px solid color-mix(in srgb, var(--accent) 32%, transparent);
  color: var(--accent);
}

.mark.small {
  width: 28px;
  height: 28px;
}

.brand-text {
  display: flex;
  flex-direction: column;
  min-width: 0;
  line-height: 1.25;
}

.name {
  font-size: 14px;
  font-weight: 700;
  white-space: nowrap;
}

.product {
  font-size: 10px;
  font-weight: 500;
  color: var(--text-3);
}

.links {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 1px;
  padding: var(--s-8);
  overflow-y: auto;
}

.navsec {
  display: block;
  padding: var(--s-12) var(--s-8) var(--s-4);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text-3);
}

.navrule {
  display: none;
  width: 100%;
  margin: var(--s-8) 0;
  border: 0;
  border-top: 1px solid var(--nav-border);
}

.navlink {
  display: flex;
  align-items: center;
  gap: var(--s-8);
  width: 100%;
  padding: 7px var(--s-8);
  border: 0;
  border-left: 2px solid transparent;
  border-radius: var(--r-control);
  background: none;
  color: var(--text-2);
  font: inherit;
  font-size: 13px;
  font-weight: 500;
  line-height: 1.25;
  text-align: left;
  text-decoration: none;
  white-space: nowrap;
  cursor: pointer;
  transition:
    background var(--ease),
    color var(--ease);
}

.navlink :deep(svg) {
  flex-shrink: 0;
  opacity: 0.7;
  transition: opacity var(--ease);
}

.navlink:hover {
  background: var(--surface-raised);
  color: var(--text);
}

.navlink:hover :deep(svg),
.navlink.router-link-exact-active :deep(svg),
.navlink.is-current :deep(svg) {
  opacity: 1;
}

.navlink.router-link-exact-active,
.navlink.is-current {
  background: var(--accent-wash);
  border-left-color: var(--accent);
  color: var(--text);
}

.modhead.is-current {
  background: none;
  border-left-color: transparent;
  color: var(--text);
}

.chev {
  display: inline-flex;
  margin-left: auto;
  color: var(--text-3);
  transition: transform 160ms ease-out;
}

.modhead[aria-expanded='true'] .chev {
  transform: rotate(90deg);
}

.module {
  position: relative;
}

.children {
  display: grid;
  grid-template-rows: 0fr;
  visibility: hidden;
  transition:
    grid-template-rows 160ms ease-out,
    visibility 160ms;
}

.children.is-open {
  grid-template-rows: 1fr;
  visibility: visible;
}

.children ul {
  min-height: 0;
  overflow: hidden;
  margin: 0;
  padding: 1px 0 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.navlink.child {
  padding-left: calc(var(--s-8) + 16px);
  font-size: 12.5px;
}

/* The round collapse button on the sidebar's edge. */
.railbtn {
  position: fixed;
  top: 72px;
  left: calc(var(--nav-w) - 12px);
  z-index: 25;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  padding: 0;
  border: 1px solid var(--border-strong);
  border-radius: 50%;
  background: var(--surface);
  color: var(--text-2);
  cursor: pointer;
  transition:
    left 220ms ease-out,
    color var(--ease),
    border-color var(--ease);
}

.railbtn :deep(svg) {
  transform: rotate(180deg);
}

.railbtn[aria-pressed='true'] :deep(svg) {
  transform: none;
}

.railbtn:hover {
  color: var(--text);
  border-color: var(--border-control);
}

.user {
  display: flex;
  align-items: center;
  gap: var(--s-8);
  padding: var(--s-12);
  border-top: 1px solid var(--nav-border);
}

.avatar {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  flex-shrink: 0;
  border-radius: 7px;
  background: var(--accent-wash);
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
}

.who {
  display: flex;
  flex-direction: column;
  min-width: 0;
  flex: 1;
  line-height: 1.3;
}

.who-name {
  font-size: 12px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.who-role {
  font-size: 10px;
  color: var(--text-3);
}

.foot-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  flex-shrink: 0;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: var(--r-control);
  background: none;
  color: var(--text-2);
  cursor: pointer;
}

.foot-btn:hover {
  background: var(--surface-raised);
  color: var(--text);
}

.content {
  position: relative;
  min-width: 0;
}

.main {
  position: relative;
  z-index: 1;
  width: 100%;
  min-width: 0;
  max-width: var(--content-max);
  margin-inline: auto;
  padding: var(--s-30) var(--s-34) var(--s-48);
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
}

/* The rail: icons only; a module's children open as a flyout beside it. */
.shell.is-rail .links {
  overflow: visible;
}

.shell.is-rail .brand-text,
.shell.is-rail .label,
.shell.is-rail .chev,
.shell.is-rail .navsec,
.shell.is-rail .who {
  display: none;
}

.shell.is-rail .navrule {
  display: block;
}

.shell.is-rail .brand {
  justify-content: center;
  padding-inline: 0;
}

.shell.is-rail .navlink:not(.child) {
  justify-content: center;
  padding: 7px 0;
}

.shell.is-rail .user {
  flex-direction: column;
  padding-inline: 0;
}

.shell.is-rail .children {
  position: absolute;
  top: 0;
  left: calc(100% + 8px);
  z-index: 30;
  display: none;
  min-width: 180px;
  padding: var(--s-6);
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--r-card);
  box-shadow: var(--shadow-sheet);
}

.shell.is-rail .children.is-open {
  display: block;
}

.shell.is-rail .children ul {
  overflow: visible;
  padding: 0;
}

.shell.is-rail .navlink.child {
  padding-left: var(--s-8);
}

@media (max-width: 767px) {
  .shell {
    grid-template-columns: minmax(0, 1fr);
    background: none;
  }

  .topbar {
    position: sticky;
    top: 0;
    z-index: 15;
    display: flex;
    align-items: center;
    gap: var(--s-10);
    min-height: 56px;
    padding: 0 var(--s-12);
    background: var(--bg-nav);
    border-bottom: 1px solid var(--nav-border);
  }

  .menu {
    width: 44px;
    height: 44px;
  }

  .top-title {
    font-size: 15px;
    font-weight: 600;
  }

  .backdrop {
    display: block;
    position: fixed;
    inset: 0;
    z-index: 40;
    background: var(--overlay);
  }

  .side {
    position: fixed;
    inset: 0 auto 0 0;
    z-index: 41;
    width: var(--drawer-w);
    transform: translateX(-100%);
    visibility: hidden;
    transition:
      transform 240ms ease-out,
      visibility 240ms;
  }

  .side.is-open {
    transform: none;
    visibility: visible;
  }

  .railbtn {
    display: none;
  }

  .navlink {
    min-height: 44px;
  }

  .main {
    padding: var(--s-20) var(--s-16) 40px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .shell,
  .chev,
  .children,
  .side,
  .railbtn {
    transition: none;
  }
}
</style>
