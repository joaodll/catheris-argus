/**
 * The Settings page's "On this page" list (docs/ui/screens.md, E5, Layout): each SettingsCard
 * registers its title and whether it has unsaved changes; the page lists them in that order.
 */
import { reactive, type InjectionKey } from 'vue'

export interface SettingsSection {
  id: string
  title: string
  dirty: boolean
}

export interface SettingsSections {
  /** The cards in the order they rendered. */
  list: SettingsSection[]
  set(section: SettingsSection): void
  remove(id: string): void
}

export const SETTINGS_SECTIONS: InjectionKey<SettingsSections> = Symbol('settings-sections')

export function settingsSections(): SettingsSections {
  const list = reactive<SettingsSection[]>([])
  return {
    list,
    set(section) {
      const at = list.findIndex((s) => s.id === section.id)
      if (at === -1) list.push(section)
      else list.splice(at, 1, section)
    },
    remove(id) {
      const at = list.findIndex((s) => s.id === id)
      if (at !== -1) list.splice(at, 1)
    },
  }
}
