<script setup lang="ts">
/**
 * The Security view panel's Routes tab (W6 §5, §11.7): the open routes whose listed steps pass
 * this resource, worst first, ten at most. The list's own defaults (state open, Latent hidden),
 * so the count is what "See all in Attack paths" opens. Play opens the Map's Attack Path view at
 * the first listed target and step that touch this resource (the API's through_target and
 * through_step).
 */
import { computed } from 'vue'
import { api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import { useResource } from '@/composables/useResource'
import { utc } from '@/format'
import RouteClassBadge from '../paths/RouteClassBadge.vue'
import { routeTitle, type Names, type RouteOut } from '../paths/routeWords'

const props = defineProps<{ resourceId: number; names: Names }>()
const emit = defineEmits<{ play: [at: { route: number; target: number; step: number }] }>()

const LIMIT = 10
const list = useResource(() => unwrap(api.GET('/api/v1/attack-paths', { params: { query: { through: props.resourceId, limit: LIMIT } } })), {
  watch: [() => props.resourceId],
})
const page = computed(() => list.data.value ?? null)
const evaluation = computed(() => page.value?.evaluation ?? null)
const heading = computed(() => {
  const total = page.value?.total ?? 0
  if (total === 0) return "On no open route's listed steps."
  return `On ${total.toLocaleString('en-US')} open ${total === 1 ? "route's" : "routes'"} listed steps.`
})
const allLink = computed(() => ({ name: 'attack-paths', query: { through: String(props.resourceId) } }))

function play(r: RouteOut): void {
  emit('play', { route: r.id, target: r.through_target ?? 1, step: r.through_step ?? 1 })
}
</script>

<template>
  <div class="routes">
    <AlertBanner v-if="list.error.value" kind="fail">
      Routes didn't load: {{ list.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="list.reload">Retry</button></template>
    </AlertBanner>
    <div v-else-if="!page" class="loading" aria-busy="true" aria-label="Loading routes">
      <div v-for="n in 3" :key="n" class="skeleton sk-row"></div>
    </div>
    <p v-else-if="evaluation && evaluation.evaluated_at == null" class="cap">Routes haven't been worked out yet.</p>
    <template v-else>
      <p v-if="evaluation?.behind && evaluation.evaluated_at" class="cap behind">
        <AppIcon name="info" :size="14" />Routes are behind the scans: worked out at {{ utc(evaluation.evaluated_at) }}.
      </p>
      <p class="count">{{ heading }}</p>
      <ul v-if="page.items.length" class="rows">
        <li v-for="r in page.items" :key="r.id" class="row">
          <span class="row-head">
            <SeverityTag :severity="r.severity" compact />
            <span class="row-title" :title="routeTitle(r, names)">{{ routeTitle(r, names) }}</span>
          </span>
          <span class="row-foot">
            <RouteClassBadge :cls="r.worst_class" />
            <span class="row-actions">
              <button type="button" class="btn btn-secondary btn-sm" :aria-label="`Play ${routeTitle(r, names)} on the map`" @click="play(r)">
                <AppIcon name="play" :size="14" />Play
              </button>
              <RouterLink class="btn btn-ghost btn-sm" :to="{ name: 'attack-paths', query: { route: String(r.id), target: r.through_target && r.through_target > 1 ? String(r.through_target) : undefined } }">
                Details<span class="sr-only"> of {{ routeTitle(r, names) }}</span>
              </RouterLink>
            </span>
          </span>
        </li>
      </ul>
      <RouterLink v-if="page.total > 0" class="all" :to="allLink">See all in Attack paths</RouterLink>
    </template>
  </div>
</template>

<style scoped>
.routes {
  display: flex;
  flex-direction: column;
  gap: var(--s-12);
}

.cap,
.count {
  margin: 0;
  font-size: 12.5px;
  color: var(--text-2);
}

.count {
  color: var(--text);
}

.behind {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.sk-row {
  height: 64px;
  border-radius: var(--r-tile);
}

.rows {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  margin: 0;
  padding: 0;
  list-style: none;
}

.row {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding: var(--s-10) var(--s-12);
  border: 1px solid var(--border);
  border-radius: var(--r-tile);
  background: var(--surface-raised);
}

.row-head {
  display: flex;
  align-items: flex-start;
  gap: var(--s-8);
  min-width: 0;
}

/* The title: two lines at most, the whole in its title. */
.row-title {
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  overflow-wrap: anywhere;
}

.row-foot {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-8);
}

.row-actions {
  display: inline-flex;
  gap: var(--s-6);
}

.row-actions .btn {
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
}

@media (pointer: coarse) {
  .row-actions .btn {
    min-height: 44px;
    min-width: 44px;
  }
}

.all {
  font-size: 13px;
}
</style>
