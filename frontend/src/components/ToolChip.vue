<script setup lang="ts">
/** Which tool a finding, run or schedule comes from: its name, tinted in the tool's colour
 * (design-system.md, Tool chip). The name carries the meaning; the colour helps scanning. */
import { COLLECTORS } from '@/tools'

const NAMES: Record<string, string> = Object.fromEntries(COLLECTORS.map((c) => [c.id, c.name]))
defineProps<{ tool: string }>()
</script>

<template>
  <span class="chip tool" :class="NAMES[tool] ? `tool-${tool}` : null">{{ NAMES[tool] ?? tool }}</span>
</template>

<style scoped>
/* Fill 10% and border 35% of the tool colour over whatever the chip sits on; the text in the
   full colour is at least 6.2:1 on every surface (surface-active is the darkest case). */
.tool-prowler {
  --tool: var(--tool-prowler);
}

.tool-steampipe {
  --tool: var(--tool-steampipe);
}

.tool-cloudfox {
  --tool: var(--tool-cloudfox);
}

.tool-inspector {
  --tool: var(--tool-inspector);
}

.tool[class*='tool-'] {
  color: var(--tool);
  background: color-mix(in srgb, var(--tool) 10%, transparent);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--tool) 35%, transparent);
}
</style>
