<script setup lang="ts">
/**
 * Sign-in (ADR-0048), read-only for Admins: how people sign in, set in the deployment and never
 * here, since whoever could change the identity provider could choose who is Admin. It also gives
 * what the identity provider's set-up needs: Argus's entity id and reply URL.
 */
import { api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import { ROLE_LABEL } from '@/composables/useSession'
import { useResource } from '@/composables/useResource'
import SettingsCard from './SettingsCard.vue'

const signIn = useResource(() => unwrap(api.GET('/api/v1/settings/sign-in')))
</script>

<template>
  <SettingsCard id="sign-in" title="Sign-in" description="How people sign in. Set in the Helm values (auth.*), or in .env on Docker Compose." readonly>
    <AlertBanner v-if="signIn.error.value" kind="fail">Sign-in didn't load: {{ signIn.error.value }}</AlertBanner>
    <div v-else-if="!signIn.data.value" aria-busy="true" class="skeleton sk-48"></div>
    <template v-else>
      <dl class="facts">
        <dt class="lbl">Password sign-in</dt>
        <dd>{{ signIn.data.value.local ? 'On' : 'Off' }}</dd>
        <dt class="lbl">Single sign-on</dt>
        <dd>{{ signIn.data.value.sso ? 'On, with SAML' : 'Off' }}</dd>
        <template v-if="signIn.data.value.sso">
          <dt class="lbl">Argus address</dt>
          <dd class="mono">{{ signIn.data.value.public_url }}</dd>
          <dt class="lbl">Argus entity id</dt>
          <dd class="mono">{{ signIn.data.value.sp_entity_id }}</dd>
          <dt class="lbl">Reply URL</dt>
          <dd class="mono">{{ signIn.data.value.acs_url }}</dd>
          <dt class="lbl">Identity provider</dt>
          <dd class="mono">{{ signIn.data.value.idp_entity_id }}</dd>
          <dt class="lbl">Groups attribute</dt>
          <dd class="mono">{{ signIn.data.value.groups_attribute }}</dd>
          <dt class="lbl">Email from</dt>
          <dd><span v-if="signIn.data.value.email_attribute" class="mono">{{ signIn.data.value.email_attribute }}</span><span v-else>the NameID</span></dd>
        </template>
      </dl>
      <table v-if="signIn.data.value.group_roles.length" class="table dense map">
        <caption class="cap">Each group the identity provider sends gives a role. The highest wins; someone in none is refused.</caption>
        <thead><tr><th scope="col">Group</th><th scope="col">Role</th></tr></thead>
        <tbody>
          <tr v-for="g in signIn.data.value.group_roles" :key="g.group">
            <td class="mono group">{{ g.group }}</td>
            <td>{{ ROLE_LABEL[g.role] }}</td>
          </tr>
        </tbody>
      </table>
      <p v-if="signIn.data.value.local" class="cap">While password sign-in is on, Admins can still create local users of any role.</p>
    </template>
  </SettingsCard>
</template>

<style scoped>
.facts {
  display: grid;
  grid-template-columns: 160px minmax(0, 1fr);
  gap: var(--s-8) var(--s-16);
  margin: 0;
}
.facts dt {
  margin: 0;
}
.facts dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.map caption {
  text-align: left;
  caption-side: top;
  padding-bottom: var(--s-8);
}
.group {
  overflow-wrap: anywhere;
}
@media (max-width: 600px) {
  .facts {
    grid-template-columns: minmax(0, 1fr);
    gap: var(--s-4);
  }
  .facts dd {
    margin-bottom: var(--s-8);
  }
}
</style>
