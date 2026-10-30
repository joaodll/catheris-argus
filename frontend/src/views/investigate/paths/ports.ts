/**
 * Port names (docs/ui/screens.md, E12, Port names): "tcp/22 (SSH)". The services in Prowler's
 * own port checks (backend/src/argus/attackpaths/doors.py, ADMIN_PORTS), plus the web
 * and Windows ports. Only a single port is named; a range or an unknown port stays as it is.
 */

const TCP: Record<number, string> = {
  20: 'FTP',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  53: 'DNS',
  80: 'HTTP',
  88: 'Kerberos',
  139: 'SMB',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  464: 'Kerberos',
  636: 'LDAPS',
  749: 'Kerberos',
  750: 'Kerberos',
  1433: 'SQL Server',
  1434: 'SQL Server',
  1521: 'Oracle',
  2483: 'Oracle',
  2484: 'Oracle',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5601: 'Kibana',
  5985: 'WinRM',
  5986: 'WinRM',
  6379: 'Redis',
  7000: 'Cassandra',
  7001: 'Cassandra',
  7199: 'Cassandra',
  8080: 'HTTP',
  8443: 'HTTPS',
  9042: 'Cassandra',
  9092: 'Kafka',
  9160: 'Cassandra',
  9200: 'Elasticsearch',
  9300: 'Elasticsearch',
  11211: 'Memcached',
  27017: 'MongoDB',
  27018: 'MongoDB',
}
const UDP: Record<number, string> = { 53: 'DNS' }
// The rules write "tcp/22"; a security group's protocol number ("6/22") counts too.
const PROTOCOL: Record<string, 'tcp' | 'udp'> = { tcp: 'tcp', '6': 'tcp', udp: 'udp', '17': 'udp' }
const SINGLE = /^([a-z0-9]+)\/(\d{1,5})$/

/** "tcp/22" -> "tcp/22 (SSH)"; "all" -> "all ports"; anything else as it is. */
export function portLabel(label: string): string {
  if (label === 'all') return 'all ports'
  const m = SINGLE.exec(label)
  if (!m) return label
  const protocol = PROTOCOL[m[1]!]
  const name = protocol === 'tcp' ? TCP[Number(m[2])] : protocol === 'udp' ? UDP[Number(m[2])] : undefined
  return name ? `${label} (${name})` : label
}

/** Labels in reading order: by protocol, then by first port; "all" first. */
export function sortPorts(labels: string[]): string[] {
  const key = (l: string): [number, string, number] => {
    if (l === 'all') return [0, '', 0]
    const [protocol = l, ports = ''] = l.split('/')
    const first = Number(ports.split('-')[0])
    return [1, protocol, Number.isFinite(first) ? first : Number.MAX_SAFE_INTEGER]
  }
  return [...new Set(labels)].sort((a, b) => {
    const [ka, kb] = [key(a), key(b)]
    return ka[0] - kb[0] || ka[1].localeCompare(kb[1]) || ka[2] - kb[2] || a.localeCompare(b)
  })
}
