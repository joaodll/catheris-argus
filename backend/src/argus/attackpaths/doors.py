"""The doors path kinds read as `d` (ADR-0037, second amendment): every resource the internet
reaches, with the ports it is open on and whether one is an administrative or data port.

    d(uid, ports, admin_port, policy)

A door is what the search seeds from (search.entries): Argus's own internet verdict (ROUTES_TO,
PUBLIC_RESTRICTED, PUBLIC_UNVERIFIED from a rule) or CloudFox's INTERNET_REACHABLE. Its ports
come from Argus's verdict when it has one (ADR-0035): what gets in (`open`) when Reachable; when
Restricted or Unknown, what its groups open on any interface and in either family (`network`,
and a Restricted door's `open_ports`), what one change would let in. CloudFox's ports count
only for a door Argus has no verdict on, so a port a network ACL blocks never makes an exposure
path "confirmed". Labels are the rules' own: "tcp/22", "tcp/1000-2000", "udp/53", "icmp",
"all". `policy`: the door is a resource public by its own policy (`via` resource_policy, wave
2), whatever its ports.
"""

# The ports of Prowler's ec2_instance_port_*_exposed_to_internet checks (check_ports in each
# check, read from the worker image at 5.44.0 on 2026-10-22; unchanged in 5.45.0): remote
# access (ssh, rdp, telnet, ftp), directories (kerberos, ldap), file sharing (cifs), databases
# and caches (cassandra, elasticsearch and kibana, kafka, memcached, mongodb, mysql, oracle,
# postgresql, redis, sqlserver). Prowler matches TCP only, a range that covers one of them,
# and protocol -1.
ADMIN_PORTS: tuple[int, ...] = (
    20, 21, 22, 23, 88, 139, 389, 445, 464, 636, 749, 750, 1433, 1434, 1521, 2483, 2484, 3306,
    3389, 5432, 5601, 6379, 7000, 7001, 7199, 9042, 9092, 9160, 9200, 9300, 11211, 27017, 27018,
)  # fmt: skip

_ADMIN = ", ".join(str(p) for p in ADMIN_PORTS)
_ARRAY = "CASE WHEN jsonb_typeof({0}) = 'array' THEN {0} ELSE '[]' END"

# Exported SQL: the view `d`, read beside `e` (the effective edges) by the path kinds.
DOORS_SQL = f"""
  SELECT x.uid,
         COALESCE(array_agg(DISTINCT x.label ORDER BY x.label)
                    FILTER (WHERE x.label IS NOT NULL), '{{}}') AS ports,
         -- CASE, not AND: only a label of one or two port numbers of at most five digits ever
         -- reaches the casts, whatever order the planner picks (a tool's malformed output never
         -- fails the ingest).
         COALESCE(bool_or(
           CASE WHEN x.label = 'all' THEN true
                WHEN x.label ~ '^(tcp|6)/[0-9]{{1,5}}(-[0-9]{{1,5}})?$' THEN EXISTS (
                  SELECT 1 FROM unnest(ARRAY[{_ADMIN}]) a(port)
                  WHERE a.port BETWEEN split_part(split_part(x.label, '/', 2), '-', 1)::int
                    AND COALESCE(NULLIF(split_part(split_part(x.label, '/', 2), '-', 2), ''),
                                 split_part(split_part(x.label, '/', 2), '-', 1))::int)
                ELSE false END),
           false) AS admin_port,
         COALESCE(bool_or(x.policy), false) AS policy
  FROM (
    SELECT door.target_uid AS uid, l.label,
           door.attributes ->> 'via' = 'resource_policy' AS policy
    FROM (
      SELECT de.*, bool_or(starts_with(de.origin, 'rule:')) OVER (PARTITION BY de.target_uid)
               AS judged
      FROM e de
      WHERE de.source_uid = 'internet'
        AND ((starts_with(de.origin, 'rule:')
              AND de.type IN ('ROUTES_TO', 'PUBLIC_RESTRICTED', 'PUBLIC_UNVERIFIED'))
             OR de.type = 'INTERNET_REACHABLE')
    ) door
    LEFT JOIN LATERAL (
      SELECT o AS label
      FROM jsonb_array_elements_text({_ARRAY.format("door.attributes -> 'open'")}) o
      WHERE door.type = 'ROUTES_TO'
      UNION ALL
      SELECT o FROM jsonb_array_elements_text({_ARRAY.format("door.attributes -> 'open_ports'")}) o
      WHERE door.type = 'PUBLIC_RESTRICTED'
      UNION ALL
      SELECT o FROM jsonb_array_elements({_ARRAY.format("door.attributes -> 'network'")}) n
      CROSS JOIN LATERAL (VALUES (n -> 'open' -> 'ipv4'), (n -> 'open' -> 'ipv6')) f(fam)
      CROSS JOIN LATERAL jsonb_array_elements_text({_ARRAY.format("f.fam")}) o
      WHERE door.type IN ('PUBLIC_RESTRICTED', 'PUBLIC_UNVERIFIED')
      UNION ALL
      -- CloudFox: endpoints name one port ("443", https), network-ports a list
      -- ("80,443,8000-8100", tcp or udp).
      SELECT CASE WHEN lower(COALESCE(door.attributes ->> 'protocol', '')) = 'udp' THEN 'udp/'
                  ELSE 'tcp/' END || trim(p)
      FROM regexp_split_to_table(
             COALESCE(door.attributes ->> 'ports', door.attributes ->> 'port', ''), ',') p
      WHERE door.type = 'INTERNET_REACHABLE' AND trim(p) ~ '^[0-9]{{1,5}}(-[0-9]{{1,5}})?$'
    ) l ON true
    -- Argus's verdict when it has one, else CloudFox's.
    WHERE door.judged = starts_with(door.origin, 'rule:')
  ) x
  GROUP BY x.uid
"""  # noqa: S608 - fixed fragments, no input
