"""The relationship-rule engine.

A rule is a TOML file: id, version, edge_type, description, and one SQL query. The query reads
`r`, the day's resources for one connection (inventory exports the view):

    r(uid, type, native_id, name, region, vpc_id, config)

and returns (source_uid, target_uid, attributes jsonb). Rules run in a READ ONLY transaction,
so a rule can never write; their edges are then written by load_edges(). Every edge carries
origin rule:<id>@<version>, so a rule change shows up in history.

Rules also read three views built from `r` (RULE_VIEWS_SQL). Rules that follow a host name
(Route53, CloudFront origins, API integrations; ADR-0033) read `h`, the day's host index:

    h(host, uid, rank)

host is lower-case, with no trailing dot and no "dualstack." prefix; a rule normalises its own
side the same way. rank 1 is the resource that serves the host (a load balancer, a
distribution, an API, a bucket, a database, a function URL), 2 a custom domain resource, 3 a
Route53 record of that name: a rule takes the lowest rank per host. A host no resource owns
becomes the pseudo-node external:<host>; write_edges() records the AWS-owned ones as
unresolved references, so a broken join stays visible.

The internet rules (ADR-0035) read `g`, every security group ingress rule, and `p`, what faces
the internet and whether traffic can really arrive (open, restricted or unknown):

    g(group_id, protocol, from_port, to_port, ports, source, anywhere, family)
    p(uid, reach, attributes)

`p` is built from route tables (`rt`), network ACL entries (`na`), the resources that sit in a
VPC and are public by their settings (`vc`) and their verdict per address family (`vf`, `vv`;
ADR-0035, second amendment).
"""

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine, text

from argus.core.resolver import record_unresolved
from argus.inventory import RESOURCES_ON_DAY_SQL, effective_day, resource_id_sql


def _array(path: str) -> str:
    """A JSON value as an array: a column the plugin returns as JSON null or a scalar must not
    fail the whole derivation."""
    return f"CASE WHEN jsonb_typeof({path}) = 'array' THEN {path} ELSE '[]'::jsonb END"


_HOST = "lower(regexp_replace(rtrim({}, '.'), '^dualstack[.]', ''))"
# A URL's host alone: never its userinfo, port, path or query, which can hold a token (an
# external:<host> uid is stored and shown).
_URL_HOST = "substring({} from '^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#]*@)?([A-Za-z0-9.-]+)')"
HOSTS_SQL = f"""
  SELECT DISTINCT host, uid, rank FROM (
    SELECT {_HOST.format("x.config ->> 'domain_name'")} AS host, x.uid, 1 AS rank
    FROM r x WHERE x.type = 'aws_cloudfront_distribution'
    UNION ALL
    SELECT {_HOST.format("x.config ->> 'dns_name'")}, x.uid, 1
    FROM r x WHERE x.type IN ('aws_ec2_application_load_balancer',
      'aws_ec2_network_load_balancer', 'aws_ec2_gateway_load_balancer',
      'aws_ec2_classic_load_balancer')
    UNION ALL
    SELECT lower(x.native_id || '.execute-api.' || x.region || '.amazonaws.com'), x.uid, 1
    FROM r x WHERE x.type IN ('aws_api_gateway_rest_api', 'aws_api_gatewayv2_api')
    UNION ALL
    SELECT lower(b.host), x.uid, 1
    FROM r x CROSS JOIN LATERAL (VALUES
      (x.native_id || '.s3.amazonaws.com'),
      (x.native_id || '.s3.' || x.region || '.amazonaws.com'),
      (x.native_id || '.s3-website-' || x.region || '.amazonaws.com'),
      (x.native_id || '.s3-website.' || x.region || '.amazonaws.com')) AS b(host)
    WHERE x.type = 'aws_s3_bucket'
    UNION ALL
    SELECT {_HOST.format("x.config ->> 'endpoint_address'")}, x.uid, 1
    FROM r x WHERE x.type = 'aws_rds_db_instance'
    UNION ALL
    SELECT {_HOST.format(_URL_HOST.format("x.config -> 'url_config' ->> 'FunctionUrl'"))},
           x.uid, 1
    FROM r x WHERE x.type = 'aws_lambda_function'
    UNION ALL
    SELECT {_HOST.format("d.v")}, x.uid, 2
    FROM r x CROSS JOIN LATERAL (VALUES (x.config ->> 'domain_name'),
      (x.config ->> 'regional_domain_name'), (x.config ->> 'distribution_domain_name')) AS d(v)
    WHERE x.type = 'aws_api_gateway_domain_name'
    UNION ALL
    SELECT {_HOST.format("x.config ->> 'domain_name'")}, x.uid, 2
    FROM r x WHERE x.type = 'aws_api_gatewayv2_domain_name'
    UNION ALL
    SELECT {_HOST.format("c ->> 'ApiGatewayDomainName'")}, x.uid, 2
    FROM r x CROSS JOIN LATERAL jsonb_array_elements(
      CASE jsonb_typeof(x.config -> 'domain_name_configurations')
        WHEN 'array' THEN x.config -> 'domain_name_configurations' ELSE '[]' END) AS c
    WHERE x.type = 'aws_api_gatewayv2_domain_name'
    UNION ALL
    SELECT {_HOST.format("x.config ->> 'name'")}, x.uid, 3
    FROM r x WHERE x.type = 'aws_route53_record' AND x.config ->> 'type' IN ('A', 'AAAA', 'CNAME')
    UNION ALL
    -- Public addresses and names, so an A, AAAA or CNAME record naming one reaches what owns
    -- it (argus_v12): the instance first, else its network interface, else the Elastic IP.
    SELECT lower(a.v), x.uid, 1
    FROM r x CROSS JOIN LATERAL (
      SELECT x.config ->> 'public_ip_address' UNION ALL SELECT x.config ->> 'public_dns_name'
      UNION ALL
      SELECT v FROM jsonb_array_elements({_array("x.config -> 'network_interfaces'")}) n
      CROSS JOIN LATERAL (VALUES (n -> 'Association' ->> 'PublicIp'),
                                 (n -> 'Association' ->> 'PublicDnsName')) pv(v)
      UNION ALL
      SELECT a6 ->> 'Ipv6Address'
      FROM jsonb_array_elements({_array("x.config -> 'network_interfaces'")}) n
      CROSS JOIN LATERAL jsonb_array_elements({_array("n -> 'Ipv6Addresses'")}) a6) AS a(v)
    WHERE x.type = 'aws_ec2_instance'
    UNION ALL
    SELECT lower(a.v), x.uid, 2
    FROM r x CROSS JOIN LATERAL (
      SELECT x.config ->> 'association_public_ip'
      UNION ALL SELECT x.config ->> 'association_public_dns_name'
      UNION ALL SELECT a6 ->> 'Ipv6Address'
      FROM jsonb_array_elements({_array("x.config -> 'ipv6_addresses'")}) a6) AS a(v)
    WHERE x.type = 'aws_ec2_network_interface'
    UNION ALL
    SELECT x.config ->> 'public_ip', x.uid, 3
    FROM r x WHERE x.type = 'aws_vpc_eip'
  ) hosts
  WHERE host IS NOT NULL AND host <> ''
"""  # noqa: S608 - fixed fragments, no input


# `g`: every security group ingress rule (ADR-0035). `anywhere` is a source of 0.0.0.0/0 or
# ::/0, the only source Argus counts as the internet: an address list, another security group
# or a prefix list restricts who can connect. `family` is the source's address family (ipv4,
# ipv6; null for a group or prefix list), so an IPv6 rule never opens an IPv4 address (ADR-0035,
# second amendment). `ports` is a label ("tcp/443", "tcp/8000-8100", "all"; ICMP "icmp",
# "icmpv6" or "icmp/<type>", fifth amendment); `source` names what a restricted rule lets in.
INGRESS_SQL = """
  SELECT sg.native_id AS group_id, lower(rule.config ->> 'ip_protocol') AS protocol,
         (rule.config ->> 'from_port')::int AS from_port,
         (rule.config ->> 'to_port')::int AS to_port,
         CASE WHEN rule.config ->> 'ip_protocol' = '-1' THEN 'all'
              WHEN lower(rule.config ->> 'ip_protocol') IN ('icmp', '1', 'icmpv6', '58') THEN
                CASE WHEN lower(rule.config ->> 'ip_protocol') IN ('icmp', '1') THEN 'icmp'
                     ELSE 'icmpv6' END
                || CASE WHEN COALESCE((rule.config ->> 'from_port')::int, -1) = -1 THEN ''
                        ELSE '/' || (rule.config ->> 'from_port') END
              ELSE lower(rule.config ->> 'ip_protocol') || '/' || (rule.config ->> 'from_port')
                   || CASE WHEN rule.config ->> 'to_port' <> rule.config ->> 'from_port'
                           THEN '-' || (rule.config ->> 'to_port') ELSE '' END
         END AS ports,
         COALESCE(rule.config ->> 'cidr_ipv4', rule.config ->> 'cidr_ipv6',
                  rule.config ->> 'prefix_list_id', rule.config ->> 'referenced_group_id')
           AS source,
         COALESCE(rule.config ->> 'cidr_ipv4' = '0.0.0.0/0'
                  OR rule.config ->> 'cidr_ipv6' = '::/0', false) AS anywhere,
         CASE WHEN rule.config ->> 'cidr_ipv4' IS NOT NULL THEN 'ipv4'
              WHEN rule.config ->> 'cidr_ipv6' IS NOT NULL THEN 'ipv6' END AS family
  FROM r rule
  JOIN r sg ON sg.type = 'aws_vpc_security_group' AND sg.native_id = rule.config ->> 'group_id'
  WHERE rule.type = 'aws_vpc_security_group_rule' AND rule.config ->> 'type' = 'ingress'
"""

# `dt`: what each DNS record names (route53-target, internet-dns): an alias target, or a CNAME,
# A or AAAA value, resolved through the host index `h`; a name or address no inventoried
# resource owns is external:<host>. An S3 website alias names the endpoint only: the bucket is
# the record's own name.
DNS_TARGETS_SQL = """
  SELECT t.src, COALESCE(b.uid, 'external:' || t.host) AS target, t.rtype, t.alias
  FROM (
      SELECT rec.uid AS src, rec.config ->> 'type' AS rtype, true AS alias,
             lower(regexp_replace(rtrim(
               CASE WHEN lower(rec.config -> 'alias_target' ->> 'DNSName') ~ '^s3-website[.-]'
                    THEN rtrim(rec.config ->> 'name', '.') || '.'
                         || (rec.config -> 'alias_target' ->> 'DNSName')
                    ELSE rec.config -> 'alias_target' ->> 'DNSName' END, '.'),
               '^dualstack[.]', '')) AS host
      FROM r rec
      WHERE rec.type = 'aws_route53_record'
        AND rec.config -> 'alias_target' ->> 'DNSName' IS NOT NULL
      UNION ALL
      SELECT rec.uid, rec.config ->> 'type', false,
             lower(regexp_replace(rtrim(CASE jsonb_typeof(v) WHEN 'string' THEN v #>> '{}'
                                                            ELSE v ->> 'Value' END, '.'),
                                  '^dualstack[.]', ''))
      FROM r rec
      CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(rec.config -> 'records') = 'array' THEN rec.config -> 'records'
             WHEN jsonb_typeof(rec.config -> 'resource_records') = 'array'
               THEN rec.config -> 'resource_records'
             ELSE '[]' END) AS v
      WHERE rec.type = 'aws_route53_record' AND rec.config ->> 'type' IN ('CNAME', 'A', 'AAAA')
        AND rec.config -> 'alias_target' ->> 'DNSName' IS NULL
  ) t
  LEFT JOIN (SELECT DISTINCT ON (host) host, uid FROM h ORDER BY host, rank, uid) b
         ON b.host = t.host AND b.uid <> t.src
  WHERE t.host IS NOT NULL AND t.host <> ''
"""

# `gk`: the security groups whose rules were collected (any rule row, ingress or egress).
RULE_GROUPS_SQL = """
  SELECT DISTINCT rule.config ->> 'group_id' AS group_id
  FROM r rule WHERE rule.type = 'aws_vpc_security_group_rule'
"""

# `rt`: which subnets a route table serves and whether it sends the internet to an internet
# gateway, per family. subnet_id is null on a VPC's main table, which serves every subnet of
# the VPC without an association of its own. An egress-only gateway (eigw-) or a NAT gateway
# carries no inbound traffic, so it does not count. def_v4/def_v6 name where the default route
# goes (null: none); a firewall or Gateway Load Balancer endpoint (vpce-) passes inbound
# traffic on through rules Argus does not read (ADR-0035, fourth amendment).
_DEFAULT_TARGET = """(SELECT COALESCE(t ->> 'GatewayId', t ->> 'NatGatewayId',
           t ->> 'TransitGatewayId', t ->> 'VpcPeeringConnectionId', t ->> 'NetworkInterfaceId',
           t ->> 'InstanceId', t ->> 'EgressOnlyInternetGatewayId', t ->> 'LocalGatewayId',
           t ->> 'CarrierGatewayId', t ->> 'CoreNetworkArn')
         FROM jsonb_array_elements(@ROUTES) t
         WHERE t ->> '@DEST' = '@ANY' AND COALESCE(t ->> 'State', 'active') = 'active'
         ORDER BY 1 LIMIT 1)"""
ROUTES_SQL = f"""
  SELECT x.config ->> 'vpc_id' AS vpc_id,
         CASE WHEN COALESCE((a ->> 'Main')::boolean, false) THEN NULL ELSE a ->> 'SubnetId' END
           AS subnet_id,
         EXISTS (SELECT 1 FROM jsonb_array_elements({_array("x.config -> 'routes'")}) t
                 WHERE t ->> 'DestinationCidrBlock' = '0.0.0.0/0'
                   AND t ->> 'GatewayId' LIKE 'igw-%'
                   AND COALESCE(t ->> 'State', 'active') = 'active') AS igw_v4,
         EXISTS (SELECT 1 FROM jsonb_array_elements({_array("x.config -> 'routes'")}) t
                 WHERE t ->> 'DestinationIpv6CidrBlock' = '::/0'
                   AND t ->> 'GatewayId' LIKE 'igw-%'
                   AND COALESCE(t ->> 'State', 'active') = 'active') AS igw_v6,
         {
    _DEFAULT_TARGET.replace("@ROUTES", _array("x.config -> 'routes'"))
    .replace("@DEST", "DestinationCidrBlock")
    .replace("@ANY", "0.0.0.0/0")
} AS def_v4,
         {
    _DEFAULT_TARGET.replace("@ROUTES", _array("x.config -> 'routes'"))
    .replace("@DEST", "DestinationIpv6CidrBlock")
    .replace("@ANY", "::/0")
} AS def_v6
  FROM r x
  CROSS JOIN LATERAL jsonb_array_elements({_array("x.config -> 'associations'")}) a
  WHERE x.type = 'aws_vpc_route_table'
    AND (a ->> 'SubnetId' IS NOT NULL OR COALESCE((a ->> 'Main')::boolean, false))
"""  # noqa: S608 - fixed fragments, no input

# `na`: every network ACL entry, once per subnet the ACL is associated with. ACLs are stateless
# and evaluated in rule-number order, first match wins; `cidr` is the entry's IPv4 or IPv6 block.
ACL_SQL = f"""
  SELECT a ->> 'SubnetId' AS subnet_id, (e ->> 'RuleNumber')::int AS num,
         COALESCE((e ->> 'Egress')::boolean, false) AS egress,
         lower(e ->> 'RuleAction') AS action, e ->> 'Protocol' AS protocol,
         (e -> 'PortRange' ->> 'From')::int AS pfrom, (e -> 'PortRange' ->> 'To')::int AS pto,
         COALESCE(e ->> 'CidrBlock', e ->> 'Ipv6CidrBlock') AS cidr,
         CASE WHEN e ->> 'Ipv6CidrBlock' IS NOT NULL THEN 'ipv6' ELSE 'ipv4' END AS family
  FROM r x
  CROSS JOIN LATERAL jsonb_array_elements({_array("x.config -> 'associations'")}) a
  CROSS JOIN LATERAL jsonb_array_elements({_array("x.config -> 'entries'")}) e
  WHERE x.type = 'aws_vpc_network_acl' AND a ->> 'SubnetId' IS NOT NULL
"""  # noqa: S608 - fixed fragments, no input

# The ports a load balancer listens on, TCP (TCP, TLS, HTTP, HTTPS) and UDP apart; TCP_UDP is
# both. Both null when no listener was collected: then any port counts.
_LB_PORTS = f"""
  SELECT CASE WHEN count(*) > 0 THEN COALESCE(array_agg(DISTINCT port ORDER BY port)
                                     FILTER (WHERE proto IS DISTINCT FROM 'UDP'), '{{}}') END
           AS ports,
         CASE WHEN count(*) > 0 THEN COALESCE(array_agg(DISTINCT port ORDER BY port)
                                     FILTER (WHERE proto IN ('UDP', 'TCP_UDP')), '{{}}') END
           AS udp_ports
  FROM (
    SELECT (l.config ->> 'port')::int AS port, upper(l.config ->> 'protocol') AS proto
    FROM r l WHERE l.type = 'aws_ec2_load_balancer_listener'
               AND l.config ->> 'load_balancer_arn' = x.uid
    UNION ALL
    SELECT (d -> 'Listener' ->> 'LoadBalancerPort')::int, 'TCP'
    FROM jsonb_array_elements({_array("x.config -> 'listener_descriptions'")}) d
  ) q WHERE port IS NOT NULL
"""  # noqa: S608 - fixed fragments, no input
_LB_TYPES = (
    "'aws_ec2_application_load_balancer', 'aws_ec2_network_load_balancer', "
    "'aws_ec2_classic_load_balancer'"
)
# A JSON array of security groups as ids: plain strings (load balancers) or objects (EC2's
# GroupId, RDS's VpcSecurityGroupId).
_SG_IDS = (
    "ARRAY(SELECT COALESCE(sg ->> 'GroupId', sg ->> 'VpcSecurityGroupId', sg #>> '{{}}') "
    "FROM jsonb_array_elements({}) sg)"
)

# `vc`: what sits in a VPC and is public by its settings: an internet-facing load balancer, an
# instance, a publicly accessible database. One row per load balancer and database, and one per
# network interface of an instance (ADR-0035, fifth amendment): its subnets, security group ids,
# the TCP and UDP ports it serves (both null: any), whether it is judged as IPv4 (v4: a public
# IPv4, or no public address at all) and IPv6 (v6: an IPv6 address), whether it has a public
# IPv4 (pub4), the interface (eni, idx: its device index; null and 0 elsewhere), and the
# instance's state (istate; running is true for everything but an instance that is not
# running). An interface with no public address is a candidate too (via private_address): its
# instance is a Restricted door when its groups open a port to the internet (fourth
# amendment). An instance that is pending, stopping or stopped is a candidate (not_running);
# one shutting down or terminated is not.
VPC_CANDIDATES_SQL = f"""
  SELECT x.uid, 'load_balancer' AS via, x.config ->> 'vpc_id' AS vpc_id,
         ARRAY(SELECT z ->> 'SubnetId'
               FROM jsonb_array_elements({_array("x.config -> 'availability_zones'")}) z
               WHERE z ->> 'SubnetId' IS NOT NULL
               UNION
               SELECT s FROM jsonb_array_elements_text({_array("x.config -> 'subnets'")}) s)
           AS subnets,
         {_SG_IDS.format(_array("x.config -> 'security_groups'"))} AS sgs,
         lis.ports, lis.udp_ports,
         COALESCE(x.config ->> 'ip_address_type', 'ipv4') <> 'dualstack-without-public-ipv4'
           AS v4,
         COALESCE(x.config ->> 'ip_address_type', '') LIKE 'dualstack%' AS v6,
         COALESCE(x.config ->> 'ip_address_type', 'ipv4') <> 'dualstack-without-public-ipv4'
           AS pub4,
         CAST(NULL AS text) AS eni, 0 AS idx, true AS running, CAST(NULL AS text) AS istate
  FROM r x CROSS JOIN LATERAL ({_LB_PORTS}) lis
  WHERE x.type IN ({_LB_TYPES}) AND x.config ->> 'scheme' = 'internet-facing'
  UNION ALL
  SELECT x.uid, CASE WHEN n.v4 OR n.v6 THEN 'public_ip' ELSE 'private_address' END,
         x.config ->> 'vpc_id', n.subnets, n.sgs, CAST(NULL AS int[]), CAST(NULL AS int[]),
         n.v4 OR NOT n.v6, n.v6, n.v4, n.eni, n.idx,
         x.config ->> 'instance_state' = 'running', x.config ->> 'instance_state'
  FROM r x
  -- Each network interface with its own subnet, groups and addresses: an open group on a
  -- private interface and a public interface's subnet are never merged. An instance that
  -- lists no interface is judged on its own columns.
  CROSS JOIN LATERAL (
    SELECT i.eni, i.idx,
           CASE WHEN cardinality(i.subnets) = 0 AND i.idx = 0 THEN own.subnets
                ELSE i.subnets END AS subnets,
           CASE WHEN cardinality(i.sgs) = 0 AND i.idx = 0 THEN own.sgs ELSE i.sgs END AS sgs,
           i.v4 OR (i.idx = 0 AND own.v4) AS v4, i.v6
    FROM (
      SELECT ni ->> 'NetworkInterfaceId' AS eni,
             COALESCE((ni -> 'Attachment' ->> 'DeviceIndex')::int, 0) AS idx,
             ARRAY(SELECT ni ->> 'SubnetId' WHERE ni ->> 'SubnetId' IS NOT NULL) AS subnets,
             ARRAY(SELECT DISTINCT gr ->> 'GroupId'
                   FROM jsonb_array_elements({_array("ni -> 'Groups'")}) gr
                   WHERE gr ->> 'GroupId' IS NOT NULL) AS sgs,
             COALESCE(ni -> 'Association' ->> 'PublicIp', '') <> '' AS v4,
             EXISTS (SELECT 1 FROM jsonb_array_elements({_array("ni -> 'Ipv6Addresses'")}) a
                     WHERE COALESCE(a ->> 'Ipv6Address', '') <> '') AS v6
      FROM jsonb_array_elements({_array("x.config -> 'network_interfaces'")}) ni
      UNION ALL
      SELECT NULL, 0, ARRAY[]::text[], ARRAY[]::text[], false, false
      WHERE jsonb_array_length({_array("x.config -> 'network_interfaces'")}) = 0) i
    CROSS JOIN LATERAL (
      SELECT ARRAY(SELECT x.config ->> 'subnet_id' WHERE x.config ->> 'subnet_id' IS NOT NULL)
               AS subnets,
             {_SG_IDS.format(_array("x.config -> 'security_groups'"))} AS sgs,
             COALESCE(x.config ->> 'public_ip_address', '') <> '' AS v4) own) n
  WHERE x.type = 'aws_ec2_instance'
    AND x.config ->> 'instance_state' IN ('pending', 'running', 'stopping', 'stopped')
  UNION ALL
  SELECT x.uid, 'database', x.config ->> 'vpc_id',
         ARRAY(SELECT s ->> 'SubnetIdentifier'
               FROM jsonb_array_elements({_array("x.config -> 'subnets'")}) s
               WHERE s ->> 'SubnetIdentifier' IS NOT NULL),
         {_SG_IDS.format(_array("x.config -> 'vpc_security_groups'"))},
         ARRAY[COALESCE((x.config ->> 'endpoint_port')::int, (x.config ->> 'port')::int)],
         CAST(NULL AS int[]), true, false, true, NULL, 0, true, NULL
  FROM r x
  WHERE x.type = 'aws_rds_db_instance'
    AND COALESCE((x.config ->> 'publicly_accessible')::boolean, false)
"""  # noqa: S608 - fixed fragments, no input

# The first network ACL entry for the whole internet of family @F that matches protocol @P and
# port @X, in subnet @S, inbound or outbound (@E): true when it allows. No match is a deny.
_ACL_VERDICT = """COALESCE((
  SELECT a.action = 'allow' FROM na a
  WHERE a.subnet_id = @S AND a.egress = @E AND a.family = @F
    AND a.cidr = CASE @F WHEN 'ipv6' THEN '::/0' ELSE '0.0.0.0/0' END
    AND (a.protocol = '-1' OR a.protocol = @P)
    AND (a.pfrom IS NULL OR @X BETWEEN a.pfrom AND a.pto)
  ORDER BY a.num LIMIT 1), false)"""
# True when the ACL lets the internet in on some port of [@LO, @HI]. A decision changes only at
# an entry's port boundary, so the range's start and every boundary inside it are enough.
_ACL_ANY_PORT = """EXISTS (
  SELECT 1 FROM (
    SELECT @LO AS x
    UNION SELECT b FROM na a2 CROSS JOIN LATERAL (VALUES (a2.pfrom), (a2.pto + 1)) bb(b)
    WHERE a2.subnet_id = @S AND a2.egress = @E AND b > @LO AND b <= @HI) t
  WHERE @VERDICT)"""


def _acl_allows(subnet: str, egress: str, family: str, protocol: str, lo: str, hi: str) -> str:
    verdict = (
        _ACL_VERDICT.replace("@S", subnet)
        .replace("@E", egress)
        .replace("@F", family)
        .replace("@P", protocol)
        .replace("@X", "t.x")
    )
    return (
        _ACL_ANY_PORT.replace("@VERDICT", verdict)
        .replace("@S", subnet)
        .replace("@E", egress)
        .replace("@LO", lo)
        .replace("@HI", hi)
    )


# Port labels in port order ("tcp/80" before "tcp/443"), "all" and "any" first.
_PORT_ORDER = "substring(l from '/([0-9]+)')::int NULLS FIRST, l"
_LO, _HI = "(rg ->> 'lo')::int", "(rg ->> 'hi')::int"
# `vf`: each VPC candidate, once per address family it has (ADR-0035, second amendment).
#   ranges   what its security groups open to the whole internet of that family, on the ports
#            it serves: [{proto, lo, hi, label}]; with no security groups, its listeners.
#   missing_sg  "security_group:<id>" for a referenced group the inventory does not have,
#            "security_group_rules:<id>" for one whose rules it does not have.
#   subnets  per subnet: rt (null: no route table found; else the family's igw route), acl
#            (whether an ACL is known), ok (the labels of the ranges the ACL lets in and lets
#            the reply out of, on 1024-65535: ACLs are stateless), def (where the family's
#            default route goes, null: none) and insp (it goes to an endpoint, vpce-).
#   open_any what its groups open to the whole internet of that family on any port, ICMP
#            included (open_both: both families, whatever addresses it has), and
#   listens  the ports it serves (null: any): the facts behind a Restricted verdict.
# ICMP is never an open range: ping reaches no service (ADR-0035, fifth amendment).
FAMILIES_SQL = f"""
  SELECT c.uid, c.via, f.fam, c.subnets, sg.ranges, sg.missing_sg, sg.sources, net.subnets AS net,
         sg.open_both -> f.fam AS open_any, sg.open_both, c.eni, c.idx, c.running, c.istate,
         CASE f.fam WHEN 'ipv6' THEN c.v6 ELSE c.pub4 END AS pub,
         CASE WHEN c.ports IS NOT NULL OR c.udp_ports IS NOT NULL THEN
           to_jsonb(ARRAY(SELECT l FROM (
             SELECT 'tcp/' || u AS l, u FROM unnest(c.ports) u
             UNION SELECT 'udp/' || u, u FROM unnest(c.udp_ports) u) q ORDER BY u, l))
         END AS listens
  FROM vc c
  CROSS JOIN LATERAL (VALUES ('ipv4', c.v4), ('ipv6', c.v6)) f(fam, has)
  CROSS JOIN LATERAL (
    SELECT COALESCE((
             SELECT jsonb_agg(DISTINCT jsonb_build_object(
                      'proto', q.proto, 'lo', q.lo, 'hi', q.hi, 'label', q.label))
             FROM (
               SELECT CASE WHEN p.lproto = 'udp' THEN '17'
                           WHEN p.lproto = 'tcp' THEN '6'
                           WHEN g.protocol IN ('-1', 'tcp', '6') THEN '6'
                           WHEN g.protocol IN ('udp', '17') THEN '17'
                           ELSE g.protocol END AS proto,
                      CASE WHEN p.port IS NOT NULL THEN p.port
                           WHEN g.protocol = '-1' THEN 0 ELSE g.from_port END AS lo,
                      CASE WHEN p.port IS NOT NULL THEN p.port
                           WHEN g.protocol = '-1' THEN 65535 ELSE g.to_port END AS hi,
                      CASE WHEN p.port IS NULL THEN g.ports ELSE p.lproto || '/' || p.port END
                        AS label
               FROM g LEFT JOIN LATERAL (
                 SELECT u, 'tcp' FROM unnest(c.ports) u
                 UNION ALL SELECT u, 'udp' FROM unnest(c.udp_ports) u) AS p(port, lproto) ON true
               WHERE g.group_id = ANY(c.sgs) AND g.anywhere AND g.family = f.fam
                 AND g.protocol NOT IN ('icmp', '1', 'icmpv6', '58')
                 AND ((c.ports IS NULL AND c.udp_ports IS NULL)
                      OR (p.port IS NOT NULL
                          AND (g.protocol = '-1'
                               OR (p.lproto = 'tcp' AND g.protocol IN ('tcp', '6')
                                   AND p.port BETWEEN g.from_port AND g.to_port)
                               OR (p.lproto = 'udp' AND g.protocol IN ('udp', '17')
                                   AND p.port BETWEEN g.from_port AND g.to_port))))
               UNION ALL
               SELECT '6', COALESCE(p.port, 0), COALESCE(p.port, 65535),
                      COALESCE('tcp/' || p.port, 'any')
               FROM (SELECT unnest(COALESCE(c.ports, ARRAY[NULL::int])) AS port) p
               WHERE cardinality(c.sgs) = 0 AND c.via = 'load_balancer'
               UNION ALL
               SELECT '17', p.port, p.port, 'udp/' || p.port
               FROM unnest(c.udp_ports) AS p(port)
               WHERE cardinality(c.sgs) = 0 AND c.via = 'load_balancer'
             ) q), '[]'::jsonb) AS ranges,
           (SELECT jsonb_build_object(
                     'ipv4', COALESCE(jsonb_agg(q.l ORDER BY {_PORT_ORDER})
                                        FILTER (WHERE q.fam = 'ipv4'), '[]'::jsonb),
                     'ipv6', COALESCE(jsonb_agg(q.l ORDER BY {_PORT_ORDER})
                                        FILTER (WHERE q.fam = 'ipv6'), '[]'::jsonb))
            FROM (SELECT DISTINCT g.family AS fam, g.ports AS l FROM g
                  WHERE g.group_id = ANY(c.sgs) AND g.anywhere) q) AS open_both,
           ARRAY(SELECT 'security_group:' || s FROM unnest(c.sgs) s
                 WHERE NOT EXISTS (SELECT 1 FROM r k
                                   WHERE k.type = 'aws_vpc_security_group' AND k.native_id = s)
                 UNION ALL
                 -- A group without a single rule row (not even egress): its rules were not
                 -- collected, so "no public source" would be a guess.
                 SELECT 'security_group_rules:' || s FROM unnest(c.sgs) s
                 WHERE EXISTS (SELECT 1 FROM r k
                               WHERE k.type = 'aws_vpc_security_group' AND k.native_id = s)
                   AND NOT EXISTS (SELECT 1 FROM gk WHERE gk.group_id = s))
             AS missing_sg,
           COALESCE((SELECT jsonb_agg(DISTINCT g.source ORDER BY g.source) FROM g
                     WHERE g.group_id = ANY(c.sgs) AND NOT g.anywhere AND g.source IS NOT NULL),
                    '[]'::jsonb) AS sources
  ) sg
  CROSS JOIN LATERAL (
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'subnet', s.id, 'rt', rt.igw, 'acl', acl.known, 'ok', ok.labels, 'def', rt.def,
             'insp', COALESCE(rt.def LIKE 'vpce-%', false))), '[]'::jsonb)
             AS subnets
    FROM unnest(c.subnets) AS s(id)
    -- The subnet's own route table, else its VPC's main one; no row: none was collected.
    LEFT JOIN LATERAL (
      SELECT q.igw, q.def FROM (
        SELECT 1 AS o, CASE f.fam WHEN 'ipv6' THEN t.igw_v6 ELSE t.igw_v4 END AS igw,
               CASE f.fam WHEN 'ipv6' THEN t.def_v6 ELSE t.def_v4 END AS def
        FROM rt t WHERE t.subnet_id = s.id
        UNION ALL
        SELECT 2, CASE f.fam WHEN 'ipv6' THEN t.igw_v6 ELSE t.igw_v4 END,
               CASE f.fam WHEN 'ipv6' THEN t.def_v6 ELSE t.def_v4 END
        FROM rt t
        WHERE t.subnet_id IS NULL
          AND t.vpc_id = COALESCE((SELECT n.config ->> 'vpc_id' FROM r n
                                   WHERE n.type = 'aws_vpc_subnet' AND n.native_id = s.id
                                   LIMIT 1), c.vpc_id)) q
      ORDER BY q.o LIMIT 1) rt ON true
    CROSS JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM na WHERE na.subnet_id = s.id) AS known) acl
    CROSS JOIN LATERAL (
      SELECT COALESCE(jsonb_agg(DISTINCT rg ->> 'label'), '[]'::jsonb) AS labels
      FROM jsonb_array_elements(sg.ranges) rg
      WHERE {_acl_allows("s.id", "false", "f.fam", "rg ->> 'proto'", _LO, _HI)}
        AND {_acl_allows("s.id", "true", "f.fam", "rg ->> 'proto'", "1024", "65535")}
    ) ok
  ) net
  WHERE f.has
"""  # noqa: S608 - fixed fragments, no input

# Each VPC candidate's verdict, family by family, in this order: security groups, route,
# network ACL. A family passes when a group opens a port and one subnet both routes the family
# to an internet gateway and has an ACL that lets it in on an open port. The resource is open
# when a family passes; else a definite failure in every family makes it restricted (the
# reason of IPv4, or of IPv6 when it has no public IPv4); else it is unknown, naming what is
# missing (a group, a route table or an ACL never collected).
_CHECKED = """'["security_groups", "route_table", "network_acl"]'::jsonb"""
VERDICT_SQL = f"""
  SELECT v.uid, v.via, v.fam, v.sources,
         CASE WHEN jsonb_array_length(v.ranges) > 0 AND v.passed <> '[]'::jsonb THEN 'pass'
              WHEN jsonb_array_length(v.ranges) = 0 AND cardinality(v.missing_sg) = 0
                THEN 'sg_no_public_source'
              WHEN v.no_route THEN 'no_internet_route'
              WHEN jsonb_array_length(v.ranges) > 0 AND v.acl_blocks THEN 'nacl_blocks'
              ELSE 'unknown' END AS state,
         v.passed, v.missing, v.acl_sources, v.open_any, v.listens, v.default_routes,
         jsonb_array_length(v.ranges) AS open_n, v.eni, v.idx, v.running, v.istate, v.pub,
         v.open_both, v.subnet_evidence
  FROM (
    SELECT fv.uid, fv.via, fv.fam, fv.ranges, fv.missing_sg, fv.sources, fv.open_any,
           fv.listens, fv.eni, fv.idx, fv.running, fv.istate, fv.pub, fv.open_both,
           -- Each subnet's route and ACL for this family, shown on every door (fifth
           -- amendment). acl is null when nothing is open to test it with.
           (SELECT jsonb_agg(jsonb_build_object(
                     'subnet', n ->> 'subnet', 'family', fv.fam,
                     'route', CASE WHEN n -> 'rt' = 'null'::jsonb THEN 'unknown'
                                   WHEN (n ->> 'rt')::boolean THEN 'igw'
                                   ELSE COALESCE(n ->> 'def', 'none') END,
                     'acl', CASE WHEN jsonb_array_length(fv.ranges) = 0 THEN NULL
                                 WHEN NOT (n ->> 'acl')::boolean THEN 'unknown'
                                 WHEN jsonb_array_length(n -> 'ok') > 0 THEN 'allows'
                                 ELSE 'blocks' END))
            FROM jsonb_array_elements(fv.net) n) AS subnet_evidence,
           COALESCE((SELECT jsonb_agg(DISTINCT COALESCE(n ->> 'def', 'none'))
                     FROM jsonb_array_elements(fv.net) n WHERE n -> 'rt' <> 'null'::jsonb),
                    '[]'::jsonb) AS default_routes,
           COALESCE((SELECT jsonb_agg(l ORDER BY {_PORT_ORDER})
                     FROM (SELECT DISTINCT l FROM jsonb_array_elements(fv.net) n
                           CROSS JOIN LATERAL jsonb_array_elements_text(n -> 'ok') l
                           WHERE (n ->> 'rt')::boolean AND (n ->> 'acl')::boolean) q),
                    '[]'::jsonb) AS passed,
           -- Every subnet's route table is known and none routes the family to the internet
           -- or on to an endpoint (a firewall: Argus cannot tell).
           cardinality(fv.subnets) > 0
             AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(fv.net) n
                             WHERE n -> 'rt' = 'null'::jsonb OR (n ->> 'rt')::boolean
                                OR (n ->> 'insp')::boolean)
             AS no_route,
           -- Every routed subnet has a known ACL that lets in none of the open ranges.
           EXISTS (SELECT 1 FROM jsonb_array_elements(fv.net) n WHERE (n ->> 'rt')::boolean)
             AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(fv.net) n
                             WHERE (n ->> 'rt')::boolean AND NOT (n ->> 'acl')::boolean)
             AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(fv.net) n
                             WHERE n -> 'rt' = 'null'::jsonb)
             AS acl_blocks,
           ARRAY(SELECT m FROM unnest(fv.missing_sg) m
                 WHERE jsonb_array_length(fv.ranges) = 0
                 UNION ALL SELECT 'subnet' WHERE cardinality(fv.subnets) = 0
                 UNION ALL
                 SELECT 'route_table:' || (n ->> 'subnet') FROM jsonb_array_elements(fv.net) n
                 WHERE n -> 'rt' = 'null'::jsonb
                 UNION ALL
                 SELECT 'network_acl:' || (n ->> 'subnet') FROM jsonb_array_elements(fv.net) n
                 WHERE (n ->> 'rt')::boolean AND NOT (n ->> 'acl')::boolean
                 UNION ALL
                 SELECT 'inspection_route:' || (n ->> 'subnet')
                 FROM jsonb_array_elements(fv.net) n
                 WHERE (n ->> 'insp')::boolean AND NOT (n ->> 'rt')::boolean) AS missing,
           COALESCE((SELECT jsonb_agg(DISTINCT a.cidr ORDER BY a.cidr) FROM na a
                     WHERE a.subnet_id = ANY(fv.subnets) AND NOT a.egress AND a.action = 'allow'
                       AND a.family = fv.fam AND a.cidr NOT IN ('0.0.0.0/0', '::/0')),
                    '[]'::jsonb) AS acl_sources
    FROM vf fv
  ) v
"""  # noqa: S608 - fixed fragments, no input

# Resources public by their own policy (ADR-0037 second amendment, wave 2): a bucket, queue,
# topic, function, KMS key, secret or ECR repository whose policy has an Allow statement for
# any principal (`*`). open: one such statement has no condition; restricted: a bucket whose
# Block Public Access (its own or the account's) restricts public buckets
# (block_public_access); unknown: every public statement has a condition Argus does not
# evaluate (policy_condition), or a bucket's account settings are not in the inventory
# (s3_account_settings). `actions` are what the public statements allow. A function's
# lambda:InvokeFunctionUrl to `*` is its URL's, judged by the function URL branch.
_PUBLIC_TYPES = (
    "'aws_s3_bucket', 'aws_sqs_queue', 'aws_sns_topic', 'aws_lambda_function', 'aws_kms_key', "
    "'aws_secretsmanager_secret', 'aws_ecr_repository'"
)
_ANYONE = (
    "(jsonb_typeof(st -> 'Principal') = 'string' AND st ->> 'Principal' = '*') "
    "OR (st -> 'Principal' -> 'AWS') @> '\"*\"'::jsonb "
    "OR (st -> 'Principal' -> 'AWS') @> '[\"*\"]'::jsonb"
)
PUBLIC_POLICY_SQL = f"""
  SELECT q.uid,
         CASE WHEN q.blocked THEN 'restricted'
              WHEN q.unconditional AND q.account_known THEN 'open'
              ELSE 'unknown' END AS reach,
         jsonb_build_object('via', 'resource_policy', 'actions', q.actions,
                            'checked', '["resource_policy"]'::jsonb)
         || CASE WHEN q.blocked
                 THEN jsonb_build_object('reason', 'block_public_access', 'sources', '[]'::jsonb,
                                         'open_ports', '[]'::jsonb)
                 WHEN q.unconditional AND q.account_known THEN '{{}}'::jsonb
                 ELSE jsonb_build_object('missing', to_jsonb(ARRAY(
                        SELECT 'policy_condition:' || q.name WHERE NOT q.unconditional
                        UNION ALL
                        SELECT 's3_account_settings:' || q.account WHERE NOT q.account_known)))
            END AS attributes
  FROM (
    SELECT x.uid, COALESCE(x.name, x.native_id) AS name,
           x.config ->> 'account_id' AS account,
           jsonb_agg(DISTINCT a ORDER BY a) AS actions,
           bool_or(COALESCE(st -> 'Condition', '{{}}'::jsonb) = '{{}}'::jsonb) AS unconditional,
           x.type = 'aws_s3_bucket' AND (
             COALESCE((x.config ->> 'restrict_public_buckets')::boolean, false)
             OR EXISTS (SELECT 1 FROM r s3 WHERE s3.type = 'aws_s3_account_settings'
                          AND s3.config ->> 'account_id' = x.config ->> 'account_id'
                          AND COALESCE((s3.config ->> 'restrict_public_buckets')::boolean,
                                       false))) AS blocked,
           x.type <> 'aws_s3_bucket' OR EXISTS (
             SELECT 1 FROM r s3 WHERE s3.type = 'aws_s3_account_settings'
               AND s3.config ->> 'account_id' = x.config ->> 'account_id') AS account_known
    FROM r x
    CROSS JOIN LATERAL jsonb_array_elements({_array("x.config -> 'policy_std' -> 'Statement'")})
      AS st
    CROSS JOIN LATERAL jsonb_array_elements_text(
      CASE jsonb_typeof(st -> 'Action') WHEN 'array' THEN st -> 'Action'
           WHEN 'string' THEN jsonb_build_array(st -> 'Action') ELSE '[]'::jsonb END) AS a
    WHERE x.type IN ({_PUBLIC_TYPES}) AND st ->> 'Effect' = 'Allow' AND ({_ANYONE})
      AND NOT (x.type = 'aws_lambda_function' AND lower(a) = 'lambda:invokefunctionurl')
    GROUP BY x.uid, x.name, x.native_id, x.type, x.config
  ) q
"""  # noqa: S608 - fixed fragments, no input

# `p`: what faces the internet, and whether traffic can really arrive (ADR-0035): one row per
# candidate, `reach` open, restricted or unknown, with why in its attributes. internet-entry
# draws the open ones (ROUTES_TO), internet-restricted the restricted ones
# (PUBLIC_RESTRICTED), internet-unverified the unknown ones (PUBLIC_UNVERIFIED). A change here
# changes all three rules' edges: bump their versions, so the change shows in history.
#   - CloudFront: an enabled distribution (WAF as an attribute).
#   - API Gateway: a REST API that is not private, unless its resource policy limits source
#     addresses; every HTTP or WebSocket API. A custom domain is a name in front of an API,
#     not a door of its own.
#   - Lambda: a function URL without IAM auth. EKS: a public endpoint open to 0.0.0.0/0.
#   - In a VPC (load balancers, instances, databases): security groups, the subnet's route to
#     an internet gateway and its network ACL, per address family (vf, VERDICT_SQL). A
#     restricted one says why with the facts: open_ports (what its groups open to the internet
#     on any port), listens (the ports it serves, absent when any counts) and, with no route,
#     default_routes. An instance with no public address is restricted (no_public_address)
#     when its groups open a port to the internet, and no door at all otherwise. An instance
#     is judged per network interface and is open when one passes; one that is not running
#     is restricted (not_running) when its groups open a port, else no door. Every VPC door
#     carries `network` (per interface: the families it has a public address of, what its
#     groups open per family, each subnet's route and ACL) and, for an instance, `state`
#     (ADR-0035, fifth amendment).
#   - A resource public by its own policy (PUBLIC_POLICY_SQL; ADR-0037 second amendment).
#   - An instance door's `imds`: v1, v2 or off (ADR-0037 second amendment, wave 3).
EXPOSURE_SQL = f"""
  SELECT d.uid, 'open' AS reach,
         jsonb_build_object('via', 'cdn', 'waf', COALESCE(d.config ->> 'web_acl_id', '') <> '')
           AS attributes
  FROM r d
  WHERE d.type = 'aws_cloudfront_distribution'
    AND COALESCE((d.config ->> 'enabled')::boolean, true)
  UNION ALL
  SELECT a.uid, CASE WHEN a.ip_only THEN 'restricted' ELSE 'open' END,
         CASE WHEN a.ip_only THEN jsonb_build_object('via', 'api', 'reason', 'cidr_allowlist')
              ELSE jsonb_build_object('via', 'api') END
  FROM (SELECT x.uid,
               COALESCE((x.config -> 'policy_std')::text ILIKE '%aws:sourceip%', false) AS ip_only
        FROM r x
        WHERE x.type = 'aws_api_gateway_rest_api'
          AND NOT {_array("x.config -> 'endpoint_configuration_types'")} ? 'PRIVATE') a
  UNION ALL
  SELECT x.uid, 'open', jsonb_build_object('via', 'api')
  FROM r x WHERE x.type = 'aws_api_gatewayv2_api'
  UNION ALL
  SELECT x.uid,
         CASE WHEN x.config -> 'url_config' ->> 'AuthType' = 'NONE' THEN 'open'
              ELSE 'restricted' END,
         CASE WHEN x.config -> 'url_config' ->> 'AuthType' = 'NONE'
              THEN jsonb_build_object('via', 'function_url', 'auth_type', 'NONE')
              ELSE jsonb_build_object('via', 'function_url', 'reason', 'iam_auth',
                                      'auth_type', x.config -> 'url_config' ->> 'AuthType') END
  FROM r x
  WHERE x.type = 'aws_lambda_function' AND jsonb_typeof(x.config -> 'url_config') = 'object'
  UNION ALL
  SELECT x.uid, CASE WHEN c.cidrs ? '0.0.0.0/0' THEN 'open' ELSE 'restricted' END,
         CASE WHEN c.cidrs ? '0.0.0.0/0'
              THEN jsonb_build_object('via', 'kubernetes_api')
              ELSE jsonb_build_object('via', 'kubernetes_api', 'reason', 'cidr_allowlist',
                                      'sources', c.cidrs) END
  FROM r x
  CROSS JOIN LATERAL (SELECT {_array("x.config -> 'resources_vpc_config' -> 'PublicAccessCidrs'")}
                        AS cidrs) c
  WHERE x.type = 'aws_eks_cluster'
    AND COALESCE((x.config -> 'resources_vpc_config' ->> 'EndpointPublicAccess')::boolean, false)
  UNION ALL
  SELECT o.uid, o.reach,
         CASE o.reach
           WHEN 'open' THEN jsonb_build_object('via', o.via, 'open', o.open,
                                               'families', o.families, 'checked', {_CHECKED})
           WHEN 'unknown' THEN jsonb_build_object('via', o.via, 'missing', o.missing,
                                                  'checked', {_CHECKED})
           ELSE jsonb_build_object('via', o.via, 'reason', o.reason, 'sources', o.sources,
                                   'checked', {_CHECKED}, 'open_ports', o.open_any)
                || CASE WHEN o.listens IS NOT NULL
                        THEN jsonb_build_object('listens', o.listens) ELSE '{{}}' END
                || CASE WHEN o.reason = 'no_internet_route'
                        THEN jsonb_build_object('default_routes', o.default_routes)
                        ELSE '{{}}' END END
         || jsonb_build_object('network', nw.network)
         || CASE WHEN o.istate IS NOT NULL THEN jsonb_build_object('state', o.istate)
                 ELSE '{{}}' END
         -- An instance's metadata service (ADR-0037 second amendment, wave 3): v1 when it does
         -- not require tokens, so a foothold reads the role's credentials with one request.
         || COALESCE((SELECT jsonb_build_object('imds',
                        CASE WHEN m.opts ->> 'HttpEndpoint' = 'disabled' THEN 'off'
                             WHEN m.opts ->> 'HttpTokens' = 'required' THEN 'v2' ELSE 'v1' END)
                      FROM (SELECT x.config -> 'metadata_options' AS opts FROM r x
                            WHERE x.uid = o.uid AND x.type = 'aws_ec2_instance') m
                      WHERE jsonb_typeof(m.opts) = 'object'), '{{}}')
  FROM (
    SELECT x.uid,
           CASE WHEN bool_or(x.via = 'public_ip') THEN 'public_ip' ELSE min(x.via) END AS via,
           CASE WHEN NOT bool_and(x.running) THEN 'restricted'
                WHEN bool_or(x.state = 'pass' AND x.via <> 'private_address') THEN 'open'
                WHEN bool_or(x.state = 'unknown' AND x.via <> 'private_address') THEN 'unknown'
                ELSE 'restricted' END AS reach,
           (SELECT jsonb_agg(l ORDER BY {_PORT_ORDER})
            FROM (SELECT DISTINCT l FROM vv y
                  CROSS JOIN LATERAL jsonb_array_elements_text(y.passed) l
                  WHERE y.uid = x.uid AND y.state = 'pass' AND y.via <> 'private_address') q)
             AS open,
           jsonb_agg(DISTINCT x.fam ORDER BY x.fam)
             FILTER (WHERE x.state = 'pass' AND x.via <> 'private_address') AS families,
           (SELECT jsonb_agg(DISTINCT m ORDER BY m) FROM vv y CROSS JOIN LATERAL unnest(y.missing) m
            WHERE y.uid = x.uid AND y.state = 'unknown' AND y.via <> 'private_address')
             AS missing,
           -- The reason of an interface whose groups open a port first, then by device index,
           -- IPv4 before IPv6 (fifth amendment); an interface without a public address says so.
           CASE WHEN NOT bool_and(x.running) THEN 'not_running'
                ELSE (array_agg(x.why ORDER BY x.rank))[1] END AS reason,
           CASE WHEN NOT bool_and(x.running) THEN '[]'::jsonb
                ELSE (array_agg(CASE WHEN x.why = 'nacl_blocks' THEN x.acl_sources
                                     WHEN x.why = 'sg_no_public_source' THEN x.sources
                                     ELSE '[]'::jsonb END ORDER BY x.rank))[1] END AS sources,
           (array_agg(x.open_any ORDER BY x.rank))[1] AS open_any,
           (array_agg(x.listens ORDER BY x.rank))[1] AS listens,
           (array_agg(x.default_routes ORDER BY x.rank))[1] AS default_routes,
           max(x.istate) AS istate
    FROM (
      SELECT z.*,
             row_number() OVER (PARTITION BY z.uid ORDER BY z.iface_open DESC, z.idx, z.eni,
                                                            z.fam) AS rank
      FROM (
        SELECT y.*,
               CASE WHEN y.via = 'private_address' THEN 'no_public_address' ELSE y.state END
                 AS why,
               bool_or(y.open_n > 0) OVER (PARTITION BY y.uid, y.idx, y.eni) AS iface_open
        FROM vv y) z) x
    GROUP BY x.uid
    -- A door when traffic could arrive at a running public interface, or when any interface's
    -- groups open a port to the internet (no public address, not running): else no door.
    HAVING (bool_and(x.running) AND bool_or(x.via <> 'private_address'))
        OR bool_or(x.open_n > 0)
  ) o
  -- The evidence, one entry per interface (a load balancer or database: one, interface null):
  -- the families it has a public address of, what its groups open per family, and each
  -- subnet's route and ACL per family. No address values: an address change makes no edge.
  JOIN (
    SELECT i.uid, jsonb_agg(jsonb_build_object('interface', i.eni, 'public', i.public,
                                               'open', i.open, 'subnets', i.subnets)
                            ORDER BY i.idx, i.eni) AS network
    FROM (
      SELECT y.uid, y.eni, y.idx,
             COALESCE(jsonb_agg(DISTINCT y.fam ORDER BY y.fam) FILTER (WHERE y.pub),
                      '[]'::jsonb) AS public,
             (array_agg(y.open_both))[1] AS open,
             COALESCE(jsonb_agg(sn ORDER BY sn ->> 'family', sn ->> 'subnet')
                        FILTER (WHERE sn IS NOT NULL), '[]'::jsonb) AS subnets
      FROM vv y
      LEFT JOIN LATERAL jsonb_array_elements(COALESCE(y.subnet_evidence, '[]'::jsonb)) sn
        ON true
      GROUP BY y.uid, y.eni, y.idx) i
    GROUP BY i.uid) nw ON nw.uid = o.uid
  UNION ALL
  {PUBLIC_POLICY_SQL}
"""  # noqa: S608 - fixed fragments, no input
# Every role's and user's policies, a user's groups' included (ADR-0037 second amendment,
# wave 2): `pa` the attached policy ARNs (customer- and AWS-managed), `ps` the Allow statements
# of the inline and customer-managed ones, `src` naming where each came from ("inline:<name>",
# a policy ARN, "group:<name>/inline:<name>"). AWS-managed policies are not in the inventory:
# the rules that read `pa` name the ones they know.
_HOLDERS_SQL = f"""
  SELECT x.uid AS principal, x.uid AS holder, NULL AS grp FROM r x
  WHERE x.type IN ('aws_iam_role', 'aws_iam_user')
  UNION
  SELECT u.uid, g.uid, COALESCE(g.name, g.native_id)
  FROM r u
  CROSS JOIN LATERAL jsonb_array_elements({_array("u.config -> 'groups'")}) ug
  JOIN r g ON g.type = 'aws_iam_group' AND g.uid = ug ->> 'Arn'
  WHERE u.type = 'aws_iam_user'
"""  # noqa: S608 - fixed fragments, no input
PRINCIPAL_ATTACHED_SQL = f"""
  SELECT h.principal, a.arn
  FROM ({_HOLDERS_SQL}) h JOIN r x ON x.uid = h.holder
  CROSS JOIN LATERAL jsonb_array_elements_text({_array("x.config -> 'attached_policy_arns'")})
    AS a(arn)
"""  # noqa: S608 - fixed fragments, no input
PRINCIPAL_STATEMENTS_SQL = f"""
  SELECT h.principal,
         COALESCE('group:' || h.grp || '/', '') || pol.src AS src, st
  FROM ({_HOLDERS_SQL}) h JOIN r x ON x.uid = h.holder
  CROSS JOIN LATERAL (
    SELECT ip -> 'PolicyDocument' -> 'Statement' AS stmts, 'inline:' || (ip ->> 'PolicyName') AS src
    FROM jsonb_array_elements({_array("x.config -> 'inline_policies_std'")}) AS ip
    UNION ALL
    SELECT p.config -> 'policy_std' -> 'Statement', p.uid
    FROM jsonb_array_elements_text({_array("x.config -> 'attached_policy_arns'")}) AS a(arn)
    JOIN r p ON p.type = 'aws_iam_policy' AND p.uid = a.arn
  ) pol
  CROSS JOIN LATERAL jsonb_array_elements({_array("pol.stmts")}) AS st
  WHERE st ->> 'Effect' = 'Allow'
"""  # noqa: S608 - fixed fragments, no input
# The views every rule reads beside `r`: the host index, what DNS records name, security group
# ingress and the groups whose rules were collected, routes, network ACL entries, the VPC
# candidates and their per-family verdicts, exposure, and the principals' policies.
RULE_VIEWS_SQL = (
    f"h AS ({HOSTS_SQL}),\ndt AS ({DNS_TARGETS_SQL}),\ng AS ({INGRESS_SQL}),\n"
    f"gk AS ({RULE_GROUPS_SQL}),\n"
    f"rt AS ({ROUTES_SQL}),\nna AS ({ACL_SQL}),\n"
    f"vc AS ({VPC_CANDIDATES_SQL}),\nvf AS ({FAMILIES_SQL}),\nvv AS ({VERDICT_SQL}),\n"
    f"p AS ({EXPOSURE_SQL}),\n"
    f"pa AS ({PRINCIPAL_ATTACHED_SQL}),\nps AS ({PRINCIPAL_STATEMENTS_SQL})"
)
RESOURCES_CTE = f"WITH r AS ({RESOURCES_ON_DAY_SQL}),\n{RULE_VIEWS_SQL}\n"
# Every rule query carries the views above, and their nested subplans estimate high enough to
# trigger JIT compilation: about 3 s per query for one connection's few hundred rows, which run
# in milliseconds (measured 2026-10-10). Rules run with JIT off, for this transaction only.
NO_JIT = "SET LOCAL jit = off"
# Hosts a missing resource would own: an external: node pointing to one is a broken join
# (another account, a table not collected), recorded in unresolved_ref.
_AWS_HOST = re.compile(r"(^|\.)(amazonaws\.com|cloudfront\.net|on\.aws)$")
EXTERNAL = "external:"
# An origin prefix load_edges() replaces -> its family in edge_load.
FAMILIES = {"rule:": "rule", "cloudfox": "cloudfox"}
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_EDGE_TYPE_RE = re.compile(r"^[A-Z][A-Z_]*$")


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    edge_type: str
    description: str
    sql: str

    @property
    def origin(self) -> str:
        return f"rule:{self.id}@{self.version}"


@dataclass(frozen=True)
class DerivedEdge:
    source_uid: str
    target_uid: str
    type: str
    origin: str
    attributes: dict[str, Any]

    def key(self, connection_id: int) -> bytes:
        """The edge's stable key. It holds the connection that derived it, so two connections
        never share an edge row (ADR-0034); migration 0017 re-keyed older edges the same way."""
        return edge_key(
            connection_id,
            self.origin,
            self.source_uid,
            self.target_uid,
            self.type,
            self.attributes,
        )


def edge_key(
    connection_id: int,
    origin: str,
    source_uid: str,
    target_uid: str,
    type_: str,
    attributes: dict[str, Any],
) -> bytes:
    canonical = json.dumps(
        [connection_id, origin, source_uid, target_uid, type_, attributes],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).digest()


def load_rules(rules_dir: Path) -> list[Rule]:
    rules = []
    for file in sorted((rules_dir / "relationships").glob("*.toml")):
        data = tomllib.loads(file.read_text())
        rule = Rule(
            id=data["id"],
            version=int(data["version"]),
            edge_type=data["edge_type"],
            description=data["description"],
            sql=data["sql"],
        )
        if not _ID_RE.match(rule.id) or file.stem != rule.id:
            raise RuleError(f"{file.name}: id must match the file name and be lower-case")
        if not _EDGE_TYPE_RE.match(rule.edge_type):
            raise RuleError(f"{file.name}: edge_type must be UPPER_SNAKE_CASE")
        rules.append(rule)
    if len({r.id for r in rules}) != len(rules):
        raise RuleError("duplicate rule ids")
    if not rules:
        # A rule-less engine is a misconfiguration (a wrong ARGUS_RULES_DIR), never a quiet
        # success: without rules there are no edges, and without edges no attack paths.
        raise RuleError(f"no relationship rules in {rules_dir / 'relationships'}")
    return rules


def derive_edges(
    engine: Engine, *, rules: list[Rule], connection_id: int, day: date
) -> list[DerivedEdge]:
    edges: list[DerivedEdge] = []
    with engine.connect() as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        conn.execute(text(NO_JIT))
        for rule in rules:
            rows = conn.execute(
                text(RESOURCES_CTE + rule.sql),
                {"resource_day": day, "connection_id": connection_id},
            )
            for source_uid, target_uid, attributes in rows:
                edges.append(
                    DerivedEdge(
                        source_uid, target_uid, rule.edge_type, rule.origin, attributes or {}
                    )
                )
        conn.rollback()
    return edges


def load_edges(
    conn: Connection,
    *,
    edges: list[DerivedEdge],
    connection_id: int,
    day: date,
    origin_prefix: str,
    carry_forward: bool = False,
    ruleset: str | None = None,
) -> int:
    """Upserts edges and replaces that day's snapshot for this connection's edges whose origin
    starts with origin_prefix ("rule:" or "cloudfox"). carry_forward (a partial run) keeps the
    previous snapshot's edges of the same family that this run did not see. The day is then
    recorded in edge_load with its edge count, even when it is 0: effective_days reads it. A
    rule load records the rule set it was derived with (`ruleset`, migration 0026), which the
    worker compares at start (ADR-0035, fifth amendment)."""
    if edges:
        conn.execute(
            text(f"""
                INSERT INTO edge (edge_key, source_uid, target_uid, source_resource_id,
                                  target_resource_id, type, origin, attributes, first_seen,
                                  last_seen, connection_id)
                VALUES (:k, :s, :t,
                        {resource_id_sql("s")}, {resource_id_sql("t")},
                        :type, :origin, CAST(:attrs AS jsonb), :d, :d, :c)
                ON CONFLICT (edge_key) DO UPDATE SET
                  first_seen = LEAST(edge.first_seen, EXCLUDED.first_seen),
                  last_seen = GREATEST(edge.last_seen, EXCLUDED.last_seen),
                  source_resource_id = COALESCE(EXCLUDED.source_resource_id,
                                                edge.source_resource_id),
                  target_resource_id = COALESCE(EXCLUDED.target_resource_id,
                                                edge.target_resource_id)
            """),  # noqa: S608 - exported SQL constants only
            [
                {
                    "k": e.key(connection_id),
                    "s": e.source_uid,
                    "t": e.target_uid,
                    "type": e.type,
                    "origin": e.origin,
                    "attrs": json.dumps(e.attributes, sort_keys=True),
                    "d": day,
                    "c": connection_id,
                }
                for e in edges
            ],
        )
    params = {"d": day, "c": connection_id, "prefix": origin_prefix}
    conn.execute(
        text(
            "DELETE FROM edge_snapshot es USING edge e WHERE es.edge_id = e.id "
            "AND es.snapshot_date = :d AND e.connection_id = :c "
            "AND starts_with(e.origin, :prefix)"
        ),
        params,
    )
    inserted: int = conn.execute(
        text(
            "INSERT INTO edge_snapshot (snapshot_date, edge_id) "
            "SELECT :d, id FROM edge WHERE edge_key = ANY(CAST(:keys AS bytea[])) "
            "AND connection_id = :c ON CONFLICT DO NOTHING"
        ),
        {"d": day, "c": connection_id, "keys": list({e.key(connection_id) for e in edges})},
    ).rowcount
    if carry_forward:
        inserted += conn.execute(
            text("""
                INSERT INTO edge_snapshot (snapshot_date, edge_id)
                SELECT :d, es.edge_id FROM edge_snapshot es JOIN edge e ON e.id = es.edge_id
                WHERE e.connection_id = :c AND starts_with(e.origin, :prefix)
                  AND es.snapshot_date = (
                    SELECT max(s.snapshot_date) FROM edge_snapshot s JOIN edge e2
                      ON e2.id = s.edge_id
                    WHERE e2.connection_id = :c AND starts_with(e2.origin, :prefix)
                      AND s.snapshot_date < :d AND s.snapshot_date >= :d - 31)
                ON CONFLICT DO NOTHING
            """),
            params,
        ).rowcount
    conn.execute(
        text("""
            INSERT INTO edge_load (connection_id, family, snapshot_date, edges, ruleset)
            VALUES (:c, :family, :d, :n, :rs)
            ON CONFLICT (connection_id, family, snapshot_date) DO UPDATE SET
              edges = :n, ruleset = :rs
        """),
        {
            "c": connection_id,
            "family": FAMILIES[origin_prefix],
            "d": day,
            "n": inserted,
            "rs": ruleset if origin_prefix == "rule:" else None,
        },
    )
    return inserted


def unresolved_hosts(edges: list[DerivedEdge]) -> list[str]:
    """AWS-owned host names the rules pointed at but no inventoried resource owns."""
    hosts = {
        e.target_uid.removeprefix(EXTERNAL) for e in edges if e.target_uid.startswith(EXTERNAL)
    }
    return sorted(host for host in hosts if _AWS_HOST.search(host))


def owners_of_hosts(
    conn: Connection, *, connection_id: int, day: date, hosts: list[str]
) -> dict[str, str]:
    """Which inventoried resource holds each host name or address, by the host index the rules
    read (`h`), on the inventory snapshot that stands for the day. A tool that reports an
    address (CloudFox network-ports) joins the inventory here, never by a lookup of its own."""
    if not hosts:
        return {}
    resource_day = effective_day(conn, connection_id=connection_id, day=day)
    if resource_day is None:
        return {}
    conn.execute(text(NO_JIT))
    rows = conn.execute(
        text(f"""
            WITH r AS ({RESOURCES_ON_DAY_SQL}), h AS ({HOSTS_SQL})
            SELECT DISTINCT ON (host) host, uid FROM h
            WHERE host = ANY(CAST(:hosts AS text[])) ORDER BY host, rank, uid
        """),  # noqa: S608 - exported SQL constants only
        {
            "resource_day": resource_day,
            "connection_id": connection_id,
            "hosts": [h.lower() for h in hosts],
        },
    )
    return {r.host: r.uid for r in rows}


def write_edges(
    engine: Engine, *, rules_dir: Path, connection_id: int, day: date, ruleset: str
) -> int:
    """Derives the day's rule edges and loads them. `ruleset` names the rules and path kinds
    they come from (ingest's rule_set()), recorded with the load."""
    rules = load_rules(rules_dir)
    edges = derive_edges(engine, rules=rules, connection_id=connection_id, day=day)
    with engine.begin() as conn:
        for host in unresolved_hosts(edges):
            record_unresolved(
                conn,
                tool="steampipe",
                connection_id=connection_id,
                raw_ref=host,
                reason="host name owned by no resource in the inventory",
                day=day,
            )
        return load_edges(
            conn,
            edges=edges,
            connection_id=connection_id,
            day=day,
            origin_prefix="rule:",
            ruleset=ruleset,
        )
