# Common Cisco Templates README

This README documents the shared Jinja2 templates in the `common/cisco/` directory. These snippets are included across main driver templates (e.g., `cisco_xe_access.j2`, `cisco_xe_core.j2`) to promote consistency and avoid duplication. Each section below corresponds to a `.j2` file, with a table summarizing:

- **What it Configures**: Key CLI commands generated.
- **Condition**: When the section is included (e.g., based on `config_context` keys).
- **Required/Optional Keys**: From `config_context` (YAML/JSON in Nautobot), with defaults.
- **Other Data Sources**: E.g., GraphQL fields, device attributes.
- **Example YAML**: Sample `config_context` snippet.
- **Customization Tips**: How to extend or modify.

Templates use conditionals to output comments (e.g., `! Key not defined`) if data is missing, ensuring renders don't fail. Edit these files to update all roles simultaneously. Version: 1.0 (July 14, 2025). For full context, see the main project README.

## aaa.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | AAA new-model, authentication/authorization/accounting lists (e.g., TACACS+), server groups, TACACS servers with keys, dynamic-author, session-id. |
| **Condition**          | Included if `host.config_context.aaa` is defined. |
| **Required/Optional Keys** | - `aaa.new_model` (bool, optional, default: true)<br>- `aaa.authentication` (dict, optional: dot1x, login.console/default, enable)<br>- `aaa.authorization` (dict, optional: exec/network/auth_proxy)<br>- `aaa.accounting` (dict, optional: exec, commands['0']/['15'])<br>- `aaa.server_groups['tacacs+']` (dict, optional: default.servers list)<br>- `aaa.tacacs_servers` (list of dicts, optional: name, ip_address, secret_group)<br>- `aaa.misc.session_id` (str, optional) |
| **Other Data Sources** | Secrets via `get_secret_by_secret_group_name` for keys. |
| **Example YAML**       | ```<br>aaa:<br>  new_model: true<br>  authentication:<br>    login:<br>      default: "group tacacs+ local"<br>    enable: "group tacacs+ enable"<br>  authorization:<br>    exec: "group tacacs+ local"<br>  accounting:<br>    exec: "default start-stop group tacacs+"<br>  tacacs_servers:<br>    - name: TAC1<br>      ip_address: 10.1.1.10<br>      secret_group: tacacs-key-group<br>  misc:<br>    session_id: common<br>``` |
| **Customization Tips** | Expand for RADIUS by adding `server_groups['radius']`. Test secrets in Nautobot UI. Use `{% raw %}` for deferred secret rendering. |

## access_lists.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | IP access-lists (e.g., standard 51/60) for SNMP or other uses, with permit/deny rules. |
| **Condition**          | Included if `cisco_snmp_ios.snmp` and `acl_51` or `acl_60` are defined. |
| **Required/Optional Keys** | - `cisco_snmp_ios.snmp.acl_51` (list of str, optional: rules like "permit 10.0.0.0 0.255.255.255")<br>- `cisco_snmp_ios.snmp.acl_60` (list of str, optional) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>cisco_snmp_ios:<br>  snmp:<br>    acl_51:<br>      - "permit 10.0.0.0 0.255.255.255"<br>      - "deny any log"<br>``` |
| **Customization Tips** | Hardcoded for SNMP; generalize by looping over a `access_lists` dict for other ACLs. |

## banner.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Multiline login banner. |
| **Condition**          | Always included (unconditional). |
| **Required/Optional Keys** | - `data.banner_login` (str/multiline, optional) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>data:<br>  banner_login: \|<br>    Authorized Access Only!<br>    Disconnect if unauthorized.<br>``` |
| **Customization Tips** | Add MOTD by extending with `banner motd`. Use multiline YAML for complex banners. |

## call_home.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Call-home settings (direct output from config_context). |
| **Condition**          | Included if `call_home` is defined. |
| **Required/Optional Keys** | - `call_home` (str, optional: full CLI block) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>call_home: "service call-home"<br>``` |
| **Customization Tips** | For simple cases; replace with structured keys (e.g., `call_home.profile`) for modularity. |

## crypto.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Crypto PKI trustpoints, enrollment, subject-name, revocation-check, RSA keypair, certificate chains. |
| **Condition**          | Included if `crypto.trustpoints` is defined. |
| **Required/Optional Keys** | - `crypto.trustpoints` (list of dicts, optional: name, enrollment, subject_name, revocation_check (bool), rsakeypair, cert_chain (list: type, index, data)) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>crypto:<br>  trustpoints:<br>    - name: TP1<br>      enrollment: url http://ca.example.com<br>      subject_name: cn=switch.example.com<br>      revocation_check: false<br>      rsakeypair: rsa2048<br>      cert_chain:<br>        - type: ca<br>          index: 01<br>          data: "-----BEGIN CERTIFICATE-----..."<br>``` |
| **Customization Tips** | Handle sensitive cert data via secrets. Add auto-enrollment logic if needed. |

## dns.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Name servers, domain list/name, lookup source-interface; hardcoded DHCP snooping and login log. |
| **Condition**          | Included if `dns` is defined. |
| **Required/Optional Keys** | - `dns.name_servers` (list of str, optional)<br>- `dns.domain_list` (list of str, optional)<br>- `dns.domain_name` (str, optional)<br>- `dns.source_interface` (str, optional) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>dns:<br>  name_servers: ["8.8.8.8", "8.8.4.4"]<br>  domain_name: example.com<br>  source_interface: Vlan1000<br>``` |
| **Customization Tips** | Remove hardcoded lines if not needed. Add VRF-specific DNS. |

## global_settings.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | No domain lookup, timestamps, password-encryption, call-home, punt-keepalive, hostname, logging, clock (CST/CDT), enable/user secrets, UDLD, RSA key, console warnings, VTP off, LLDP. |
| **Condition**          | Always included (unconditional). |
| **Required/Optional Keys** | None (static, pulls `obj.name` for hostname). |
| **Other Data Sources** | Secrets for enable/username (group: "2021_cisco_credentials"). |
| **Example YAML**       | N/A (static). |
| **Customization Tips** | Make timezone configurable (e.g., via `config_context.timezone`). Use role conditionals for overrides. |

## interface_filters.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Macro for sorting interfaces by name. |
| **Condition**          | Utility macro, used in interfaces.j2. |
| **Required/Optional Keys** | N/A (macro). |
| **Other Data Sources** | Interfaces list. |
| **Example YAML**       | N/A. |
| **Customization Tips** | Extend macro for custom sorting (e.g., by speed). |

## interfaces.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Interface configs: description, mode (access/trunk/routed/VLAN/stackwise), IP/VRF, OSPF, storm control, portfast/BPDUguard, DHCP snooping, LAG, shutdown. |
| **Condition**          | Included if `interfaces` length > 0. |
| **Required/Optional Keys** | - `ospf` (dict: process_id, helper_addresses, md5_secret)<br>Most derived from interface data. |
| **Other Data Sources** | GraphQL: interfaces (name, desc, enabled, ip_addresses, vrf, vlans, lag, custom_fields like vlan_type, storm_control_level, portfast, etc.). |
| **Example YAML**       | ```<br>ospf:<br>  process_id: 1<br>  helper_addresses: ["10.0.0.1"]<br>```<br>(Custom fields on interfaces in Nautobot). |
| **Customization Tips** | Use macros for sub-sections. Populate custom fields for control. Sort physical then logical. |

## ip_settings.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Default gateway, HTTP server/auth/secure, HTTP client source, forward-protocol, TACACS/SSH source, SSH v2. |
| **Condition**          | Included if `site_pedc` and `syslog` are defined. |
| **Required/Optional Keys** | - `site_pedc.default_gateway` (str, optional, default: "10.4.1.1")<br>- `syslog.source_interface` (str, required) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>site_pedc:<br>  default_gateway: 10.4.1.1<br>syslog:<br>  source_interface: Vlan1000<br>``` |
| **Customization Tips** | Change HTTP auth to AAA. Add IPv6 if needed. |

## line_configs.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | VTY ACL (hardcoded permits), line con/vty configs (timeout, logging, auth, ACL, accounting, transport SSH). |
| **Condition**          | Included if `line_configs` is defined (content hardcoded). |
| **Required/Optional Keys** | - `line_configs` (optional, triggers include; no subkeys). |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>line_configs: true<br>``` |
| **Customization Tips** | Make ACL permits configurable. Add aux line if needed. |

## logging_config.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Logging console level (default: informational). |
| **Condition**          | Included if `logging.console` is defined. |
| **Required/Optional Keys** | - `logging.console` (str, optional) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>logging:<br>  console: warnings<br>``` |
| **Customization Tips** | Extend for buffered/source/host. Merge with syslog.j2 if overlapping. |

## management_svi.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Management VLAN SVI with IP and no shutdown. |
| **Condition**          | Included if `mgmt` is defined. |
| **Required/Optional Keys** | - `mgmt.vlan` (str, optional, default: '1000')<br>- `mgmt.ip` (str, required) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>mgmt:<br>  vlan: 1000<br>  ip: 192.168.1.1/24<br>``` |
| **Customization Tips** | Add VRF or helper-address for management. |

## ntp.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | NTP servers. |
| **Condition**          | Included if `ntp.servers` is defined. |
| **Required/Optional Keys** | - `ntp.servers` (list of str, optional) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>ntp:<br>  servers: ["192.0.2.1", "192.0.2.2"]<br>``` |
| **Customization Tips** | Add `ntp authenticate` for security. |

## ntp_logging.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | NTP servers, logging source-interface, logging host. |
| **Condition**          | Unconditional for NTP; requires `syslog` for logging. |
| **Required/Optional Keys** | - `ntp.servers` (list)<br>- `syslog.source_interface` (str)<br>- `syslog.logging_host` (str) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>ntp:<br>  servers: ["192.0.2.1"]<br>syslog:<br>  source_interface: Vlan1000<br>  logging_host: 10.1.1.1<br>``` |
| **Customization Tips** | Potential duplicate with ntp.j2/syslog.j2; consider merging. |

## ospf.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | OSPF process, router-id, ignore LSA, log changes, area auth/type/options, networks. |
| **Condition**          | Included if `ospf` and `ospf_group` are defined (core/dist only). |
| **Required/Optional Keys** | - `ospf.loopback_ip` (str, required)<br>- `ospf.area` (str/int, required)<br>- `ospf_group.process_id` (int, default: 1)<br>- `ospf_group.global_settings.ignore_lsa_mospf` (bool, optional)<br>- `ospf_group.global_settings.log_adjacency_changes` (str, optional)<br>- `ospf_group.area_type` (str, optional)<br>- `ospf_group.area_options` (list, optional)<br>- `ospf.interfaces` (list of str, optional) |
| **Other Data Sources** | Interface IPs for networks. |
| **Example YAML**       | ```<br>ospf:<br>  loopback_ip: 192.168.0.1<br>  area: 0<br>ospf_group:<br>  process_id: 1<br>  area_type: nssa<br>  area_options: ["no-summary"]<br>``` |
| **Customization Tips** | Add BGP similarly. Derive networks auto from IPs. |

## policy_maps.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Policy-maps (direct output). |
| **Condition**          | Included if `policy_maps` is defined. |
| **Required/Optional Keys** | - `policy_maps` (str, optional: full CLI) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>policy_maps: "policy-map PM1 ..."<br>``` |
| **Customization Tips** | Structure as dict for classes/actions. |

## qos.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | QoS class-maps (match-any, description). Notes defaults. |
| **Condition**          | Included if `qos.class_maps` length > 0 and `qos.enable` (default: true). |
| **Required/Optional Keys** | - `qos.class_maps` (list of dicts: name, description)<br>- `qos.enable` (bool, optional, default: true) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>qos:<br>  enable: true<br>  class_maps:<br>    - name: CM1<br>      description: "Voice Traffic"<br>``` |
| **Customization Tips** | Add policy-maps integration. For new devices, comment as optional. |

## snmp.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | SNMP ACL (hardcoded permits), communities, trap-source, contact/location, enable traps, hosts. |
| **Condition**          | Included if `cisco_snmp_ios.snmp` is defined. |
| **Required/Optional Keys** | - `cisco_snmp_ios.snmp.contact` (str, optional)<br>- `cisco_snmp_ios.snmp.trap_source` (str, optional)<br>- `cisco_snmp_ios.snmp.communities` (list: secret_group, permission)<br>- `cisco_snmp_ios.snmp.hosts` (list: ip, version, secret_group)<br>- `cisco_snmp_ios.snmp.enable_traps` (list of str, optional) |
| **Other Data Sources** | GraphQL: location, rack_group, rack. |
| **Example YAML**       | ```<br>cisco_snmp_ios:<br>  snmp:<br>    contact: "Net Team <net@example.com>"<br>    trap_source: Vlan1000<br>    communities:<br>      - secret_group: snmp-ro<br>        permission: ro<br>    hosts:<br>      - ip: 10.10.10.10<br>        version: "2c"<br>        secret_group: snmp-trap<br>    enable_traps: ["bgp", "rstp"]<br>``` |
| **Customization Tips** | Make ACL configurable. Use `{% raw %}` for communities. |

## spanning_tree.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | STP mode, extend system-id, priority (MST or VLAN), errdisable recovery. |
| **Condition**          | Included if `stp` is defined. |
| **Required/Optional Keys** | - `stp.mode` (str, optional, default: "mst")<br>- `stp.priority` (int, optional, default: 61440) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>stp:<br>  mode: mst<br>  priority: 4096<br>``` |
| **Customization Tips** | Lower priority for roots. Add instances for MST. |

## syslog.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Logging source-interface and host. |
| **Condition**          | Unconditional if keys present. |
| **Required/Optional Keys** | - `syslog.source_interface` (str)<br>- `syslog.logging_host` (str) |
| **Other Data Sources** | None. |
| **Example YAML**       | ```<br>syslog:<br>  source_interface: Vlan1000<br>  logging_host: 10.1.1.1<br>``` |
| **Customization Tips** | Add levels/facilities. Integrate with logging_config.j2. |

## username.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | Local usernames with secrets. |
| **Condition**          | Included if `users` is defined. |
| **Required/Optional Keys** | - `users` (list of dicts: name, secret_name) |
| **Other Data Sources** | Secrets group: "local user". |
| **Example YAML**       | ```<br>users:<br>  - name: admin<br>    secret_name: password<br>``` |
| **Customization Tips** | Use for fallback; prefer AAA. Add privilege levels. |

## vlans.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | VLAN definitions (vid, name, desc), DHCP snooping for VIDs. |
| **Condition**          | Included if `vlans` or interface VLAN data present. |
| **Required/Optional Keys** | - `vlans` (list of dicts: vid, name; optional, derives from interfaces) |
| **Other Data Sources** | GraphQL: interfaces.tagged/untagged_vlans, custom_field: cf_voice_vlan. Excludes VID 1. |
| **Example YAML**       | ```<br>vlans:<br>  - vid: 100<br>    name: DATA-100<br>``` |
| **Customization Tips** | Auto from data; force with key for extras. Sort VIDs. |

## vrfs.j2

| Aspect                  | Details |
|-------------------------|---------|
| **What it Configures** | VRF definitions with IPv4 address-family. |
| **Condition**          | Included if `vrfs` or host.vrfs present. |
| **Required/Optional Keys** | - `vrfs` (list of dicts: name; optional) |
| **Other Data Sources** | GraphQL: host.vrfs. |
| **Example YAML**       | ```<br>vrfs:<br>  - name: MGMT<br>``` |
| **Customization Tips** | Add RD/import/export. Extend for IPv6. 