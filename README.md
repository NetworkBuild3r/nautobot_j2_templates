# Nautobot Golden Config Setup

## Overview

This README provides guidance on the Nautobot Golden Config setup configured by AHEAD for WEC Energy Group. The setup uses Nautobot's Golden Config plugin to generate "golden" (intended) device configurations for Cisco IOS/IOS-XE devices based on Nautobot's source-of-truth data. It standardizes configs across access, distribution, and core switches and supports future compliance checks.

The Jinja2 templates are modular, tailored for Cisco, and integrated via Git. Explanations are included for design choices (e.g., GraphQL fields, folder structures) to help you maintain and extend it.

The main "driver" templates (`cisco_xe_access.j2`, `cisco_xe_core.j2`, `cisco_xe_distribution.j2`) serve as entry points for device roles (access, core, distribution). They share a common structure: starting with global settings, conditionally including sections like AAA, VLANs, etc., based on `config_context` data or device attributes. If data is missing, they output comments (e.g., `! AAA not defined`) for easy debugging without failing the render.

Key differences across drivers:
- **Access (`cisco_xe_access.j2`)**: Focused on edge/layer-2 configs; no OSPF (as access switches typically don't route). Includes all common sections.
- **Core/Distribution (`cisco_xe_core.j2`, `cisco_xe_distribution.j2`)**: Identical to each other; add OSPF for layer-3 routing. Otherwise, mirror access with the same includes.

Below, we break down each section used across all drivers, including what it configures (key CLI lines generated), required/optional `config_context` keys (from Nautobot Config Contexts, with example YAML), data from other sources (e.g., GraphQL/device attributes), and customization tips. Sections are modular via `{% include %}`—edit the `common/cisco/` file to update all drivers at once.

## Prerequisites

- Nautobot installed and running (via your Ansible script).
- Golden Config plugin installed and activated in `nautobot_config.py`.
- Basic Nautobot knowledge (devices, interfaces, config contexts, etc.).
- Git repos accessible (credentials in Nautobot Secrets).

If missing, check Nautobot docs or contact AHEAD.

## Jinja Templates Repository

Templates are in Git at `https://ados.wecenergygroup.com/TIInfrastructure/TIAnsibleAutomation.git/jinja_templates`, added to Nautobot as a Git Repository:

- **Name**: "Golden Config Templates"
- **Remote URL**: `https://ados.wecenergygroup.com/TIInfrastructure/TIAnsibleAutomation.git/jinja_templates`
- **Branch**: Default (main/master).
- **Provides**: "jinja templates".
- **Credentials**: "jinja-repo-credentials" Secret Group.

### Folder Structure and Rationale

- **common/cisco/**: Shared snippets (e.g., `aaa.j2`, `snmp.j2`). *Why?* Centralizes reusable code to avoid duplication—update once, affects all roles via includes. Promotes consistency.
- **access/**: Access-layer specifics (e.g., `management_svi.j2`). *Why?* Groups unique configs; easy to expand with subfolders.
- **Root**: Main templates (e.g., `cisco_xe_core.j2`). *Why?* Simplifies path matching in settings.

Structure balances simplicity and scalability, based on Jinja best practices.

Sync status: Check **Extensibility > Git Repositories**.

### How to Maintain and Add to It

- **Syncing**: Auto-syncs; manual sync in UI post-updates.
- **Updates**: Edit in Git (Azure DevOps), commit with messages (e.g., "Updated SNMP in common/cisco/snmp.j2"), resync.
- **Adding Content**:
  - Shared: Add to `common/cisco/` (e.g., `bgp.j2`), include in mains.
  - Role-specific: Use/add subfolders, include in main template.
  - New roles: Add file like `cisco_xe_firewall.j2` at root; match slugs.
  - Naming: Lowercase, underscores, `.j2` suffix, platform prefix.

- **Git Flow for Testing**:
  - **Main**: Prod-ready.
  - **Feature Branches**: Branch from main (e.g., `feature/add-bgp`), develop/test.
  - **Testing**: Local Jinja render; staging Nautobot (change branch temporarily); run Intended on test devices.
  - **Release**: PR to main, review, merge, tag (e.g., v1.1), resync prod.
  *Why Git Flow?* Prevents breaking prod; enables reviews.

- **Credentials**: Update Secret Group if changed.

## Golden Config Settings

Configured under **Plugins > Golden Config > Settings**:

- **Enable Intended**: True.
- **Enable SOT Aggregation**: True.
- **Jinja Repository**: "Golden Config Templates".
- **Jinja Path Template**: `{{ obj.platform.slug }}_{{ obj.device_role.slug }}.j2`.
- **Intended Repository** (optional): `https://ados.wecenergygroup.com/TIInfrastructure/TIAnsibleAutomation.git/intended_configs`.
- **Intended Path Template**: `{{obj.site.slug}}/{{obj.name}}.cfg`.
- **SOT Aggregation Query**: "Golden Config Device Data".

*Why these?* Slugs for auto-matching; start simple with generation.

### Maintenance

- Match slugs to templates.
- Update repo URLs here, resync.
- Config file changes: Edit `nautobot_config.py`, restart services.

## Source-of-Truth Data (GraphQL Query)

Query "Golden Config Device Data" under **Extensibility > Saved Queries** aggregates data:

```graphql
query ($device_id: ID!) {
  device(id: $device_id) {
    hostname: name
    position
    rack {
      name
      rack_group {
        name
      }
    }
    serial
    primary_ip4 {
      id
      primary_ip4_for {
        id
        name
      }
    }
    tenant {
      name
    }
    tags {
      name
    }
    role {
      name
    }
    platform {
      name
      manufacturer {
        name
      }
      network_driver
      napalm_driver
    }
    software_version {
      version
    }
    location {
      name
      shipping_address
      parent {
        name
      }
    }
    vrfs {
      name
    }
    interfaces {
      description
      mac_address
      enabled
      name
      vrf {
        name
      }
      ip_addresses {
        address
        tags {
          id
        }
      }
      connected_circuit_termination {
        circuit {
          cid
          commit_rate
          provider {
            name
          }
        }
      }
      tagged_vlans {
        name
        vid
      }
      untagged_vlan {
        name
        vid
      }
      cable {
        termination_a_type
        status {
          name
        }
        color
      }
      tags {
        id
      }
      mode
      lag {
        name
      }
      _custom_field_data
    }
    all_modules {
      interfaces {
        description
        mac_address
        enabled
        name
        vrf {
          name
        }
        ip_addresses {
          address
          tags {
            id
          }
        }
        connected_circuit_termination {
          circuit {
            cid
            commit_rate
            provider {
              name
            }
          }
        }
        tagged_vlans {
          name
          vid
        }
        untagged_vlan {
          name
          vid
        }
        cable {
          termination_a_type
          status {
            name
          }
          color
        }
        tags {
          id
        }
        mode
        lag {
          name
        }
        _custom_field_data
      }
    }
    config_context
  }
  secrets_groups {
    name
  }
}
```
### Drivers strcuture 
| Driver                | Focus                  | Key Additions/Features                          | Includes OSPF? | Common Sections Included |
|-----------------------|------------------------|-------------------------------------------------|----------------|--------------------------|
| **Access**<br>(cisco_xe_access.j2) | Edge/Layer-2 configurations (e.g., access ports, SVIs) | - Management SVI (optional via access/management_svi.j2)<br>- Uplink Port-Channel (optional via access/uplink_portchannel.j2)<br>- Focused on switchports, VLANs, no routing | No            | Global Settings, AAA, VLANs, DNS, Spanning Tree, Interfaces, SNMP, Banner, VRFs, Line Configs, IP Settings, NTP |
| **Core**<br>(cisco_xe_core.j2) | Layer-3 routing core (e.g., aggregation, backbone) | - OSPF routing (conditional on ospf/ospf_group)<br>- Identical to Distribution otherwise<br>- Suitable for high-priority STP roots | Yes           | Global Settings, AAA, VLANs, DNS, Spanning Tree, Interfaces, SNMP, Banner, VRFs, Line Configs, IP Settings, NTP |
| **Distribution**<br>(cisco_xe_distribution.j2) | Layer-3 distribution (e.g., building/floor aggregation) | - OSPF routing (conditional on ospf/ospf_group)<br>- Identical to Core otherwise<br>- Balanced for mid-tier routing | Yes           | Global Settings, AAA, VLANs, DNS, Spanning Tree, Interfaces, SNMP, Banner, VRFs, Line Configs, IP Settings, NTP 
### Why "all_modules { interfaces {"?

Handles stacked/modular devices (e.g., Catalyst 9300 stacks). Standard `interfaces` misses module/stack interfaces; this aggregates all for complete configs. Future-proofs; minimal overhead if unused.

### Maintenance

- Test in /graphql/ with device ID.
- Updates: Edit, resave, reselect in settings. Test in staging.
- Git Flow: Branch for changes, test, PR.

## How Config Rendering Works

Golden Config renders intended configurations by combining Nautobot data with Jinja2 templates. Here's the step-by-step process:

1. **Data Aggregation (SOT)**: When you run the Intended job, Nautobot executes the GraphQL query ("Golden Config Device Data") for each selected device. This pulls structured data (e.g., `host.config_context`, `host.interfaces`, custom fields) into a Python dict. The query is customizable—add fields for new data needs.

2. **Template Selection**: Based on the Jinja Path Template (`{{ obj.platform.slug }}_{{ obj.device_role.slug }}.j2`), Nautobot selects the matching template from the Git repo (e.g., `cisco_xe_access.j2`).

3. **Jinja Rendering**: The template is rendered using Jinja2, passing the aggregated data as variables (e.g., `host` for device, `interfaces` for list). Conditionals check for data (e.g., `{% if host.config_context.aaa %}`), includes pull shared snippets, and loops/macros handle dynamic parts like interfaces. Secrets are injected via filters like `get_secret_by_secret_group_name`. If data is missing, comments are added for visibility.

4. **Output Storage**: The rendered config is stored in the Intended Git repo (per path template) or Nautobot database. You can view it in the device UI or Git.

**Notes**:
- **Performance**: For large fleets, optimize GraphQL (remove unused fields) or batch jobs.
- **Debugging**: Warnings in output indicate gaps—fix by populating data. Use Nautobot logs for render errors.
- **Extensions**: Add Jinja filters/extensions in Nautobot plugins for custom logic (e.g., IP calculations).

This data-driven rendering ensures configs are always based on your Nautobot SOT, promoting consistency.

## Template Sections and Configuration Options

### Global Settings (`common/cisco/global_settings.j2`) - Used in All Drivers

- **What it configures**: Foundational device settings, e.g., `no ip domain lookup`, `service timestamps ...`, `service password-encryption`, `service call-home`, `platform punt-keepalive disable-kernel-core`, `hostname {{ host.name }}`, `logging buffered 16384 debugging`, `clock timezone CST -6 0`, `clock summer-time CDT recurring`, enable secret and local username (with secrets), `udld aggressive`, `crypto key generate rsa ...`, `logging console warnings`, `vtp mode off`, `lldp run`.
- **Options from config_context**: None direct; pulls `host.name` from GraphQL for hostname.
- **Other data sources**: Secrets for enable/username (e.g., `2021_cisco_credentials` group via `get_secret_by_secret_group_name`).
- **Customization tips**: Hardcoded for common Cisco best practices (e.g., CST timezone). To customize (e.g., change timezone to EST), edit the template lines directly. Add role-specific overrides by wrapping in conditionals (e.g., `{% if host.role.name == 'core' %}clock timezone EST -5 0{% endif %}`). Example config_context (not required): N/A, as it's static.

### AAA (`common/cisco/aaa.j2`) - Used in All Drivers (Conditional on `aaa` key)

- **What it configures**: `aaa new-model`, authentication lists (e.g., `aaa authentication login default group tacacs+ local`), authorization (e.g., `aaa authorization exec default group tacacs+ local`), accounting (e.g., `aaa accounting exec default start-stop group tacacs+`), TACACS+ server groups/servers with keys, dynamic-author, session-id.
- **Options from config_context**: 
  - `aaa.new_model` (bool, optional, default true): Toggles `aaa new-model`.
  - `aaa.authentication` (dict, optional): Subkeys `dot1x` (str), `login.console/default` (str), `enable` (str).
  - `aaa.authorization` (dict, optional): `exec/network/auth_proxy` (str).
  - `aaa.accounting` (dict, optional): `exec` (str), `commands['0']/['15']` (str); always adds delay-start and proxy/dot1x/network.
  - `aaa.server_groups['tacacs+']` (dict, optional): `default.servers` (list of dicts with `name`).
  - `aaa.tacacs_servers` (list of dicts, optional): `name` (str), `ip_address` (str), `secret_group` (str for Nautobot Secret Group).
  - `aaa.misc.session_id` (str, optional): e.g., "common".
  - Example YAML:
    ```
    aaa:
      new_model: true
      authentication:
        login:
          default: "group tacacs+ local"
        enable: "group tacacs+ enable"
      authorization:
        exec: "group tacacs+ local"
      accounting:
        exec: "default start-stop group tacacs+"
      tacacs_servers:
        - name: TAC1
          ip_address: 10.1.1.10
          secret_group: tacacs-key-group
      misc:
        session_id: common
    ```
- **Other data sources**: Secrets pulled via `get_secret_by_secret_group_name("secret")` for keys.
- **Customization tips**: If `aaa` missing, outputs comment—safe default. Expand for RADIUS by adding `server_groups['radius']`. Test secrets in Nautobot before rendering.

### VLANs (`common/cisco/vlans.j2`) - Used in All Drivers (Conditional on `vlans` key or interface data)

- **What it configures**: `vlan {{ vid }} name {{ name }} description {{ name }}` for each, `ip dhcp snooping vlan <vid list>`.
- **Options from config_context**: `vlans` (optional dict/list, but primarily derives from interfaces).
- **Other data sources**: GraphQL `interfaces.tagged_vlans/untagged_vlan`, interface custom fields (e.g., `cf_voice_vlan` for voice VLANs). Collects unique VIDs (excludes 1), adds voice if not present.
- **Customization tips**: Auto-generated from device/interfaces—populate Nautobot VLAN assignments for accuracy. If missing, comment. To force VLANs, add `vlans` key as list of {'vid': int, 'name': str}. Example config_context (rarely needed):
  ```
  vlans:
    - vid: 100
      name: DATA-100
  ```

### DNS (`common/cisco/dns.j2`) - Used in All Drivers (Conditional on `dns` key)

- **What it configures**: `ip name-server {{ server }}` for each, `ip domain list {{ domain }}`, `ip domain name {{ name }}`, `ip domain lookup source-interface {{ intf }}`; hardcoded `no ip dhcp snooping information option`, `ip dhcp snooping`, `login on-success log`.
- **Options from config_context**:
  - `dns.name_servers` (list of str, optional): Server IPs.
  - `dns.domain_list` (list of str, optional): Domains.
  - `dns.domain_name` (str, optional): Primary domain.
  - `dns.source_interface` (str, optional): e.g., "Vlan1000".
  - Example YAML:
    ```
    dns:
      name_servers: ["8.8.8.8", "8.8.4.4"]
      domain_name: example.com
      source_interface: Vlan1000
    ```
- **Other data sources**: None.
- **Customization tips**: If `dns` missing, comment + hardcoded DHCP/login lines. Remove hardcoded if not needed.

### Spanning Tree (`common/cisco/spanning_tree.j2`) - Used in All Drivers (Conditional on `stp` key)

- **What it configures**: `spanning-tree mode {{ mode }}`, `spanning-tree extend system-id`, priority (`mst 0 priority {{ pri }}` or `vlan 1-4094 priority {{ pri }}`), `errdisable recovery cause udld/bpduguard/storm-control interval 900`.
- **Options from config_context**:
  - `stp.mode` (str, optional, default "mst"): "mst", "rapid-pvst", etc.
  - `stp.priority` (int, optional, default 61440).
  - Example YAML:
    ```
    stp:
      mode: mst
      priority: 4096  # Lower for root bridges (e.g., core)
    ```
- **Other data sources**: None.
- **Customization tips**: If missing, comment. Use role-based contexts (e.g., low priority for core).

### Interfaces (`common/cisco/interfaces.j2`) - Used in All Drivers (Conditional on `interfaces` length > 0)

- **What it configures**: For each interface: `interface {{ name }}`, description, mode (switchport access/trunk, no switchport for routed, Vlan for SVIs, stackwise-virtual), IP address/mask, VRF forwarding, OSPF (process/area/network-type/md5), storm control, spanning-tree portfast/bpduguard, dhcp snooping limit/trust, channel-group for LAGs, shutdown/no shutdown.
- **Options from config_context**: `ospf` (dict for process_id, helper_addresses, md5_secret); derives most from device data.
- **Other data sources**: GraphQL `interfaces` (name, description, enabled, ip_addresses, vrf, untagged_vlan, tagged_vlans, lag, _custom_field_data like vlan_type/data_vlan/voice_vlan/storm_control_level/action/portfast/bpduguard/dhcp_snooping_limit/trust/ospf_enabled/area/md5_key/network_type/stackwise_virtual_type/id).
- **Customization tips**: Sorts physical then logical; infers mode from data (e.g., VLANs for switchport). Populate custom fields in Nautobot for control. Macros handle storm/OSPF. Example custom fields on interface: `vlan_type: "data"`, `data_vlan: 100`, `portfast: true`.

### OSPF (`common/cisco/ospf.j2`) - Used in Core/Distribution Only (Conditional on `ospf` and `ospf_group`)

- **What it configures**: `router ospf {{ process_id }}`, `router-id {{ loopback_ip }}`, `ignore lsa mospf`, `log-adjacency-changes {{ detail }}`, `area {{ area }} authentication message-digest`, `area {{ area }} {{ type }} {{ options }}`, `network {{ ip }} {{ wildcard }} area {{ area }}` for OSPF interfaces.
- **Options from config_context**:
  - `ospf.loopback_ip` (str, required): Router ID.
  - `ospf.area` (str/int, required).
  - `ospf_group.process_id` (int, default 1).
  - `ospf_group.global_settings.ignore_lsa_mospf` (bool, optional).
  - `ospf_group.global_settings.log_adjacency_changes` (str, optional): e.g., "detail".
  - `ospf_group.area_type` (str, optional): e.g., "nssa".
  - `ospf_group.area_options` (list, optional): e.g., ["no-summary"].
  - `ospf.interfaces` (list of str, optional): Interface names; derives networks from IPs.
  - Example YAML:
    ```
    ospf:
      loopback_ip: 192.168.0.1
      area: 0
    ospf_group:
      process_id: 1
      area_type: nssa
      area_options: ["no-summary"]
    ```
- **Other data sources**: Interface IPs for networks.
- **Customization tips**: If missing, comment. Add BGP similarly if needed.

### SNMP (`common/cisco/snmp.j2`) - Used in All Drivers (Conditional on `cisco_snmp_ios.snmp`)

- **What it configures**: `ip access-list standard SNMP_ACCESS_ACL` with hardcoded permits (DNA Center, SevOne, Prime), `snmp-server community {{ key }} {{ perm }} SNMP_ACCESS_ACL`, `snmp-server trap-source {{ intf }}`, `snmp-server contact "{{ contact }}"`, `snmp-server location {{ composed }}`, `snmp-server enable traps {{ trap }}` for each, `snmp-server host {{ ip }} version {{ ver }} {{ key }}`.
- **Options from config_context**:
  - `cisco_snmp_ios.snmp.contact` (str, optional).
  - `cisco_snmp_ios.snmp.trap_source` (str, optional).
  - `cisco_snmp_ios.snmp.communities` (list of dicts: secret_group, permission).
  - `cisco_snmp_ios.snmp.hosts` (list of dicts: ip, version, secret_group).
  - `cisco_snmp_ios.snmp.enable_traps` (list of str, optional).
  - Example YAML:
    ```
    cisco_snmp_ios:
      snmp:
        contact: "Net Team <net@example.com>"
        trap_source: Vlan1000
        communities:
          - secret_group: snmp-ro
            permission: ro
        hosts:
          - ip: 10.10.10.10
            version: "2c"
            secret_group: snmp-trap
        enable_traps: ["bgp", "rstp"]
    ```
- **Other data sources**: Location from GraphQL (location/rack_group/rack).
- **Customization tips**: If missing, comment. Update hardcoded ACL for your pollers. Secrets for keys/communities.

### Banner (`common/cisco/banner.j2`) - Used in All Drivers

- **What it configures**: Multiline `{{ host.config_context.data.banner_login }}`.
- **Options from config_context**:
  - `data.banner_login` (str/multiline, optional).
  - Example YAML:
    ```
    data:
      banner_login: |
        Authorized Access Only!
        Disconnect if unauthorized.
    ```
- **Other data sources**: None.
- **Customization tips**: Simple; add MOTD banner if needed by extending template.

### VRFs (`common/cisco/vrfs.j2`) - Used in All Drivers (Conditional on `vrfs`)

- **What it configures**: `vrf definition {{ name }} address-family ipv4 exit-address-family`.
- **Options from config_context**: `vrfs` (list of dicts: name); or from GraphQL `host.vrfs`.
- **Other data sources**: Device VRFs.
- **Customization tips**: If missing, comment. Add RD/export via template edits. Example YAML:
  ```
  vrfs:
    - name: MGMT
  ```

### Line Configs (`common/cisco/line_configs.j2`) - Used in All Drivers (Conditional on `line_configs`)

- **What it configures**: `ip access-list standard VTY_ACCESS_ACL` with hardcoded permits (10/192 networks), `line con 0` (timeout, logging, auth), `line vty 0 4/5 15/16 31` (ACL, timeout, accounting, transport input ssh).
- **Options from config_context**: `line_configs` (optional, but content hardcoded).
- **Other data sources**: None.
- **Customization tips**: If missing, comment. Update ACL for your management nets; add `line aux` if needed.

### IP Settings (`common/cisco/ip_settings.j2`) - Used in All Drivers (Conditional on `site_pedc` and `syslog`)

- **What it configures**: `ip default-gateway {{ gw }}`, `ip http server/authentication local/secure-server`, `ip http client source-interface {{ intf }}`, `ip forward-protocol nd`, `ip tacacs/ssh source-interface {{ intf }}`, `ip ssh version 2`.
- **Options from config_context**:
  - `site_pedc.default_gateway` (str, optional, default "10.4.1.1").
  - `syslog.source_interface` (str, required for condition).
  - Example YAML:
    ```
    site_pedc:
      default_gateway: 10.4.1.1
    syslog:
      source_interface: Vlan1000
    ```
- **Other data sources**: None.
- **Customization tips**: If incomplete, comment. Hardcoded HTTP local—change to AAA if preferred.

### NTP (`common/cisco/ntp.j2`) - Used in All Drivers (Conditional on `ntp`)

- **What it configures**: `ntp server {{ server }}` for each.
- **Options from config_context**:
  - `ntp.servers` (list of str, optional).
  - Example YAML:
    ```
    ntp:
      servers: ["192.0.2.1", "192.0.2.2"]
    ```
- **Other data sources**: None.
- **Customization tips**: If missing, comment. Add `ntp authenticate` via template for security.

## Populating Nautobot Data

Populate for templates:

- **Devices**: Platform/role slugs, location, interfaces, VLANs.
- **Interfaces**: Mode, VLANs, descriptions, LAGs, custom fields as above.
- **Config Contexts**: YAML/JSON with keys/examples from sections. Attach globally or per role/site. Use Secrets for sensitive (e.g., via group names).
- **Custom Fields**: Create on Interface model; populate per interface.

Use UI/bulk/scripts. Templates warn on missing data.

### Maintenance

- Use Config Context Schemas to validate YAML structures.
- Layer contexts (global for AAA/SNMP, role for STP priority, site for DNS/NTP).

## Examples and Sample Data

To get started quickly, here are full examples of data setup in Nautobot. Use these as templates and adapt for your environment.

### Full Config Context Example (Global YAML)
Attach this to all devices or a role (e.g., "access") via **Organization > Config Contexts**:
```
aaa:
  new_model: true
  authentication:
    login:
      default: "group tacacs+ local"
    enable: "group tacacs+ enable"
  authorization:
    exec: "group tacacs+ local"
  accounting:
    exec: "default start-stop group tacacs+"
  tacacs_servers:
    - name: TAC1
      ip_address: 10.1.1.10
      secret_group: tacacs-key-group
  misc:
    session_id: common
dns:
  name_servers: ["8.8.8.8", "8.8.4.4"]
  domain_name: example.com
  source_interface: Vlan1000
stp:
  mode: mst
  priority: 61440
ntp:
  servers: ["192.0.2.1", "192.0.2.2"]
syslog:
  source_interface: Vlan1000
cisco_snmp_ios:
  snmp:
    contact: "Net Team <net@example.com>"
    trap_source: Vlan1000
    communities:
      - secret_group: snmp-ro
        permission: ro
    hosts:
      - ip: 10.10.10.10
        version: "2c"
        secret_group: snmp-trap
    enable_traps: ["bgp", "rstp"]
# For core/dist: Add ospf and ospf_group as in OSPF section example
```

### Custom Fields Definition
Create these on the Interface model (**Extensibility > Custom Fields**):
- `vlan_type`: Choice field (options: data, video, security; description: "Primary VLAN type for access port").
- `data_vlan`: Integer (description: "Data VLAN ID if vlan_type is data").
- `voice_vlan`: Integer (description: "Voice VLAN ID for VoIP").
- `storm_control_level`: Integer (description: "Broadcast storm control level (percentage)").
- `storm_control_action`: Text (description: "Action on storm threshold: shutdown or trap").
- `portfast`: Boolean (description: "Enable spanning-tree portfast").
- `bpduguard`: Boolean (description: "Enable spanning-tree bpduguard").
- `dhcp_snooping_limit`: Integer (description: "DHCP snooping rate limit").
- `dhcp_snooping_trust`: Boolean (description: "Mark as DHCP snooping trusted port").
- `ospf_enabled`: Boolean (description: "Include in OSPF").
- `ospf_area`: Text (description: "OSPF area ID").
- `ospf_md5_key`: Integer (description: "OSPF MD5 key ID").
- `ospf_network_type`: Text (description: "OSPF network type: broadcast, point-to-point, etc.").
- `stackwise_virtual_type`: Text (description: "Stackwise Virtual type: link or dual-active-detection").
- `stackwise_virtual_id`: Integer (description: "Stackwise Virtual link ID").

### Sample Test Device
Add a device in Nautobot:
- Name: test-access-switch
- Platform: Slug "cisco_xe"
- Role: Slug "access"
- Location: Your site/rack
- Interfaces: Add GigabitEthernet1/0/1 with untagged_vlan (VID 100, name "DATA-100"), custom fields (vlan_type: data, portfast: true, storm_control_level: 5).
- Config Context: Assign the global YAML above.
- Run Intended job on this device to verify output—no warnings if data is complete.

## Security Considerations

Golden Config handles sensitive data like passwords and keys—follow these practices to secure your setup:

- **Secrets Management**: Use Nautobot Secrets (**Organization > Secrets**) for all credentials (e.g., TACACS, SNMP). Create groups like "tacacs-key-group" and reference in config_context (e.g., `secret_group: tacacs-key-group`). Templates pull via `get_secret_by_secret_group_name`—test access in UI. Avoid plaintext in YAML.
- **Git Repos**: Use private repos with credentials in Secret Groups. Enable Git HTTPS auth and rotate tokens regularly.
- **Access Control**: Restrict Nautobot roles—limit "edit" on config contexts/templates to admins. Use RBAC for jobs (e.g., only network team runs Deploy).
- **Deployment Safety**: Always use dry-run in Deploy jobs; integrate with change approval (e.g., via Nautobot webhooks).
- **Auditing**: Git commits for intended/backups provide history—enable Nautobot logging for job audits.
- **Config Rendering Security**: During rendering, secrets are injected dynamically and not stored in templates. Ensure the Intended repo is secure, as it holds full configs (including resolved secrets if not masked). Use Git encryption tools if needed. Avoid rendering in untrusted environments.
- **Post-Processing Rendered Secrets with Jinja and Nautobot**: To enhance security, secrets in templates (e.g., enable passwords, usernames) are wrapped in `{% raw %}` blocks. This prevents the initial Intended job from evaluating and injecting the actual secret values, outputting placeholders like `{{ "2021_cisco_credentials" | get_secret_by_secret_group_name("secret") }}` instead. Why use `{% raw %}`? It escapes the inner Jinja syntax, ensuring the placeholder is treated as literal text during the first render—preventing sensitive data from being stored in the Intended Git repo (avoiding exposure in version control). During compliance, remediation, or deployment, enable post-processing in Golden Config settings (beta feature via `config_postprocessing.py`) to re-render the config on-the-fly, injecting secrets only then (using the same filter). This defers secret resolution to runtime, keeping stored configs safe. Customize post-processing for additional transformations (e.g., masking in logs). Test in staging to confirm placeholders persist in Git and resolve during push.
- **Pitfalls**: Don't store secrets in templates; ensure Nornir connections use encrypted channels (SSH/TLS).

## Generating Intended Configurations

1. **Plugins > Golden Config > Home**.
2. Run Job > Intended.
3. Select devices (filter by site/role), run.
4. View in device details (**Golden Config** tab) or intended Git repo.

Re-run after data/template changes.

## Testing and Validation

Before production use, test the full workflow in a staging Nautobot instance or the community sandbox (demo.nautobot.com). Follow these steps:

1. **Setup Test Data**: Add a sample device (as in Examples section), populate interfaces/custom fields, assign config_context.
2. **Run Jobs Sequentially**:
   - Backup: Verify config fetched and stored in Git.
   - Intended: Check output for warnings (e.g., `! AAA not defined`); compare to expected CLI.
   - Compliance: Run post-intended; ensure rules match sections (e.g., AAA block).
3. **Validate Output**: In device UI, review Golden Config tab for diffs. Use local Jinja tools to mock renders.
4. **Edge Cases**: Test missing data (expect comments), stacked devices (verify all_modules), secret failures.
5. **Automation**: Script tests via Nautobot API (e.g., trigger jobs programmatically).
- **Pitfalls**: Incomplete GraphQL (add fields if new data needed); unsynced Git (resync before tests).

### Pushing Intended Configurations

Once you have generated intended configurations, Nautobot Golden Config supports deploying them to devices through a structured process. This ensures safe, auditable changes by leveraging backups, compliance checks, remediation plans, and deployment jobs. The features are modular, so you can use them independently, but the recommended workflow is:

1. **Ensure Accurate Backups**: Before any deployment, run the Backup job to fetch and store the current (actual) device configurations in a Git repository. This provides a baseline for comparisons and rollbacks.
   - Enable backups in Golden Config settings (set **Enable Backup** to True and configure a Backup repository).
   - Run the job: **Plugins > Golden Config > Home > Run Job > Backup**.
   - *Why first?* Deployments rely on knowing the current state to generate safe diffs and avoid overwriting unexpected changes.

2. **Generate Intended Config**: As described in the previous section, run the Intended job to create the golden configuration based on templates and data.
   - This stores the intended config in the configured Git repo (or Nautobot database).

3. **Perform Compliance Check (Recommended)**: Run the Compliance job to compare actual (backup) vs. intended configs. This identifies discrepancies per feature/section.
   - Enable in settings if not already (**Enable Compliance** to True).
   - Run: **Run Job > Compliance**.
   - Results show in the device UI (Golden Config tab) with diffs.

4. **Create a Build Plan (Remediation)**: Use the remediation feature to generate a partial configuration or "plan" that resolves non-compliance. This is essentially a diff of changes needed.
   - Enable **Enable Remediation** in settings.
   - Nautobot can auto-generate Config Plans from compliance results, or create them manually via the UI (**Golden Config > Config Plans**).
   - Plans can be for full replacement, partial remediation, or missing/extra sections.
   - Review the plan in the UI for approval.

5. **Push the Plan (Deployment)**: Deploy the approved plan to push configs to devices.
   - Enable **Enable Deploy** in settings.
   - Run: **Run Job > Deploy** (select devices/plans).
   - This uses Nornir to connect and apply changes (e.g., via NAPALM or Netmiko). It supports dry-run mode for testing.
   - Post-deploy: Re-run Backup and Compliance to verify.

**Notes**:
- **Prerequisites**: Git repos for backups/intended, device credentials (via Secrets), Nornir setup in Nautobot.
- **Customization**: Use post-processing (beta feature) to transform configs before push (e.g., via chained callables in `config_postprocessing.py`).
- **Best Practices**: Always test in staging; use Git for versioned plans; integrate with approval workflows.
- **Troubleshooting**: Check job logs for connection errors; ensure compliance rules are defined for accurate plans.

### Maintenance

- Check job logs for errors; look for `! warning` in output for data gaps.

## Configuration Compliance (Optional)

- Enable backups: Add backup Git repo in settings, run Backup job (uses NAPALM/Netmiko).
- Define Rules (**Golden Config > Compliance Rules**): One per section (e.g., "AAA") with regex to match config block (e.g., start `aaa new-model`, end before next section).
- Run Compliance job; view per-device/feature diffs in UI.

## Tips and Troubleshooting

- **Global changes**: Edit common snippets (e.g., add logging to `global_settings.j2`).
- **Secrets testing**: Use Nautobot UI to verify group access; render a test device.
- **Common issues**: Slug mismatches (check platform/role), unsynced Git (resync), missing keys (add to config_context), invalid custom fields (validate types).
- **Expansion**: For new sections (e.g., BGP), add `common/cisco/bgp.j2`, include in drivers (e.g., core only via conditional).
- **Resources**: Nautobot docs (Golden Config section), Network to Code Slack/community, Cisco config guides for section details.

## FAQ and Known Limitations

**Q: Why are there warnings in generated configs?** A: Missing data (e.g., no `aaa` key)—populate config_context or custom fields.

**Q: Can I use without backups?** A: Yes, features are independent, but backups enable compliance/deployment.

**Q: How to handle non-Cisco?** A: Add templates/Git; update GraphQL for vendor-specific data.

**Limitations**:
- Cisco-focused templates; expand as needed.