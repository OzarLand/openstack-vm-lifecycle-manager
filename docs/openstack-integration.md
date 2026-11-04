# OpenStack integration: validated capabilities and constraints

Author: Agent 3 (OpenStack specialist). Purpose: check what OVLM may assume about OpenStack, against real code and not memory.

**Release scope.** Wheels read from PyPI on 2026-11-04, unpacked and read as text only (never imported): `openstacksdk 4.22.0`, `nova 34.0.0` (API max microversion 2.104), `cinder 29.0.0` (API max 3.71), `neutron 29.0.0`, `neutron-lib 5.0.1`, `keystone 30.0.0`, `keystonemiddleware 13.0.2`, `glance 33.0.0`, `octavia 19.0.0`, `designate 23.0.0`, `openstack-placement 16.0.0`. A real cloud runs an older release and has its own policy overrides. Everything below is "what upstream defaults do", not "what your cloud does".

**Tags.** `SOURCE-VERIFIED` (SV) = I read the code. `DOCUMENTED-UNVERIFIED` (DU) = from docstrings or release notes in the wheel only. `ASSUMPTION` (AS) = could not verify. Paths are relative to the package root inside the wheel (for example `nova/api/openstack/compute/servers.py`). `LAB-OBSERVED` (LO) = seen on a real cloud by [EXP-01](experiments/EXP-01-design-assumptions-on-felcloud.md) (Felcloud, member-equivalent credential, one run); it adds to, and does not replace, the source tag.

> **Revision 2026-11-04**: lab results of EXP-01 tagged where they confirm a fact (sections 2, 4, 7, 9, recommendation 11); recommendation 4 reworded to observable facts only (SEC-R-6; matches renewal-workflow.md §1 and W3). New finding, not in the source reading: **the cloud had no working default volume type**. `volume create` without a type returned HTTP 500 (`__DEFAULT__` not found), so any code that creates a volume must pass an explicit type and preflight must check it (LAB-OBSERVED (EXP-01, Felcloud, 2026-11-04)). OVLM creates no Cinder volume in the MVP.

**Policy baseline (SV).** Nova, Neutron, Glance, Octavia, Designate and Placement defaults are role based and project scoped (`scope_types=['project']`). Rules use `reader`, `member`, `manager` and `admin` plus `service`. Cinder 29.0.0 still uses the older "Xena persona" strings (`cinder/policies/base.py`: `SYSTEM_READER_OR_PROJECT_READER = XENA_...`, with a `TODO: update ... in Yoga`). It is project-role based, with no system scope, and many admin operations are the legacy `admin_api` rule. Keystone bootstrap creates the implication chain `admin => manager => member => reader` (`keystone/cmd/bootstrap.py`: `_bootstrap_reader_role`, `_bootstrap_member_role`, `_bootstrap_manager_role`, `_bootstrap_admin_role`). Every new rule has a `DeprecatedRule` fallback to the legacy rule (for example Nova `is_admin:True or project_id:%(project_id)s`). Whether the fallback is active depends on `[oslo_policy] enforce_new_defaults` in the cloud (AS, oslo.policy not read). With the fallback active, a user with no `reader` role can still read, and the role checks below are only a lower bound.

---

## 1. Read-only discovery via openstacksdk

SDK proxies (SV, `openstack/*/_proxy.py`): `compute.servers(details=True, all_projects=False, **query)`, `compute.volume_attachments(server)`, `compute.server_groups()`, `compute.flavors()`, `compute.get_limits()`, `compute.get_quota_set()`; `block_storage.volumes()`, `block_storage.attachments()`, `block_storage.get_limits()`, `block_storage.get_quota_set()`; `network.ports()`, `network.ips()`, `network.security_groups()`, `network.networks()`, `network.subnets()`, `network.get_quota()`; `image.images()`.
The SDK pins `Server._max_microversion = '2.100'`, `VolumeAttachment 2.89`, `ServerGroup 2.64`, compute `Limits 2.57`, `Volume 3.71`. It negotiates min(resource max, server max) (`openstack/resource.py: Resource._get_microversion`) (SV).

| Resource | Call | Minimum role by default policy | Source / policy name | Tag |
|---|---|---|---|---|
| Servers (list, detail, show) | `GET /servers/detail` | project `reader` | Nova `policies/servers.py` `servers:detail`, `servers:show` = `PROJECT_READER_OR_ADMIN` | SOURCE-VERIFIED |
| All-project listing, `deleted` listing | `all_tenants=1`, `vm_state=deleted` | admin | `servers:detail:get_all_tenants` = ADMIN; `servers.py::_get_servers` (403 "Only administrators may list deleted instances") | SOURCE-VERIFIED |
| Server tags, metadata | `GET /servers/{id}/tags`, `/metadata` | reader | `server_tags.py`, `server_metadata.py` | SOURCE-VERIFIED |
| Volume attachments of a server | `GET /servers/{id}/os-volume_attachments` | reader | `volumes_attachments.py` `index`, `show` | SOURCE-VERIFIED |
| Server groups | `GET /os-server-groups` | reader (`index:all_projects` admin) | `server_groups.py` | SOURCE-VERIFIED |
| Flavors | `GET /flavors/detail` | no policy file for flavor list; flavor extra specs `show`/`index` = reader | `flavor_extra_specs.py` | SOURCE-VERIFIED (extra specs) / AS (flavor list open to project users) |
| Compute limits (absolute) | `GET /limits` | any authenticated user (`RULE_ANY`); other project's limits admin | `limits.py` | SOURCE-VERIFIED |
| Compute quota with usage | `GET /os-quota-sets/{pid}/detail` | reader | `quota_sets.py` `detail` = `PROJECT_READER_OR_ADMIN` | SOURCE-VERIFIED |
| Hypervisors, services, aggregates | `/os-hypervisors*` | admin only | `hypervisors.py`: all 7 rules = ADMIN | SOURCE-VERIFIED |
| Placement resource providers, candidates | `/resource_providers`, `/allocation_candidates` | admin or service | `placement/policies/resource_provider.py`, `allocation_candidate.py` | SOURCE-VERIFIED |
| Placement usage per project | `GET /usages?project_id=` | project reader | `placement/policies/usage.py` (second rule `ADMIN_OR_PROJECT_READER_OR_SERVICE`) | SOURCE-VERIFIED (access also depends on the Placement endpoint being in the user's catalog) |
| Cinder volumes list/show | `GET /volumes/detail` | reader | `cinder/policies/volumes.py` `GET_ALL_POLICY`, `GET_POLICY` | SOURCE-VERIFIED |
| Cinder attachments list/show | `GET /attachments` (mv >= 3.27) | no policy rule defined for GET; API filters to project | `cinder/policies/attachments.py` defines only create/update/delete/complete; `api/v3/attachments.py::index` has no `authorize` | SOURCE-VERIFIED (absence of rule) |
| Cinder limits, quota | `GET /limits`, `GET /os-quota-sets/{pid}` | reader | `policies/limits.py`, `policies/quotas.py` `SHOW_POLICY` | SOURCE-VERIFIED |
| Neutron ports, networks, subnets, SGs, FIPs | `GET` | reader (plus shared/external networks for anyone) | `neutron/conf/policies/port.py` `get_port`, `network.py` `get_network`, `floatingip.py` `get_floatingip` | SOURCE-VERIFIED |
| **Neutron quota** | `GET /quotas/{pid}` | **`manager` or admin, not reader or member** | `neutron/conf/policies/quotas.py` `get_quota` = `ADMIN_OR_PROJECT_MANAGER` | SOURCE-VERIFIED |
| Glance images | `GET /v2/images` | reader | `glance/policies/image.py` `get_images` = `ADMIN_OR_PROJECT_READER` (`get_image` also lets image members, public and community images through) | SOURCE-VERIFIED |

### What a non-admin does not see (SV, Nova `policies/`)
- `OS-EXT-SRV-ATTR:host`, `instance_name`, `reservation_id`, `launch_index`, `root_device_name`, `user_data`, `kernel_id`, `ramdisk_id` are all gated by one admin rule, `extended_server_attributes.py` (the SDK fields `compute_host`, `hypervisor_hostname`, `instance_name`, `user_data` stay empty). `hostname` is visible to all from mv 2.90 (policy text says so).
- `host_status` is admin only (`servers:show:host_status`).
- `hostId` is visible to everybody: it is a hash of host and project (`views/servers.py::_get_host_id`). It is usable only to see "same host or not" within one project, never the host name.
- Instance action events and event details are admin only (`instance_actions.py` `events`, `events:details`). Action list and show are reader.

### Server fields relevant to OVLM (SV, `nova/api/openstack/compute/views/servers.py`)
- `created` is always present. `OS-SRV-USG:launched_at` and `terminated_at` are added by `show_srv_usg`. The SDK maps them to `created_at`, `launched_at`, `terminated_at`, `updated_at` (`openstack/compute/v2/server.py`). `launched_at` is null until the first boot succeeded. For the renewal deadline use `launched_at`, and fall back to `created` when it is null.
- Flavor: from mv 2.47 the server embeds `{original_name, vcpus, ram, disk, ephemeral, swap}` and no flavor id (`_get_flavor_dict`). `extra_specs` is added only when the `servers:show:flavor-extra-specs` policy passes (reader by default). Before 2.47 it returns only `id` and links. The SDK uses 2.100, so OVLM gets the embedded form and must map `original_name` back to a flavor by name. The flavor may have been deleted or renamed since boot.
- `image` is `{id, links}` (empty string for boot from volume, AS from the API schema; SV that the SDK has `image` and `image_id`). Boot-from-volume servers have no image id. The image of record is in the root volume's `volume_image_metadata` (Cinder, DU).
- `tags` (list) is present from mv 2.26. `metadata` is always present (`_get_metadata`). `locked` and `locked_reason` (mv 2.73) are present. `server_groups` (mv 2.71) is returned only when `show_server_groups`. The SDK `Server` exposes `server_groups`.
- `addresses` is hidden (empty) while the VM is in `BUILDING` (`_get_addresses`).
- mv 2.69: servers in an unreachable cell are returned as minimal constructs (status `UNKNOWN`, few fields). OVLM must not treat "missing fields" as drift or "gone" (DU, `rest_api_version_history.rst` 2.69).

### Pagination and incremental sync
| Service | Mechanism | Evidence | Tag |
|---|---|---|---|
| Nova | `limit`, `marker`, `servers_links` next link; server cap `[api] max_limit` default 1000 | `common.py::get_limit_and_marker`, `conf/api.py` | SOURCE-VERIFIED |
| Nova | `changes-since` (all versions) and `changes-before` (mv >= 2.66). With either filter, **deleted servers are included** (the `deleted=False` default is skipped), so deletions can be observed as tombstones. | `servers.py::_get_servers` lines "Unless 'changes-since' or 'changes-before' is specified" | SOURCE-VERIFIED |
| Nova | How long tombstones exist depends on operator archive/purge jobs. | n/a | ASSUMPTION |
| Nova | `updated` changes on any server update (state, tags?, metadata). Whether tag edits bump `updated` was not checked; do a periodic full sync regardless. | n/a | ASSUMPTION |
| Nova non-admin filters | `reservation_id, name, status, image, flavor, ip, ip6, changes-since, changes-before, tags/tags-any/not-tags/not-tags-any (2.26), locked (2.73), availability_zone, config_drive, key_name, created_at, launched_at, terminated_at, power_state, task_state, vm_state, progress, user_id (2.83), hostname (2.90)`. **`metadata` is not allowed**: unknown filters are silently removed (`servers.py::remove_invalid_options`), unless the admin-only `allow_all_filters` policy passes. A metadata filter therefore returns ALL servers for a non-admin, without error. | `_get_server_search_options` | SOURCE-VERIFIED |
| Nova `name` filter | Is a regex (`_regex_instance_filter`; SQL `REGEXP`, or `LIKE %x%` on SQLite). Use `^name$` and re-check equality client-side. | `db/main/api.py` | SOURCE-VERIFIED |
| Cinder | `limit`, `marker`, `offset` (`osapi_max_limit` default 1000). Filters from `resource_filters.json`: volumes accept `name, status, metadata, created_at, updated_at, bootable, size, availability_zone, ...`; `updated_at`/`created_at` take comparison operators (`gt:`, `gte:`...) from mv 3.60. Deleted volumes are not listed, so there are **no tombstones**: removal detection needs a full listing. | `cinder/api/common.py`, `api/v3/volumes.py::_handle_time_comparison_filters`, `cinder-29.0.0.data/data/etc/cinder/resource_filters.json` | SOURCE-VERIFIED (the file is an operator-overridable config) |
| Neutron | `limit`, `marker`, `page_reverse`; `pagination_max_limit` default unlimited. **No `changes-since`** (grep over `neutron/` found none). `revision_number` and timestamps exist as extensions (`neutron/extensions/timestamp.py`); the SDK exposes `revision_number`/`updated_at`. Treat as full sync with local diff. | `neutron/conf/common.py` | SOURCE-VERIFIED (no changes-since); DOCUMENTED-UNVERIFIED (timestamp filtering) |
| SDK | Generators follow `next`/`<resource>_links` (`Resource.list`, `_get_next_link` in `openstack/resource.py`). Pass `paginated=True` default; do not pass `limit` unless wanted. | | SOURCE-VERIFIED |

OVLM implication: incremental sync only helps for Nova servers. Volumes, ports, FIPs, SGs and images need full listing per project each cycle, plus a "not seen in N consecutive full syncs" rule before marking `gone` (FR-INV-3).

---

## 2. Nova tags and metadata for ownership marking

| Fact | Evidence | Tag |
|---|---|---|
| Server tags need mv >= 2.26; tags at create need mv >= 2.52 | `rest_api_version_history.rst` 2.26, 2.52; `schemas/servers.py::create_v252` | SOURCE-VERIFIED |
| Tag: 1 to 60 characters, no `,` and no `/`; at most 50 tags per server | `objects/tag.py MAX_TAG_LENGTH=60`, `objects/instance.py MAX_TAG_COUNT=50`, `parameter_types.tag` pattern `^[^,/]*$` | SOURCE-VERIFIED |
| Metadata: key matches `^[a-zA-Z0-9-_:. ]{1,255}$`, value <= 255 characters, quota `metadata_items` default 128 per server | `parameter_types.metadata`, `conf/quota.py` | SOURCE-VERIFIED |
| `ovlm:managed` is a valid tag and a valid metadata key. A workflow run id as tag `ovlm:run:<uuid>` is 9 + 36 = 45 characters, fits. | derived | SOURCE-VERIFIED |
| Tags are queryable by non-admins (`tags`, `tags-any`, `not-tags`) on `GET /servers`; metadata is **not** queryable by non-admins | see section 1; LAB-OBSERVED (EXP-01, Felcloud, 2026-11-04): `tags=` and `tags-any=` returned exactly the tagged servers; the metadata filter was silently ignored (HTTP 200 with every server in the project, including foreign ones) | SOURCE-VERIFIED; LAB-OBSERVED |
| Write: tags and metadata need `member` (`server_tags:update`, `update_all`, `delete`; `server_metadata:*`) | `policies/server_tags.py`, `server_metadata.py` | SOURCE-VERIFIED |
| Neutron tags: <= 255 characters each, <= 50 per resource. Cinder volume metadata: key and value <= 255 characters (`extra_specs` pattern; key set `[a-zA-Z0-9-_:. /]`). Both usable on ports, FIPs, volumes. | `neutron/extensions/tagging.py`; `cinder/api/validation/parameter_types.py::extra_specs`, `api/schemas/volume_metadata.py` | SOURCE-VERIFIED |

Answer: yes, OVLM can mark ownership. Use **tags for lookup** (`ovlm:managed`, `ovlm:run:<id>`) and metadata for payload (`ovlm.service`, `ovlm.profile_version`, `ovlm.role=green|blue`). Constraints:
1. Any project `member` can edit or remove both. They are markers, not a security boundary. OVLM's own database stays the source of truth.
2. Instance metadata is exposed to the guest through the metadata service and config drive (AS, standard Nova behaviour, not re-read). Never put secrets in it.
3. mv >= 2.26 needs explicit negotiation by the caller; the SDK's 2.100 maximum covers it.
4. Tags on a server in a down cell may be missing (mv 2.69 minimal construct).

---

## 3. Idempotency

| Operation | Client idempotency token? | What exists instead | Tag |
|---|---|---|---|
| Nova server create | **No.** Searched `nova/api` and `nova/compute/api.py` for `idempoten`/`client_token`: no request-level token (the only "idempotent" hit is in the 2.104 release note). The schema (`schemas/servers.py::create`) has `min_count`, `max_count`, `return_reservation_id` and no token. Names are not unique: nothing enforces uniqueness of `display_name` in `compute/api.py`. | See below | SOURCE-VERIFIED |
| `return_reservation_id: true` | The response is `{"reservation_id": "r-xxxx"}`; the id is **generated server side** (`utils.generate_uid('r')`, `compute/api.py::_create_instance`); the client cannot supply it. `reservation_id` is an allowed non-admin list filter, so created servers can be listed afterwards. But it cannot be known before the request, so it does **not** help when the response is lost. The SDK has no `return_reservation_id` support (grep over `openstack/compute`), so it would need a raw `session.post`. | Not a substitute for a token | SOURCE-VERIFIED |
| Cinder attach (via Nova) | Nova refuses a duplicate: `compute/api.py::_check_volume_already_attached` raises `InvalidVolume` ("volume X already attached" / "already attached to instances: ...") if a BDM exists. HTTP 400. The Cinder reserve is conditional (`volume.conditional_update` on status). So "attach" is naturally safe to retry: read `GET /servers/{id}/os-volume_attachments` first, and treat "already attached to the target server" as success. | Check-then-act | SOURCE-VERIFIED |
| Neutron FIP association | `PUT /floatingips/{id} {port_id}` is a pure state set. If the FIP is already associated with this port, `_check_and_get_fip_assoc` returns unchanged (`if port_id == floatingip_obj.fixed_port_id: return`). Safe to repeat. If the target port+fixed IP already has another FIP on the same external network, 409 `FloatingIPPortAlreadyAssociated`. | Natural idempotency | SOURCE-VERIFIED |

**Pattern for create (recommended).** Before create, persist the intended name `ovlm-<service>-<run8>-<n>` plus the run id in OVLM's DB. Create with tags `ovlm:managed` and `ovlm:run:<run>` in the same call (mv >= 2.52). On retry or resume: list servers filtered by `tags=ovlm:run:<run>` (works for a non-admin) and by `^name$`, never by metadata. If exactly one matches, adopt it. If zero, create. If more than one, stop and raise an incident (a lost response plus a retry happened). A server in `BUILD` or `ERROR` appears in the list, so a crashed worker never creates a second one. The window left: create accepted by Nova but the worker dies before it records the server id. Listing by tag closes it, because the tag is set atomically with the create.
Quota note: a failed create that is deleted frees the quota; a server left in `ERROR` still counts (AS for exact accounting).

---

## 4. Data volume handoff (detach from A, attach to B)

### API calls and responses (SV)
- Detach: `DELETE /servers/{A}/os-volume_attachments/{volume_id}` returns **202** (`volume_attachments.py::delete`, `@wsgi.response(202)`). Errors: 400 for the root device ("Cannot detach a root device volume") and `InvalidVolume`; 409 for wrong instance state or lock; 404 if not attached.
- Attach: `POST /servers/{B}/os-volume_attachments` returns 200 with `{volumeId, device}` before mv 2.101 and **202 with no body from mv 2.101** (`create`, `needs_device_returned`). The SDK maximum for this resource is 2.89, so the SDK path returns the "async" 200 with a possibly empty `device`. Either way the call is asynchronous: poll.
- States allowed for attach and detach: vm_state in `ACTIVE, PAUSED, STOPPED, RESIZED, SOFT_DELETED, SHELVED, SHELVED_OFFLOADED` and **no task in progress** (`@check_instance_state`, default `task_state=(None,)`). A server in `ERROR` or `BUILD` cannot attach or detach (409).
- **A locked server rejects attach, detach, stop, start and delete from a non-admin** (`compute/api.py::check_instance_lock`: `if instance.locked and not context.is_admin`, 409 `InstanceIsLocked`). See section 7. LAB-OBSERVED (EXP-01, Felcloud, 2026-11-04): a locked server refused detach and stop with HTTP 409 "Instance is locked".
- Detach requires the compute host to be up (`@check_instance_host(check_is_up=True)` on `_detach_volume`). If the host of the old VM is down, the detach is refused.

### Volume state machine (SV, Cinder `volume/api.py`, `volume/manager.py`; Nova `compute/api.py`, `virt/block_device.py`)
Nova uses the Cinder attachments API (`attachment_create` needs Cinder mv >= 3.44, `volume/cinder.py`).

| Step | Volume `status` | Attachment `attach_status` | Where set |
|---|---|---|---|
| Detach requested | `in-use` -> `detaching` | `attached` | `begin_detaching` (conditional on `in-use` and `attached`, else 400 "Volume status must be 'in-use'") |
| Guest released, connection terminated, attachment deleted | `detaching` -> `available` (when it was the last attachment) | row removed | `attachment_delete`, `finish_detach` |
| Guest refused or hypervisor error | `detaching` -> **`in-use`** (rolled back) | stays `attached` | `roll_detaching` on `DeviceDetachFailed` and on any detach exception (`virt/block_device.py::detach`, `compute/manager.py`) |
| Attach requested | `available` -> `reserved` | `reserved` | `_attachment_reserve` (new flow; the legacy `attaching` status belongs to the old `reserve_volume` flow) |
| Connector submitted | `reserved` -> `attaching` (volume) | `attaching` | `attachment_update` writes `attach_status='attaching'`; `attachment_complete` moves the volume to `in-use` (`manager.py::attachment_update`, `volume_attached`) |
| Failure | volume may stay `reserved` or `attaching`; attachment `attach_status` becomes `error_attaching` | `error_attaching` | `volume/manager.py` (line with `ERROR_ATTACHING`) |

Corrections to common assumptions:
- `error_detaching` and `error_attaching` are **values of the attachment's `attach_status`** (`objects/fields.py::VolumeAttachStatus`), not volume `status` values. In this code the volume `status` after a failed detach goes back to `in-use`; I found no code path that sets volume `status='error_detaching'` (grep returned only the enum). Cinder admin tooling can still set `error*` states (`reset_status` is admin only: `volume_actions.py RESET_STATUS = RULE_ADMIN_API`). DU for older clouds that may differ.
- Poll signal for OVLM: the volume (`status`, `attachments[]`) and, for the cause, `GET /servers/{id}/os-instance-actions` (reader) for the `detach_volume`/`attach_volume` action result. Events with tracebacks are admin only.
- Timeouts: libvirt hot-unplug waits `[libvirt] device_detach_timeout` (default 20 s) x `device_detach_attempts` (default 8) = about 160 s before `DeviceDetachFailed` (`conf/libvirt.py`). Budget at least 3 minutes for detach, 2 minutes for attach, plus operator-specific backend time. Cinder backend attach/detach may take longer (AS). Poll every 2 to 5 seconds with exponential backoff and a hard deadline, never an unbounded loop. After the deadline, do not retry attach until the volume is `available`.
- A stuck `reserved`/`attaching` volume or attachment can be cleaned by a member only through the Nova path. Direct `DELETE /attachments/{id}` by a user on an attachment connected to a VM is refused with 409 `ConflictNovaUsingAttachment` unless Nova confirms it is gone (`volume/api.py::attachment_deletion_allowed`, Bug #2004555). Force-detach (`os-force_detach`) and `os-reset_status` are admin only (`FORCE_DETACH_POLICY`, `RESET_STATUS`). So stuck states need an operator; OVLM can only report them (FR-REN-6 fits).

### Attaching an in-use, non-multiattach volume (SV)
Rejected in two places: (1) Nova `_check_volume_already_attached` -> `InvalidVolume` "volume <id> is already attached to instances: <uuids>" -> HTTP 400 (`volume_attachments.py::create` maps `InvalidVolume` to 400); (2) Cinder `_attachment_reserve` -> `InvalidVolume` "Volume X status must be available or downloading to reserve, but the current status is in-use" (also for `reserved`, `detaching`, `attaching`). Both are 400 at the Nova API. Admins resetting state can bypass Cinder's check, which is why Nova re-checks. The same-instance second attach is also rejected ("volume ... already attached").

### `delete_on_termination` (SV)
Relevant and dangerous. Attach to an existing server defaults to `False` (`compute/api.py::attach_volume(delete_on_termination=False)`); an existing volume given as `source_type: volume` in boot BDM defaults to `False` (`block_device.py` lines 86 to 87: `bool(bdm_dict.get('delete_on_termination'))`). Volumes Nova creates from image/blank/snapshot at boot default to `True` (`block_device.py` line 148). So: (a) the persistent data volume must be created by OVLM or the user beforehand, never by Nova at boot; (b) before deleting the old VM, assert `delete_on_termination == false` on the data attachment (visible from mv 2.79 on `GET os-volume_attachments`); (c) if it is true, fix with `PUT /servers/{id}/os-volume_attachments/{vol}` with `delete_on_termination:false` (mv >= 2.85, member). Deleting the server detaches remaining volumes and deletes only those flagged. Preflight check recommended as a blocker.

### Device naming (SV for Nova side, DU for guest side)
Nova chooses the name when none is given (`virt/driver.py::get_device_name_for_instance`, libvirt `blockinfo.py`); the `device` parameter is only a hint, and since mv 2.101 the API does not even wait for the name. The libvirt disk gets `serial = connection_info['serial'] = volume id` (`virt/block_device.py` lines 585, 672, 800; `virt/libvirt/volume/volume.py: conf.serial = connection_info.get('serial')`). Guest kernel enumeration (`/dev/vdb` vs `/dev/vdc`) is not guaranteed to match (DU). Recommended guest lookup: `/dev/disk/by-id/virtio-<first 20 characters of the volume id>` (QEMU truncates virtio-blk serials to 20 characters; AS, QEMU behaviour not in these wheels; LAB-OBSERVED (EXP-01, Felcloud, 2026-11-04): the guest showed `virtio-<volid[0:20]> -> ../../vdb`, and mounting by filesystem UUID worked). With SCSI buses the path is `scsi-0QEMU_QEMU_HARDDISK_<serial>` (AS). Safest of all: put a filesystem label or UUID on the volume once, and mount by `LABEL=`/`UUID=` in fstab (`nofail`). OVLM's profile should store label/UUID, not a device name.

### Same-AZ rule (SV)
`[cinder] cross_az_attach` default True (`conf/cinder.py`). If a cloud sets it False, the server and volume must share an AZ (`check_availability_zone`, `InvalidVolume`). Blue/green must therefore create the green VM in the volume's AZ (`volume.availability_zone`).

### Alternatives
Alternative sequence "stop A, detach, attach to B, start B" is the safest for filesystem integrity: OVLM cannot unmount inside the guest, and a hot-unplug of a mounted volume can be refused by the guest (rolled back to `in-use` after roughly 160 s). Stopping A first removes that failure mode. Rolling back = detach from B, attach to A (A must be unlocked and in `STOPPED`/`ACTIVE`). Cinder volume snapshot or backup before handoff is a member operation (`snapshots` CREATE = member).

---

## 5. Multiattach

| Fact | Evidence | Tag |
|---|---|---|
| Volume type must carry extra spec `multiattach="<is> True"`; admin creates the type. `volume.multiattach` is derived at create. A user cannot request it per volume (the API parameter was removed: "multiattach parameter has been removed ... Contact your administrator"). | `cinder/volume/api.py::_is_multiattach`, `api/v3/volumes.py` lines 460-465 | SOURCE-VERIFIED |
| Creating such a volume needs the `MULTIATTACH_POLICY` (member). Attaching a **bootable** multiattach volume to a second server is a separate policy (`MULTIATTACH_BOOTABLE_VOLUME_POLICY`, member). Encrypted + multiattach is rejected (`create_volume.py` line 495). | `cinder/policies/volumes.py`, `attachments.py`, `volume/flows/api/create_volume.py` | SOURCE-VERIFIED |
| Nova attach needs mv >= 2.60 (`MultiattachNotSupportedOldMicroversion` -> 400 otherwise); not allowed for shelved-offloaded servers; requires virt driver and backend support (libvirt, and backends that declare it). | `compute/utils.py::check_attach_and_reserve_volume`, `compute/api.py::attach_volume` | SOURCE-VERIFIED |
| Retype between multiattach and non-multiattach is only allowed on `available` volumes. | `cinder/volume/api.py::retype` lines ~1903-1931 | SOURCE-VERIFIED |

Why not the default for single-writer filesystems: multiattach only gives block-level shared access (and Cinder status goes `in-use` even with several attachments). ext4/xfs mounted read-write on two guests corrupt without a cluster filesystem or application-level fencing. It also removes the Cinder/Nova guard that prevents the double attach described in section 4, so a double-mount during a faulty cutover would corrupt data silently. Multiattach can serve as an optional strategy only when the data service is cluster-aware (read-only second attach is one valid use: `attach_mode=ro`, `attachment_create`). Default strategy: exclusive handoff.

---

## 6. Cutover

### 6.1 Floating IP re-association (SV)
- One call: `PUT /v2.0/floatingips/{id}` with `{"floatingip": {"port_id": "<B port>"}}` (add `fixed_ip_address` if the port has several IPv4 addresses, else 400 "Port %s has multiple fixed IPv4 addresses"). The DB update happens in **one writer transaction**: `l3_db.py::_update_floatingip` -> `_update_fip_assoc` sets `fixed_port_id`, `fixed_ip_address`, `router_id` together under `CONTEXT_WRITER.using`. No prior disassociate is required. API view: atomic. DU for data plane: the router update notification goes to the L3 agent(s) of the old and the new router (`notify_routers_updated(old_router, new_router)`, `L3RpcNotifierMixin.update_floatingip`); the NAT rule changes asynchronously. The FIP `status` is DOWN/ACTIVE as reported by the agent (not verified in this code). OVLM must poll the FIP `status` and then probe from outside. Expect seconds of inconsistency, not zero downtime. Existing connections through the old NAT are lost (conntrack, AS).
- Preconditions enforced by `_internal_fip_assoc_data` / `_get_assoc_data`: the port belongs to the same project as the FIP (unless admin) else 400; the port has a fixed IPv4 (`is_fip_serviced` only excludes DHCP ports, so **unbound or unattached ports can hold a FIP**); and a router exists that has an interface on the port's subnet and a gateway on the FIP's external network (`get_router_for_floatingip`).
- **No router path:** raises `ExternalGatewayForFloatingIPNotFound`, "External network X is not reachable from subnet Y. Therefore, cannot associate Port Z with a Floating IP." It is a `NotFound` subclass (`neutron_lib/exceptions/l3.py`), so the API answers **404**, easily mistaken for "FIP not found". Map this exception text explicitly. Nothing changes on failure. So run it as a preflight: check that a router interface exists on green's subnet and gateway on the external network. A green VM on a different subnet/router than blue is a design error.
- Target port that already carries another FIP on the same external network -> 409 `FloatingIPPortAlreadyAssociated`. Disassociate or choose another fixed IP first.
- Roles: `update_floatingip` = admin or project `member`; `update_floatingip:router_id` = member; choosing a specific floating address at create (`create_floatingip:floating_ip_address`) = **manager** or admin (`conf/policies/floatingip.py`). OVLM never creates FIPs in the MVP (it moves existing ones), so `member` is enough.
- Revert = same call with the old port id.
- If the VM has no FIP (direct provider network address), this method is impossible (AS from the data model, not a cloud fact). NETWORK_ATTACH_EXTERNAL to external networks is admin only by default (`servers.py` `NETWORK_ATTACH_EXTERNAL = ADMIN`), so ordinary members normally use tenant networks plus FIPs.

### 6.2 Alternatives (short)
| Method | Services | Permissions by default | Notes | Tag |
|---|---|---|---|---|
| Shared VIP port with `allowed_address_pairs` (keepalived-like; or move the VIP between ports) | Neutron | Setting `allowed_address_pairs` on a port = admin or network **owner** `member` (`update_port:allowed_address_pairs` = `ADMIN_OR_NET_OWNER_MEMBER`). On a shared network owned by another project a member cannot set it. | Needs guest cooperation (the guest must own the VIP address). Port security must allow it. Not atomic from one API call. | SOURCE-VERIFIED (policy) |
| Re-point a pre-created port (stable fixed IP, then FIP stays on that port) | Nova, Neutron | Create port with fixed IP/MAC: admin or net owner `member` (`create_port:fixed_ips`, `create_port:mac_address`; on shared networks `fixed_ips` is allowed through `rule:shared`, MAC is not). Delete a compute-owned port: not by project user. | See section 9: the port can only be attached to one server at a time. | SOURCE-VERIFIED |
| Octavia member swap | Octavia (service must exist) | Create/update/delete members: `load-balancer:write` = `member_and_owner` or admin; list/show = `observer_and_owner`, `global_observer`, `member_and_owner` or admin (`octavia/policies/base.py`, `member.py`). `PUT .../members` batch update is one provider call (`controllers/member.py`). | Gives health-checked, graceful shifting; the best choice for zero-downtime. Provisioning-state polling needed (`PENDING_UPDATE`). | SOURCE-VERIFIED (policy); AS (behaviour) |
| Designate recordset update | Designate (DNS) | `update_recordset`: project `member` that owns the recordset/zone and zone type PRIMARY; admin otherwise (`designate/common/policies/recordset.py ADMIN_OR_PROJECT_MEMBER_RECORD_OWNER_ZONE_TYPE`); `get_recordset` = reader. | Limited by TTL and client caches; not an instant cutover. Good as DNS-level indirection. | SOURCE-VERIFIED (policy); AS (propagation) |

---

## 7. Server lifecycle operations OVLM needs

| Operation | Role (default) | Evidence | Remarks | Tag |
|---|---|---|---|---|
| Create from image | `member` | `servers:create` = `PROJECT_MEMBER_OR_ADMIN`; extra gates `create:attach_network` (member), `create:attach_volume` (member), `create:trusted_certs` (member) | `create:forced_host`, `requested_destination`, `network:attach_external_network` = admin; zero-disk flavors = admin | SOURCE-VERIFIED |
| Boot from existing volume | `member` | BDM `source_type=volume, destination_type=volume, boot_index=0`, `delete_on_termination` default false | The volume must be bootable, `available`, in a compatible AZ; but the volume then holds the OS. Not our data volume. For the MVP prefer image boot plus attach data volume afterward, as stated in the task. | SOURCE-VERIFIED (`block_device.py`) |
| Attach existing volume at create (BDM) | `member` | `check_attach_and_reserve_volume` in create path | An in-use volume fails the whole create (400); do the attach after create, as in section 4, to keep control | SOURCE-VERIFIED |
| Stop / start | `member` | `servers:stop`, `servers:start`; stop needs vm_state `ACTIVE` or `ERROR`, start needs `STOPPED` (`compute/api.py::stop/start`) | both blocked by lock for non-admin | SOURCE-VERIFIED |
| Lock | `member` | `os-lock-server:lock`; since mv 2.73 `locked_reason` | `lock()` records `locked_by = 'owner'` if the caller's project equals the server's, else `'admin'` | SOURCE-VERIFIED |
| Unlock | `member`, **but** if `locked_by` differs from the caller's expected value an `unlock:unlock_override` check = **admin** applies | `lock_server.py::_unlock`, `is_expected_locked_by` | A lock set by an admin cannot be removed by the project member. A lock set by the member can be removed by the member. | SOURCE-VERIFIED |
| What a lock blocks | delete, stop, start, attach, detach, reboot, resize, rebuild, etc. for non-admin | `@check_instance_lock`; admin passes via `context.is_admin` | Admin override is by role `admin`; no per-user exception. LAB-OBSERVED (EXP-01, Felcloud, 2026-11-04): detach and stop refused with 409 for an owner lock; the same credential could unlock | SOURCE-VERIFIED; LAB-OBSERVED |
| Delete | `member`, not when locked, no task running | `servers:delete`; `delete` decorated with `check_instance_lock`, `check_instance_state(vm_state=None, task_state=None)` | A delete while a task runs is refused 409 | SOURCE-VERIFIED |
| Server group create (anti-affinity) | `member` | `server_groups:create`; policies `affinity, anti-affinity, soft-affinity, soft-anti-affinity` (mv >= 2.15 for soft); `rules.max_server_per_host` (mv >= 2.64) | Quota `server_groups` default 10, `server_group_members` default 10 | SOURCE-VERIFIED |
| Reboot / resize / rebuild | `member` (migrate: **manager**) | `servers:reboot`, `resize`, `rebuild`; `os-migrate-server:migrate` = `PROJECT_MANAGER_OR_ADMIN` | OVLM does not need them | SOURCE-VERIFIED |
| Reset state, evacuate, shelve-offload, force-delete | admin | `admin_actions.py`, `shelve.py` | A server stuck in `ERROR` with a task state needs an operator | SOURCE-VERIFIED |

Anti-affinity: hint `group=<server_group_id>` at create (`os:scheduler_hints`). Membership is fixed at boot (AS: no add-member API in the policy files). Hard `anti-affinity` makes the green create fail with "No valid host" if capacity does not exist; `soft-anti-affinity` degrades silently. Because the blue VM was probably not created in a group, anti-affinity against it is only possible with the `different_host: [<blue uuid>]` hint, which depends on `DifferentHostFilter` being enabled (it is a scheduler filter; enabled filters are operator config; AS). If neither is possible, same-host green and blue is a valid outcome and OVLM should state that in the plan.

### Capacity pre-check for a non-admin (SV)
- Possible: Nova absolute limits (`totalInstancesUsed`, `totalCoresUsed`, `totalRAMUsed`, `maxTotal*`, `maxServerGroups`, `maxServerGroupMembers`) from `GET /limits` or `GET /os-quota-sets/{pid}/detail`; Cinder `limits` and quota usage (`volumes`, `gigabytes`); Neutron quota **only with manager role** (`get_quota`); Neutron counts can be derived by listing ports and FIPs and comparing to defaults (AS: defaults unknown).
- Not possible: free host capacity. `os-hypervisors*` (7 rules) and Placement providers/candidates are admin or service only (`hypervisors.py`, `placement/policies/resource_provider.py`, `allocation_candidate.py`). Quota says "you are allowed", never "the scheduler will find a host". A green create can still fail with `NoValidHost` (server goes to `ERROR` with a fault; mv 2.x shows `fault.message`). Plan that as a normal failure with cleanup.
- Quota enforcement happens in the API at create (synchronous 403 `OverQuota`, DU/AS; not traced). Defaults seen: instances 10, cores 20, ram 51200 MB, metadata_items 128, server_groups 10 (`conf/quota.py`); Cinder volumes 10, gigabytes 1000 (`cinder/quota.py`). Nova usage counting is from cell DBs unless `[quota] count_usage_from_placement` (default False).

---

## 8. Keystone: application credentials, roles, minimal role sets

### Application credentials with access rules (SV: `keystone/application_credential/schema.py`, `keystone/api/auth.py`, `keystone/token/provider.py`; `keystonemiddleware/auth_token/__init__.py`)
- An access rule is `{service, method, path}`: `service` is a **catalog service type** (for example `compute`, `network`, `identity`, not a code name), `method` is one of `DELETE, GET, HEAD, PATCH, POST, PUT`, `path` matches `^/\.*`, max 225 characters. Yes, it can restrict to specific API paths and methods.
- Matching (`auth_token/__init__.py::_path_matches`): `{tag}` and `*` match one path segment, `**` matches anything, otherwise literal. The comparison is on `request.path` as the service sees it, so it includes the version prefix and, for APIs that carry it, the project id (for example Cinder `/v3/<project>/...`). The query string is not part of it. So rules like `GET /v2.1/servers/detail` work and cannot restrict by query parameters. A path like `/v2.1/servers/*/os-volume_attachments/*` is allowed.
- Enforcement is **per service by keystonemiddleware** (`validate_allowed_request`): `[keystone_authtoken] service_type` must be set, else the token is rejected ("Cannot validate request with restricted access rules. Set service_type..."). It also needs the service type in the token catalog. Services that do not use keystonemiddleware (or an old one) cannot enforce; Keystone refuses to validate a token carrying access rules unless the validating middleware sends the `OpenStack-Identity-Access-Rules` header with a version >= `ACCESS_RULES_MIN_VERSION`; the result is a hard failure ("You must upgrade keystonemiddleware on all services") (`token/provider.py::_validate_token_access_rules`). So a restricted application credential works only where every API it touches is behind a new-enough middleware with `service_type` configured. Verify per cloud.
- Bypass: a request carrying a valid service token is accepted without matching rules (`validate_allowed_request`: `if request.service_token and request.service_token_valid: return`, referencing LP#2162748). Nova adds a service token to downstream calls only with `[service_user] send_service_user_token = True` (default **False**, `nova/conf/service_token.py`). When false, Nova's own calls to Cinder, Neutron and Glance are made with the user token and are checked against the access rules of the downstream service: rules must also allow `POST /v3/<project>/attachments` (block-storage), `GET/PUT /v2.0/ports...` (network) etc. This makes a tight rule list fragile. AS for what a given Nova actually calls; a lab run is required.
- Restricted vs unrestricted: an app credential cannot create or delete other application credentials, trusts, etc. unless `unrestricted=true` (`api/users.py::_check_unrestricted_application_credential`, `api/trusts.py::_check_unrestricted`). Roles on the credential must be a subset of the user's own roles on that project (`application_credential/core.py::_require_user_has_role_in_project`) and a credential is bound to one project. Per-user limit `[application_credential] user_limit`. Lifetime: optional `expires_at`.
- Operational: one credential per OVLM role and per project: `ovlm-inventory` (role `reader`, GET-only access rules) and `ovlm-renewal` (role `member`, method/path rules for the renewal calls). That matches FR-REN-6 (write credential used only by authorized renewal steps).

### Roles in default policies (SV)
- `reader < member < manager < admin` (bootstrap implication). Project-scoped rules check `role:X and project_id:%(project_id)s`, so the credential's project is the boundary.
- `reader` read-only works for Nova, Cinder, Neutron and Glance as shown in section 1; **two exceptions for a pure reader inventory: Neutron quota (manager) and every admin-only server attribute** (host names).
- With `enforce_new_defaults=False` the legacy rule is OR-ed; with it True, a user with only `member` still reads (implied reader).

### Minimal role sets
(a) Read-only inventory: `reader` on each project. Optionally add `manager` only if Neutron quota pre-check is needed (then the credential is not read-only; keep that separate from the inventory credential and use access rules to restrict it to `GET /v2.0/quotas/*`). Everything in section 1 except Neutron quota and admin attributes works with `reader`.
(b) Renewal within ONE project: `member` covers: Nova create, delete, stop, start, lock, unlock (own lock), tags/metadata, volume attach/detach, server group create; Cinder attachment create/update/delete/complete, volume get/update/delete, snapshot create, `begin_detaching`/`reserve` actions; Neutron port create/update (on networks the project owns), FIP update, SG read; Glance reads of visible images.

### Operations a `member` cannot do by default (SV)
- Neutron quota read (`manager`); create a FIP with a chosen address (`manager`); Nova migrate and live-migrate (`manager`).
- Unlock a server locked by an admin (`unlock:unlock_override`); show host, hypervisor, instance name; list all tenants; hypervisor or Placement capacity data.
- Cinder `os-force_detach`, `os-reset_status`, `os-force_delete`, volume host attribute, migration, create or edit volume types and extra specs (`RULE_ADMIN_API` in `volume_actions.py`, `volume_type.py`); creating a multiattach type.
- Neutron: `create_port` with `fixed_ips`/MAC on a **shared** network owned by another project (MAC refused; `fixed_ips` allowed via `rule:shared`); `allowed_address_pairs` on such a network; attach to external networks via Nova.
- Delete a Neutron port whose `device_owner` is `compute:*` (`delete_port` excludes compute, baremetal, manila devices for members).
- Server `reset_state`, evacuate, shelve offload; read instance-action events.

---

## 9. Operational limits of "replace the VM" (blue/green)

| Topic | Finding | Evidence | Tag |
|---|---|---|---|
| Keep the fixed IP | Possible by **pre-creating a Neutron port** with the fixed IP (and optionally MAC) and booting with `networks: [{port: <id>}]`. Creating a port with a chosen IP/MAC needs net-owner `member` (IP also via `rule:shared`; MAC only net owner). | Nova `network/neutron.py` around lines 736-775, `create_port:fixed_ips`, `create_port:mac_address` | SOURCE-VERIFIED |
| Port in use elsewhere | Nova refuses to boot with a port whose `device_id` is set: `PortInUse` (`network/neutron.py` lines 763-764, 2561-2562). Requesting a fixed IP that already exists on the network gives `FixedIpAlreadyInUse` (line ~2605, also an explicit comment about a race between concurrent boots). **Blue and green cannot both hold the same fixed IP at once**; fixed-IP preservation means a short outage, or keeping the FIP/alias as the stable address. | same | SOURCE-VERIFIED |
| Reuse a port after the old VM | A pre-existing port passed at boot is not deleted when the server is deleted; Nova only resets `binding:host_id` (and, on detach, `device_id` and `device_owner`) (`deallocate_for_instance`: `ports_to_skip |= _get_preexisting_port_ids`; `_unbind_ports`). Ports Nova created itself are deleted with the server. A port can also be moved with interface detach (`DELETE /servers/{id}/os-interface/{port}`, member) then interface attach on the new server (member; `attach_interfaces` create/delete). | `network/neutron.py` 1840-1862, 611-650; `attach_interfaces.py` | SOURCE-VERIFIED |
| MAC address | A new server gets a new port with a new MAC unless the port is pre-created with the MAC. Guests that pin MAC in udev/netplan, DHCP reservations, licence servers or MAC-based ACLs will break. Setting an own MAC is net-owner member only on create; `update_port:mac_address` needs `manager`. | `conf/policies/port.py` | SOURCE-VERIFIED |
| Quota during blue/green | Two servers coexist: `instances +1`, `cores +flavor`, `ram +flavor` against Nova limits; ports +1 (+1 floating IP only if a second FIP is used; the FIP move needs none); volume quota unaffected (the data volume is moved); root volume +1 for boot-from-volume; server group members +1 per group. Pre-check with `GET /limits` and quota detail (section 7). Cinder snapshot/backup taken as safety net also counts (`snapshots`, `gigabytes`). | `conf/quota.py` | SOURCE-VERIFIED (defaults); AS (what the cloud has) |
| cloud-init | A new server gets a new instance id (the server UUID; the EC2-style id differs), so cloud-init runs per-instance modules and user-data again on first boot (ssh host keys regenerated, hostnames, users). The data volume must not be reformatted by user data (use a `fs_setup` with `overwrite: false`, or avoid it). Idempotent mounting by label is required. LAB-OBSERVED (EXP-01, Felcloud, 2026-11-04): on Ubuntu 24.04 cloud-init printed the host key fingerprints and the full host key block to the console log, and a non-admin credential could read it (the block appeared about 190 s after create); the fingerprint matched the first SSH contact. | not in these wheels | ASSUMPTION; console-log host keys LAB-OBSERVED |
| Hostname | A new server can be given the same `hostname` from mv 2.90 (`hostname` parameter; filter at 2.90) but the DNS record (Neutron DNS integration or Designate) must be updated or the old one deleted first. | `rest_api_version_history.rst` 2.90 | DOCUMENTED-UNVERIFIED |
| Server name | Not unique (SV, section 3). Two servers named identically can coexist, which is convenient for blue/green but makes name-based lookup ambiguous. Prefer ids and tags. | | SOURCE-VERIFIED |
| Metadata/tags/security groups/key pair | Must be re-applied to green (not inherited). SG membership is per port. The key pair name only resolves at create (the key pair must still exist). | `schemas/servers.py` | SOURCE-VERIFIED (schema) |
| Old VM retention (FR-REN-7: stopped and locked) | A locked old VM can only be unlocked by the member who locked it (`locked_by='owner'`); an admin lock would block revert. Stopped is enough for volume handoff safety, and **lock must be applied after** the volume has been handed off, and unlocked first for a revert (attach/detach are blocked on locked servers for non-admin). | section 4, 7 | SOURCE-VERIFIED |
| Down compute host | Detach needs the compute host up (`check_instance_host(check_is_up=True)`); when the host of blue is down the volume cannot be released by a member. Evacuate/force-detach are admin operations. | `compute/api.py::_detach_volume` | SOURCE-VERIFIED |

---

## Recommendations for the architect (max 15)

1. Treat "floating IP move" as an asynchronous, router-dependent operation: one PUT, atomic in the DB, applied by the L3 agent afterwards. Add a preflight (router interface on green subnet + gateway on the FIP's external net), a post-check (FIP status and an external probe), and map the misleading 404 `ExternalGatewayForFloatingIPNotFound` text.
2. Make idempotency OVLM's job: pre-persist name and run id, create with tags `ovlm:managed` and `ovlm:run:<id>`, and on resume find the server by tag plus anchored name. Never look up by metadata (silently ignored for non-admins, returns everything).
3. Handoff order: stop blue, detach, wait `available`, attach to green, wait `in-use`, start green, verify, cut over. Hot-detach of a mounted volume can be refused by the guest after about 160 s. Make "stop first" the default and "hot detach" an opt-in per profile.
4. Preflight blockers for a data volume, observable facts only: attachment `delete_on_termination=false` (read at mv >= 2.79, fix with PUT at mv >= 2.85), not multiattach, same AZ as green (when `cross_az_attach=false`), volume `in-use` by blue only, blue `ACTIVE` with no `task_state`, blue `locked == false` (mv >= 2.73). Whether a lock is an admin lock and whether blue's compute host is up are not observable to a `member` (`host_status` is admin-only); both show only when the stop or detach call fails, which OVLM treats as needs-human with no retry (SEC-R-6; renewal-workflow.md §1, W3).
5. Never set a lock before the handoff and revert paths are complete. Lock blocks every state-changing server call for non-admins, including attach and delete. Keep the "stopped and locked" retention (FR-REN-7), but unlock explicitly in the revert step. Record who locked.
6. Poll with deadlines and handle rollback states: detach failure rolls the volume back to `in-use` (not an error status); stuck `reserved`/`attaching`/`detaching` need an operator (force-detach and reset-status are admin only). OVLM should detect, stop and report, not try to fix.
7. Design for two credentials: `reader` for inventory (plus optional separate `manager` credential only for Neutron quota reads) and `member` for renewal. Do not assume reader suffices for capacity pre-check: Neutron quota needs manager, and free host capacity is admin only. FR-PLN-2 should be "quota-based, advisory", with `NoValidHost` handled as a normal failure.
8. Tell cloud admins that access rules require `service_type` in every service's `[keystone_authtoken]`, a current keystonemiddleware, and (usually) `[service_user] send_service_user_token=True` in Nova. Without it, restricted credentials either fail closed or need downstream paths listed. Plan access rules as defense in depth, tested in a lab, not as the primary control.
9. Inventory: full listing per cycle for everything except servers; use Nova `changes-since` (returns deleted servers) for cheap deltas, but keep a periodic full sync. Mark `gone` only after N full syncs without the resource. Normalize embedded flavor (no id from mv 2.47), nullable `launched_at`, and "minimal construct" servers (mv 2.69).
10. Use the SDK for everything but accept its limits: no `return_reservation_id`, attachment resource capped at mv 2.89 (async 200 with maybe empty device), server at 2.100 while Nova goes to 2.104. Pin the microversions you rely on in OVLM (2.26/2.52 tags, 2.47 flavor, 2.73 lock reason, 2.79 `delete_on_termination`).
11. Record `/dev/disk/by-id/virtio-<volume id prefix>` as a hint only (20-character prefix, LAB-OBSERVED (EXP-01, Felcloud, 2026-11-04)). Put a filesystem label or UUID on the data volume at first use and require the profile's automation to mount by label/UUID with `nofail`. Never persist `/dev/vdX`.
12. Default to exclusive attachment. Offer multiattach only as an explicit opt-in for cluster-aware data, never as the way to shorten the handoff.
13. For fixed-IP preservation, pre-create the port and boot green with `port=<id>` only after blue released it (short outage), or keep the FIP as the stable identity and let green have a new fixed IP. Default: new fixed IP, FIP moved, DNS (Designate) updated if used.
14. Use tags/metadata as markers only; store the truth in OVLM's database. Members can edit them. Tag Neutron ports and Cinder volumes as well, so orphans of a failed renewal can be found and reported.
15. Put the lab test list below into the test environment plan (`docs/test-environment.md`) before the MVP engine is built.

## Open questions needing a real cloud

1. Is `enforce_new_defaults` on? Does a user with only `reader` pass every call in section 1, and is Neutron quota really manager-only on that release/override?
2. Real Nova/Cinder/Neutron versions and microversion maxima: is 2.101+ (202 on attach) active? What does the SDK do in a mixed state?
3. Data plane behaviour of a FIP re-association: observed downtime, FIP `status` transitions, effect on existing TCP sessions, behaviour with DVR/OVN and with an HA router.
4. Detach timing and refusal behaviour with a mounted ext4/xfs volume on a running guest, on the real backend (Ceph RBD, iSCSI, NFS). Real `device_detach_timeout/attempts` values.
5. Which volume statuses and attachment statuses appear after a forced failure (kill compute during detach, backend error on attach)? Whether any clouds set volume `status=error_detaching` (older releases).
6. Does `tags=` listing return a just-created server in `BUILD` state, and does a retry after a lost response behave as designed?
7. Do access rules work end to end: `service_type` configured in each service, which downstream paths Nova needs without a service token, token validation failures, behaviour behind a proxy that rewrites paths (project id segments).
8. Server group behaviour: can anti-affinity vs. an existing ungrouped blue VM be expressed (different_host filter enabled?), and what happens at `server_group_members` limit?
9. Quota accounting details: failed builds in `ERROR`, `count_usage_from_placement`, and the exact error body for over-quota at create.
10. cloud-init behaviour on the real images (instance id, `fs_setup`, SSH host keys), and MAC-sensitive guest configs.
11. Locks: confirm that an admin-set lock blocks the project credential and gives 409; confirm `locked_by` semantics for service accounts.
12. Octavia and Designate: whether the services exist in the target clouds; propagation time and provisioning-state handling.
13. Whether non-admin `GET /servers/detail` returns `launched_at` for all states and what Nova shows for servers in a down cell.
