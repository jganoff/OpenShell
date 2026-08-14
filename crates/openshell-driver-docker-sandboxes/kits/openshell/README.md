# OpenShell agent kit

A standard Docker Sandboxes (`sbx`) **`kind: sandbox`** agent kit. The
`docker-sandboxes` compute driver ships it inline on every `create`
(`kit_artifacts`), so the `sandboxd` daemon needs no pre-installed `openshell`
agent — an OpenShell gateway configured with the `docker-sandboxes` driver
"just works" against a stock `sbx`.

## Files

| File | Role |
|------|------|
| `spec.yaml` | Human-editable source. Standard kit spec — works with `sbx kit validate`/`inspect`/`pack`. **Edit this.** |
| `artifact.json` | Generated canonical wire form, produced by `sbx kit inspect --json` (see below). The driver embeds and ships this verbatim. **Do not hand-edit.** |

`artifact.json` is not the same as `spec.yaml` transcoded to JSON — `sbx`
normalizes the spec (e.g. `sandbox.image` → `manifest.template`) into its own
canonical form, and `sandboxd` decodes each `kit_artifacts` entry with no
separate normalization pass of its own (confirmed empirically: a hand-edited
`spec.yaml`-shaped entry doesn't resolve the way an `sbx`-produced one does),
so the driver must ship the form `sbx` itself already produces.

## Regenerating `artifact.json`

After editing `spec.yaml`, regenerate using only the `sbx` CLI — this
repository has no dependency on `github.com/docker/sandboxes` and must not
gain one, so `artifact.json` is never generated from that private source:

```shell
# 1. Validate the edited spec first.
sbx kit validate kits/openshell

# 2. Regenerate the canonical wire form from it.
sbx kit inspect --json kits/openshell > kits/openshell/artifact.json
```

`sbx kit inspect`/`validate` only read a directory, ZIP, OCI reference, or
git repository — not a bare JSON file — so there's no separate CLI command
to re-validate `artifact.json` on its own once written; regenerating it from
an already-validated `spec.yaml` is the check.
