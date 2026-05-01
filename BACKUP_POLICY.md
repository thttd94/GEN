# Backup / Rollback Policy

## Baseline

- Version `1.1` is the clean installed baseline requested by the user.
- Every future release must preserve rollback artifacts instead of deleting older backups.

## Git-side backups

- Version snapshots are stored inside GEN under `gen_backup/versions/<version>/`.
- `gen_backup/versions/1.1/` is the immutable baseline snapshot.
- Future versions may add `gen_backup/versions/<version>/` without removing previous snapshots.

## Router-side backups

- Router backups live under `/root/genrouter_backups/versions/<version>/`.
- During install/update, the installer copies the current package into `/root/genrouter_backups/versions/<version>/package` when missing.
- Rollback should restore from the requested version package without deleting other backup versions.

## Rollback guarantee

When the user asks to return to version `1.1`, restore the package snapshot at:

- Git / inside GEN: `gen_backup/versions/1.1/package/`
- Router: `/root/genrouter_backups/versions/1.1/package/`

The restore should replace app/runtime files needed by the GUI while preserving the backup directory itself.
