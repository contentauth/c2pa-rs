# C2PA SDK: `instanceID` Behavior

The C2PA claim's `instanceID` field is intended to bind the claim to a specific incarnation of an asset. When the asset contains XMP, `xmpMM:InstanceID` is the canonical source of this value and must agree with the claim.

The correct behavior depends on two factors: whether the source asset already has an InstanceID, and whether the SDK is responsible for writing the output asset.

---

## SDK owns the write (embed)

The SDK is modifying the file, so it owns the output incarnation identity.

The caller can configure behavior via `InstanceIDBehavior`:

| Source has InstanceID | `Preserve` | `Bump` (default) |
|---|---|---|
| Yes | Use source InstanceID in claim; write it to output XMP | Generate new UUID; write to output XMP; use in claim |
| No | Generate new UUID; write to output XMP; use in claim | Generate new UUID; write to output XMP; use in claim |

When the source has no InstanceID, `Preserve` and `Bump` are identical — a new UUID must be generated, and since the SDK is writing the file it writes the UUID to XMP.

**`Bump` is the default.** It is the only behavior that is unambiguously correct about what the SDK is doing to the file. Use `Preserve` when the caller has already finalized the asset's InstanceID (e.g., streamed an asset to the SDK that already has the intended InstanceID set) and wants that value preserved in both the claim and the output.

---

## Caller owns the write (SDK receives a finished asset)

The asset is already finalized before the SDK is invoked. The SDK reads but does not write.

| Source has InstanceID | Behavior |
|---|---|
| Yes | Use source InstanceID in claim. No XMP written. |
| No | Generate UUID for claim only. Cannot write to asset. Binding is weak. |

No mode knob applies here. The caller is responsible for ensuring the asset's InstanceID is correct before invoking the SDK.

---

## Sidecar

The SDK does not modify the asset.

| Source has InstanceID | Behavior |
|---|---|
| Yes | Use source InstanceID in claim. Asset untouched. |
| No | Generate UUID for claim only. Asset untouched. Binding is weak. |

---

## Weak binding

In cases where the source has no InstanceID and the SDK cannot write to the asset (caller-owns-write or sidecar), the claim will contain a generated UUID that nothing in the asset corroborates. The binding between claim and asset exists only by convention. Callers should be aware of this limitation and ideally ensure the asset has an InstanceID before signing.
