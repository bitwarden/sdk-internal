# SDK Android Impact Report

## Summary

- **SDK PR**: #{PR_NUMBER} (or local changes on branch `{BRANCH_NAME}`)
- **Base branch**: {BASE_BRANCH}
- **Analysis date**: {DATE}
- **Breaking compilation changes**: {N_COMPILE}
- **Breaking behavioral changes**: {N_BEHAVIORAL}
- **Additive changes**: {N_ADDITIVE}
- **Requires attention**: {N_ATTENTION}

## Breaking Compilation Changes

> These changes will cause the Android project to fail compilation. Each must be addressed before
> the SDK update can be integrated.

### {N}. {Change Title}

- **Package**: com.bitwarden.{package}
- **Type**: {data class field removed | method signature changed | type removed | sealed variant
  removed | enum variant removed}
- **Before**:
  ```kotlin
  {previous signature or declaration}
  ```
- **After**:
  ```kotlin
  {new signature or declaration}
  ```
- **Android impact**:
  - `{SdkSourceImpl}.kt:{line}` — {description of how this call site is affected}
  - `{Repository/Manager}.kt:{line}` — {upstream consumer impact}
- **Compilation errors** (if available):
  ```
  e: {File}:{line}:{col} {error message}
  ```
- **Suggested fix**: {Brief description of what the Android code needs to do}

## Breaking Behavioral Changes

> These changes compile successfully but alter runtime behavior. They can cause subtle bugs if not
> addressed.

### {N}. {Change Title}

- **Package**: com.bitwarden.{package}
- **Type**: {nullability change | default value change | type narrowing | semantic change}
- **Before**:
  ```kotlin
  {previous declaration}
  ```
- **After**:
  ```kotlin
  {new declaration}
  ```
- **Semantic impact**: {Detailed description of what changed behaviorally — e.g., "Null now
  impossible; empty list replaces null. Code checking `== null` will never trigger."}
- **Android impact**:
  - `{SdkSourceImpl}.kt:{line}` — {how this code path is affected}
- **Risk level**: {HIGH | MEDIUM | LOW}
- **Suggested fix**: {What the Android code should change}

## Additive Changes

> New API surface that does not break existing code. No action required unless the Android app wants
> to adopt the new functionality.

| Package             | Type                                                     | Name   | Description         |
| ------------------- | -------------------------------------------------------- | ------ | ------------------- |
| com.bitwarden.{pkg} | {data class \| method \| enum variant \| sealed variant} | {Name} | {Brief description} |

## Requires Attention

> Changes that don't fit neatly into the above categories but warrant review.

### {N}. {Change Title}

- **Package**: com.bitwarden.{package}
- **Details**: {Description of the change}
- **Why attention needed**: {Why this doesn't fit into other categories — e.g., "New required
  callback interface that must be implemented by the app"}

## Android Files Affected

> Summary of all Android files that reference changed API elements.

| File                | Type                                              | Changed APIs Used      | Action Needed |
| ------------------- | ------------------------------------------------- | ---------------------- | ------------- |
| `{path/to/File}.kt` | {SdkSource \| Repository \| Manager \| ViewModel} | {List of changed APIs} | {Yes/No}      |

## Migration Checklist

- [ ] Address all breaking compilation changes ({N_COMPILE} items)
- [ ] Review all breaking behavioral changes ({N_BEHAVIORAL} items)
- [ ] Update unit tests for changed behavior
- [ ] Run `./gradlew app:compileStandardDebugKotlin` to verify compilation
- [ ] Run full test suite
- [ ] Update any affected UI/integration tests

## PR Description Snippet

> Copy this into the SDK PR description to inform reviewers about Android impact.

```markdown
### Android Impact

This PR introduces **{N_COMPILE} breaking compilation** and **{N_BEHAVIORAL} breaking behavioral**
changes to the Android SDK surface.

**Key changes:**

- {Brief list of most important changes}

**Android migration required:** {Yes/No}

<details>
<summary>Full impact details</summary>

{Summary table of all changes}

</details>
```
