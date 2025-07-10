# Basic Concepts

Understand the fundamental architecture and concepts of RemediationBuilder.

## Overview

RemediationBuilder is built around the following core components: Conditions, Remediations, and Builders. Understanding these components is essential for understanding the RemediationBuilder DSL.

## Conditions

Conditions are evaluators that check specific properties of system entities. They implement the `Condition` protocol and are used to determine whether a remediation (or detection) should be triggered.

### Condition Types

- <doc:ServiceConditions>: Evaluates launchd services
- <doc:ProcessConditions>: Evaluates running processes  
- <doc:FileConditions>: Evaluates files
- <doc:SafariAppExtensionConditions>: Evaluates Safari App Extensions

## Remediations

Remediations represent the actions to be taken when conditions are met. They conform to the `Remediation` protocol and can target different types of system entities.

### Remediation Types

- ``ServiceRemediation``: Targets launchd services
- ``ProcessRemediation``: Targets running processes
- ``FileRemediation``: Targets files
- ``SafariAppExtensionRemediation``: Targets Safari App Extensions
- ``ProxyRemediation``: Manages proxy settings

## Builders

Builders provide the DSL syntax that makes it easy to compose conditions and remediations. They use Swift's result builder feature to enable the declarative composition of conditions and remediations.

### Builder Types

- ``ServiceRemediationBuilder``: For service remediations
- ``ProcessRemediationBuilder``: For process remediations
- ``FileRemediationBuilder``: For file remediations
- ``SafariAppExtensionRemediationBuilder``: For Safari extension remediations
- ``RemediationArrayBuilder``: For building arrays of remediations

## How RemediationBuilder DSL works

The following example uses `WaterNetRemediator` to illustrate how RemediationBuilder DSL works. For simplicity, this explanation uses a simplified version of the `WaterNetRemediator`.

```swift
// XProtectRemediatorWaterNet v145

struct WaterNetRemediator {
    var statusReports: XPPluginStatusCollator
    var remediations: Remediations
}

let remediator = WaterNetRemediator {
    // (2)
    File(searchDir: "~/Library/Application Support", regexp: "/(([a-zA-Z0-9]{19,40})|([a-zA-Z0-9]{39}/[a-zA-Z0-9]{39}))/(helper|main|m|h)$", searchDepth: 3) {
        // (1)
        FileYara(constraint: YaraMatcher(waterNetYara))
        MaxFileSize(constraint: 20971520)
    }
    ...(snip)...
}
```

### Step 1: [FileConditionConvertible] → [AnyFileCondition] at (1)

At point (1), the DSL block passed to the initializer of ``File`` is evaluated. This block is defined according to the ``FileRemediationBuilder`` specification. Objects within this block are converted to ``AnyFileCondition`` using the methods defined in the Protocol Witness Table (PWT) of ``FileConditionConvertible``. The resulting value of the DSL block is `[AnyFileCondition]`, which is assigned to the `conditions` property of ``File``.

``AnyFileCondition`` includes an `_assess` function, which later is used to determine whether the specified condition is met.

### Step 2: [RemediationConvertible] → [Remediation] at (2)

At point (2), the DSL block passed to the initializer of `WaterNetRemediator` is evaluated. This block is defined according to the ``RemediationArrayBuilder`` specification. Objects within this block are converted to ``FileRemediation`` using the methods defined in the protocol’s Protocol Witness Table (PWT). ``FileRemediation`` conforms to the ``Remediation`` protocol, and the final result of the DSL block is stored as an existential container of type `[any Remediation]`. This value is then assigned to the `remediations` property of `WaterNetRemediator`.

During the conversion from ``File`` to ``FileRemediation``, the system searches for file paths to be removed as needed. In this example, files are searched under the directory specified by `searchDir` of ``File``. For instance, if the following three files exist in the system:

```
/Users/user/Library/Application Support/wfpvtrubs4gpq4jmwkftbndkc0/main
/Users/user/Library/Application Support/aaaa/wfpvtrubs4gpq4jmwkftbndkc0/helper
/Users/user/Library/Application Support/aaaa/bbbbbb/wfpvtrubs4gpq4jmwkftbndkc0/h
```

then three corresponding ``FileRemediation`` instances are generated. Each generated ``FileRemediation`` represents a file to be removed.

```swift
[
    FileRemediation(
        filepath: "/Users/user/Library/Application Support/wfpvtrubs4gpq4jmwkftbndkc0/main",
        conditions: [
            AnyFileCondition(...), // AnyFileCondition for FileYara
            AnyFileCondition(...)  // AnyFileCondition for MaxFileSize
        ],
        followUpRemediations: [],
        reportOnly: false,
        tag: nil
    ),
    FileRemediation(
        filepath: "/Users/user/Library/Application Support/aaaa/wfpvtrubs4gpq4jmwkftbndkc0/helper",
        conditions: [
            AnyFileCondition(...), // AnyFileCondition for FileYara
            AnyFileCondition(...)  // AnyFileCondition for MaxFileSize
        ],
        followUpRemediations: [],
        reportOnly: false,
        tag: nil
    ),
    FileRemediation(
        filepath: "/Users/user/Library/Application Support/aaaa/bbbbbb/wfpvtrubs4gpq4jmwkftbndkc0/h",
        conditions: [
            AnyFileCondition(...), // AnyFileCondition for FileYara
            AnyFileCondition(...)  // AnyFileCondition for MaxFileSize
        ],
        followUpRemediations: [],
        reportOnly: false,
        tag: nil
    )
]
```

### Step 3: Performing Remediation

The `remediations` property of the WaterNetRemediator is retrieved and processed. For each ``FileRemediation``, the system checks whether the file path specified in `filepath` satisfies the associated conditions. During this evaluation, the `_assess` function of each ``AnyFileCondition`` is invoked. If all conditions evaluate to true and reportOnly is false, the file is deleted. Finally, the status of the deletion is logged via `OSLog` through statusReports of WaterNetRemediator.
