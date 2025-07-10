# Safari App Extension Conditions

Learn about the conditions available for evaluating Safari App Extensions.

## Overview

Safari App Extension conditions are used to evaluate properties of Safari App Extensions. They conform to the `SafariAppExtensionCondition` protocol and can be used within the DSL block passed to `SafariAppExtension`'s initializer.

## Available Conditions

The following Safari App Extension conditions are available for evaluating Safari App Extensions:

- ``ExtensionBinaryYara`` - Evaluates the compiled binary of a Safari App Extension against a YARA rule
- ``JavaScriptYara`` - Evaluates the JavaScript payload of a Safari App Extension against a YARA rule

## Example

```swift
// XProtectRemediatorSheepSwap v145
SheepSwapRemediator {
    SafariAppExtension { // SafariAppExtensionRemediationBuilder DSL block
        // Safari App Extension Conditions go here
        ExtensionBinaryYara(YaraMatcher(sheepSwapYara1))
    }
    ...(snip)...
}
```

## Related Topics

- <doc:ServiceConditions>
- <doc:ProcessConditions>
- <doc:FileConditions>
