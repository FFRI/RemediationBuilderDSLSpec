# Process Conditions

Learn about the conditions available for evaluating running processes.

## Overview

Process conditions are used to evaluate properties of running processes. They conform to the `ProcessCondition` protocol and can be used within the DSL block passed to `Process`'s initializer.

## Available Conditions

The following process conditions are available for evaluating running processes:

- ``ProcessName`` - Matches the process name of a running process
- ``ProcessCDHash`` - Matches the CDHash of the process's executable
- ``ProcessIsNotarised`` - Evaluates whether the process binary is notarized
- ``ProcessIsAppleSigned`` - Evaluates whether the process binary is signed by Apple
- ``ProcessMainExecutable`` - Applies file conditions to the process's main executable
- ``ProcessHasBackingFile`` - Checks if the process has an on-disk backing file
- ``HasLoadedLibrary`` - Matches loaded shared libraries in the process address space

## Example

```swift
// XProtectRemediatorRedPine v141
RedPineScanner {
    Process { // ProcessRemediationBuilder DSL block
        // Process Conditions go here
        ProcessIsAppleSigned(false)
        HasLoadedLibrary("/System/Library/PrivateFrameworks/FMCore.framework")
        HasLoadedLibrary("/System/Library/Frameworks/CoreLocation.framework/CoreLocation")
        HasLoadedLibrary("/System/Library/Frameworks/AVFoundation.framework/AVFoundation")
        HasLoadedLibrary("/usr/lib/libsqlite3.dylib")
    }.reportOnly()
}
```

## Related Topics

- <doc:ServiceConditions>
- <doc:FileConditions>
- <doc:SafariAppExtensionConditions>
