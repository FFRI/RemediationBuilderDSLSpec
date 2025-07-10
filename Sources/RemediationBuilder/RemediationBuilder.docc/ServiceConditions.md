# Service Conditions

Learn about the conditions available for evaluating launchd services.

## Overview

Service conditions are used to evaluate properties of launchd services. They conform to the `ServiceCondition` protocol and can be used within the DSL block passed to `Service`'s initializer.

## Available Conditions

The following service conditions are available for evaluating launchd services:

- ``ArgumentCount`` - Matches the number of command-line arguments received by a launchd service
- ``Arguments`` - Matches positional arguments passed to a launchd service by index
- ``KeyValue`` - Matches the value of one or more keys in the service's property list or configuration
- ``ExecutableYara`` - Evaluates the service's executable binary against a YARA rule
- ``ExecutablePath`` - Applies a pattern match to the absolute path of the service's executable
- ``ExecutableIsUntrusted`` - Evaluates whether the service's executable is signed with an untrusted certificate
- ``ExecutableRevoked`` - Evaluates whether the Notarization ticket for the executable has been revoked
- ``ServiceExecutable`` - Applies a list of file conditions to the executable referenced by a launchd service

## Example

```swift
// XProtectRemediatorKeySteal v145
KeyStealRemediator {
    Service(tag: nil) { // ServiceRemediationBuilder DSL block
        // Service Conditions go here
        ExecutablePath(.PatternGroup([".*/Library/.*"]))
        ExecutableYara(YaraMatcher(keyStealYara))
    }
    ...(snip)...
}
```

## Related Topics

- <doc:ProcessConditions>
- <doc:FileConditions>
- <doc:SafariAppExtensionConditions>