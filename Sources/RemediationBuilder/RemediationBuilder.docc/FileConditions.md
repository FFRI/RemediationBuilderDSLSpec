# File Conditions

Learn about the conditions available for evaluating files.

## Overview

File conditions are used to evaluate properties of files. They conform to the `FileCondition` protocol and can be used within the DSL block passed to `File`'s initializer, as well as within the DSL block passed to `ServiceExecutable` and `ProcessMainExecutable` initializers.

## Available Conditions

The following file conditions are available for evaluating files:

- ``FileYara`` - Evaluates a file against a YARA rule
- ``FilePath`` - Applies a pattern match to the absolute path of the file
- ``FileMime`` - Matches the MIME type of the file
- ``FileMagic`` - Matches the file signature
- ``FileMacho`` - Evaluates whether the file is a valid Mach-O executable
- ``FileNotarised`` - Evaluates whether the file is notarized
- ``FileSingleByteXor`` - Evaluates an XOR-decoded view of the file against nested conditions
- ``MaxFileSize`` - Matches files whose size is less than or equal to the given bytes
- ``MinFileSize`` - Matches files whose size is greater than or equal to the given bytes
- ``FileSHA256`` - Matches the SHA-256 digest of the file's contents
- ``FileCDHash`` - Matches the CDHash of the executable

## Example

```swift
// XProtectRemediatorEicar v145
EicarRemediator {
    File(path: "/tmp/eicar") { // FileRemediationBuilder DSL block
        // File Conditions go here
        MinFileSize(68)
        FileYara(YaraMatcher(eicarYara))
    }
}

// XProtectRemediatorAdload v145
AdloadRemediator {
    for pathPattern in pathPatterns {
        Process {
            ProcessIsNotarised(false)
            ProcessMainExecutable { // FileRemediationBuilder DSL block
                // File Conditions go here
                FilePath(.StringContains(pathPattern))
                FileYara(YaraMatcher(adloadYara))
            }
        }
    }
    ...(snip)...
}
```

## Related Topics

- <doc:ServiceConditions>
- <doc:ProcessConditions>
- <doc:SafariAppExtensionConditions>
