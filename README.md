# RemediationBuilder DSL Specification

A reverse-engineered RemediationBuilder DSL specification presented at [Black Hat USA 2025](https://blackhat.com/us-25/briefings/schedule/#xunprotect-reverse-engineering-macos-xprotect-remediator-44791).

## Overview

This project provides a RemediationBuilder DSL specification discovered through reverse engineering of XProtect Remediator (XPR). RemediationBuilder is used internally by XPR to define malware detection rules and remediation actions in a declarative manner.

**⚠️ Important Disclaimer:**

This framework aims to document the specifications of the DSL identified through reverse engineering. Therefore, the implementations of classes and structs defined in [RemediationBuilder.swift](Sources/RemediationBuilder/RemediationBuilder.swift) and [XPPluginAPI.swift](Sources/RemediationBuilder/XPPluginAPI.swift) are not fully provided. Only the following information, identified through reverse engineering, is included in the source code:

- All properties of structs and classes
- Descriptions for most structs and classes
- Protocol conformance and associated types
- Some protocol requirements (only for ProcessCondition, FileCondition, ServiceCondition, and SafariAppExtensionCondition)
- Initializer implementations for the File, Process, SafariAppExtension, and Service structs

## What is RemediationBuilder?

RemediationBuilder is a Domain Specific Language that enables describing malware detection or remediation conditions and logic in a declarative manner.

- **Define Detection Conditions**: Specify criteria for identifying malicious files, processes, services, and Safari App Extensions
- **Compose Complex Rules**: Combine multiple conditions using Swift's result builder

## Documentation

Comprehensive API documentation is generated using Swift-DocC:

```bash
# Generate documentation
swift package --allow-writing-to-directory ./docs generate-documentation --output-path ./docs --transform-for-static-hosting --hosting-base-path RemediationBuilderDSLSpec --disable-indexing --target RemediationBuilder

# Preview documentation locally
swift package --disable-sandbox preview-documentation
```

The documentation includes:
- Detailed API reference for almost all condition and remediation types
- Architecture overview and core concepts

## Contributing

Contributions are welcome, particularly:

- Documentation improvements and code examples
- Research findings about unknown components
- Analysis of additional XPR components

## Author

Koh M. Nakagawa (@tsunek0h) © FFRI Security, Inc. 2025

## License

[Apache License 2.0](LICENSE)
