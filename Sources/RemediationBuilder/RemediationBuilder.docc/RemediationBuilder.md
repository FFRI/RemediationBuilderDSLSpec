# ``RemediationBuilder``

A Domain Specific Language for declaratively describing malware remediation (or detection) conditions and logic.

## Overview

RemediationBuilder provides a set of Domain Specific Languages that enable the declarative description of malware remediation (or detection) conditions and logic. This framework is specifically designed for use within XProtect Remediator.

NOTE: **This framework is not intended to be used directly by developers. This documentation is provided to detail the reverse-engineered RemediationBuilder DSL. Some of the interfaces are inferred from my reverse engineering findings. Some of the specifications may not reflect the actual implementation.**

The framework consists of the following key components:

- **Conditions**: Evaluators that determine if a remediation (or detection) should be applied.
- **Remediations**: Actions to be taken when conditions are met.
- **Builders**: Result-builder types that enable the declarative composition of conditions and remediations.

## Topics

- <doc:BasicConcepts>
- <doc:ServiceConditions>
- <doc:ProcessConditions>
- <doc:FileConditions>
- <doc:SafariAppExtensionConditions>
