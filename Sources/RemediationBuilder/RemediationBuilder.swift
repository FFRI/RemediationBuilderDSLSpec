/// # RemediationBuilder
/// A Domain Specific Language for declaratively describing malware remediation (or detection) conditions and logic.
///
/// This file reproduces the minimal public APIs that were discovered through reverse engineering.
/// All DocC comments exist solely so that Swift-DocC can generate a meaningful API reference.
import Foundation

// MARK: - Protocols

/// Base interface implemented by every condition.
///
/// This protocol serves as the foundation for all condition types in
/// RemediationBuilder, providing a common interface for evaluating
/// different types of system objects.
///
/// `Subject` is the target type that the condition evaluates.
public protocol Condition {
    associatedtype Subject
}

/// Condition for evaluating launchd services.
///
/// Structs conforming to this protocol are used within `Service` DSL blocks to
/// specify criteria for matching launchd services based on their configuration,
/// executable properties, arguments, or other service-specific attributes.
///
/// The associated `Constraint` type stores the value used by the evaluator
/// and is held in the `constraint` property.
public protocol ServiceCondition: ServiceConditionConvertible, Condition where Subject == XProtectLaunchdDaemonAgentProtocol {
    associatedtype Constraint
    var constraint: Constraint { get set }
}

/// Condition for evaluating running processes.
///
/// Structs conforming to this protocol are used within `Process` DSL blocks to
/// specify criteria for matching running processes based on their name, executable
/// properties, loaded libraries, or other process-specific attributes.
///
/// The associated `Constraint` type stores the value used by the evaluator
/// and is held in the `constraint` property.
public protocol ProcessCondition: ProcessConditionConvertible, Condition where Subject == XPProcessProtocol {
    associatedtype Constraint
    var constraint: Constraint { get set }
}

/// Condition for evaluating files.
///
/// Structs conforming to this protocol are used within `File` DSL blocks to specify
/// criteria for matching files based on various attributes such as path, content,
/// signatures, or metadata.
///
/// The associated `Constraint` type stores the value used by the evaluator
/// and is held in the `constraint` property.
public protocol FileCondition: FileConditionConvertible, Condition where Subject == XPPluginPathProtocol {
    associatedtype Constraint
    var constraint: Constraint { get set }
}

/// Condition for evaluating Safari App Extensions.
///
/// Structs conforming to this protocol are used within `SafariAppExtension` DSL blocks to
/// specify criteria for matching Safari App Extensions based on their binary executables,
/// JavaScript payloads.
///
/// The associated `Constraint` type stores the value used by the evaluator
/// and is held in the `constraint` property.
public protocol SafariAppExtensionCondition: SafariAppExtensionConditionConvertible, Condition where Subject == XPRegisteredPlugin {
    associatedtype Constraint
    var constraint: Constraint { get set }
}

/// Protocol that represents a remediation item (detection or cleanup).
public protocol Remediation: RemediationConvertible {}

/// Unknown protocol (possibly used to store user-supplied callbacks executed when a remediation triggers).
public protocol OnMatchable {
    associatedtype Subject
}

/// Type-erasing protocol that allows a sequence of `Remediation` instances to be
/// passed to `RemediationArrayBuilder`.
public protocol RemediationConvertible {}

/// This protocol provides a way to convert a sequence of `ServiceCondition` instances
/// into a sequence of `AnyServiceCondition` instances, which can be used to build
/// a `ServiceRemediation` instance.
public protocol ServiceConditionConvertible {}

/// This protocol provides a way to convert a sequence of `ProcessCondition` instances
/// into a sequence of `AnyProcessCondition` instances, which can be used to build
/// a `ProcessRemediation` instance.
public protocol ProcessConditionConvertible {}

/// This protocol provides a way to convert a sequence of `FileCondition` instances
/// into a sequence of `AnyFileCondition` instances, which can be used to build
/// a `FileRemediation` instance.
public protocol FileConditionConvertible {}

/// This protocol provides a way to convert a sequence of `SafariAppExtensionCondition`
/// instances into a sequence of `AnySafariAppExtensionCondition` instances, which can
/// be used to build a `SafariAppExtensionRemediation` instance.
public protocol SafariAppExtensionConditionConvertible {}

/// Structs conforming to this protocol are used to evaluate conditions and execute
/// the corresponding remediations. AdloadRemediator, RedPineScanner, etc. conform to this protocol.
public protocol Remediator {}

// MARK: - Value Enum

/// Constraint value used by condition types to specify matching criteria.
///
/// This enum provides a unified way to express different types of matching patterns
/// and literal values used across various condition implementations. It supports
/// string patterns, boolean flags, numeric values, and collection-based matching.
///
/// ## Example
/// ```swift
/// PirritRemediator {
///     Service(tag: nil) {
///         KeyValue(["WatchPaths":.Wildcard, "StartInterval":.Wildcard, "Label":.Pattern(".*\\.app")])
///         ExecutableYara(yaraPirrit)
///     }
///     ...(snip)...
/// }
/// ```
public enum Value: Equatable {
    case Pattern(String)
    case String(String)
    case Bool(Bool)
    case Int(Int)
    case PatternGroup([String])
    case StringGroup([String])
    case IntGroup([Int])
    case StringPrefix(String)
    case StringSuffix(String)
    case StringContains(String)
    case Wildcard
}

// MARK: - Service Conditions

/// Type-erased wrapper that allows any concrete struct conforming to `ServiceCondition` to be stored in a heterogeneous collection.
///
/// This wrapper enables the storage of different service condition types in a single
/// array, enabling the composition of complex service detection rules.
///
/// This type serves as the element type for arrays returned by `ServiceRemediationBuilder` 
/// when processing DSL blocks. The resulting `[AnyServiceCondition]` array is assigned to 
/// the `conditions` property of `ServiceRemediation` structures.
///
/// The `assess` member contains a function that implements the actual condition evaluation
/// logic derived from the original concrete struct conforming to `ServiceCondition`.
public struct AnyServiceCondition: ServiceCondition {
    public var constraint: Constraint
    public let assess: (Subject) -> Bool // NOTE: actual property name is _assess
    public typealias Constraint = Any
}

/// Matches the number of command-line arguments received by a launchd service.
public struct ArgumentCount: ServiceCondition {
    public var constraint: Constraint
    public typealias Constraint = Int
}

/// Matches positional arguments passed to a launchd service by index.
public struct Arguments: ServiceCondition {
    public var constraint: Constraint
    public typealias Constraint = [Int: Value]
}

/// Matches the value of one or more keys in the service's property list or configuration.
///
/// This condition matches the value of one or more keys in the service's property list or configuration.
///
/// ## Example
/// ```swift
/// PirritRemediator {
///     Service(tag: nil) {
///         KeyValue(["WatchPaths":.Wildcard, "StartInterval":.Wildcard, "Label":.Pattern(".*\\.app")])
///         ExecutableYara(yaraPirrit)
///     }
///     ...(snip)...
/// }
/// ```
public struct KeyValue: ServiceCondition {
    public var constraint: Constraint
    public typealias Constraint = [String: Value]
}

/// Evaluates the service's executable binary against a YARA rule.
///
/// This condition matches the service's executable binary against a YARA rule.
///
/// ## Example
/// ```swift
/// DollitleRemediator {
///     Service(tag: nil) {
///         ExecutableYara(YaraMatcher(dolittleYara))
///     }.deleteBundleToo()
/// }
/// ```
public struct ExecutableYara: ServiceCondition {
    public var constraint: Constraint
    public typealias Constraint = YaraMatcherProtocol
}

/// Applies a pattern match to the absolute path of the service's executable.
///
/// This condition matches the absolute path of the service's executable against a pattern.
///
/// ## Example
/// ```swift
/// BundloreRemediator {
///     Service(tag: nil) {
///         ExecutableIsUntrusted(true)
///         ExecutablePath(.Pattern(".*/(confup|macOSOTA|SofTruster|UpToDateMac|zapdate|webtools|.?MMSPROT)(/|$)"))
///     }.reportOnly()
/// }
/// ```
public struct ExecutablePath: ServiceCondition {
    public var constraint: Constraint
    public typealias Constraint = Value
}

/// Evaluates whether the service's executable is untrusted.
///
/// This condition identifies "untrusted" executables. "Untrusted" means that either
/// the code identifier cannot be obtained, or the code certificate array is empty.
///
/// ## Example
/// ```swift
/// CardboardCutoutRemediator {
///     Service(tag: nil) {
///         ExecutableIsUntrusted(true)
///         ExecutableRevoked(true)
///     }
/// }
/// ```
public struct ExecutableIsUntrusted: ServiceCondition {
    public var constraint: Constraint
    public let logger: XPLogger
    public typealias Constraint = Bool
}

/// Evaluates whether the Notarization ticket for the executable has been revoked.
///
/// This condition detects executables whose Notarization ticket has been revoked.
///
/// This is determined by checking if the result of `CFErrorGetCode` from the
/// `SecAssessmentTicketLookup` function call returns `EACCESS`.
///
/// ## Example
/// ```swift
/// CardboardCutoutRemediator {
///     Service(tag: nil) {
///         ExecutableIsUntrusted(true)
///         ExecutableRevoked(true)
///     }
/// }
/// ```
public struct ExecutableRevoked: ServiceCondition {
    public var constraint: Constraint
    public let logger: XPLogger
    public typealias Constraint = Bool
}

/// Applies a list of `FileCondition`s to the executable referenced by a launchd service.
///
/// The initializer accepts a `FileRemediationBuilder` DSL block, allowing to
/// use `FileCondition`-conforming structures to describe conditions that apply
/// to the executable file registered with the launchd service.
///
/// ## Example
/// ```swift
/// AdloadRemediator {
///     Service(tag: nil) {
///         ServiceExecutable {
///             FileMacho(true)
///             FileNotarised(false)
///             FileYara(YaraMatcher(adloadYara))
///         }
///     }
///     ...(snip)...
/// }
/// ```
public struct ServiceExecutable: ServiceCondition {
    public var constraint: Constraint
    public typealias Constraint = [AnyFileCondition]
}

// MARK: - Process Conditions

/// Type-erased wrapper that allows any concrete struct conforming to `ProcessCondition` to be stored in a heterogeneous collection.
///
/// This wrapper enables the storage of different process condition types in a single
/// array, enabling the composition of complex process detection rules.
///
/// This type serves as the element type for arrays returned by `ProcessRemediationBuilder` 
/// when processing DSL blocks. The resulting `[AnyProcessCondition]` array is assigned to 
/// the `processConditions` property of `Process` structures.
///
/// The `assess` member contains a function that implements the actual condition evaluation
/// logic derived from the original concrete struct conforming to `ProcessCondition`.
public struct AnyProcessCondition: ProcessCondition {
    public var constraint: Constraint
    public let assess: (Subject) -> Bool // NOTE: actual property name is _assess
    public typealias Constraint = Any
}

/// Matches the process name of a running process.
///
/// This condition matches the name of a running process.
///
/// ## Example
/// ```swift
/// ColdSnapRemediator {
///     for processName in processNames {
///         Process {
///             ProcessName(processName) // matches the name of the process
///             ProcessIsNotarised(false)
///             ProcessIsAppleSigned(false)
///         }.reportOnly(true)
///
///         Process {
///             ProcessName(processName) // matches the name of the process
///             ProcessIsAppleSigned(false)
///             ProcessMainExecutable(FileYara(YaraMatcher(yaraColdSnap)))
///         }.deleteExecutable(true)
///     }
///     ...(snip)...
/// }
/// ```
public struct ProcessName: ProcessCondition {
    public var constraint: Constraint
    public typealias Constraint = Value
}

/// Matches the CDHash of the process's Mach-O binary.
///
/// This condition matches the CDHash of the process's Mach-O binary.
///
/// ## Example
/// ```swift
/// RoachFlightRemediator {
///     for cdHash in targetCDHashes {
///         Process {
///             ProcessCDHash(cdHash)
///         }.deleteExecutable()
///     }
/// }
/// ```
public struct ProcessCDHash: ProcessCondition {
    public var constraint: Constraint
    public typealias Constraint = String
}

/// Evaluates whether the process binary is notarized.
///
/// This condition checks if the process binary is notarized.
///
/// ## Example
/// ```swift
/// ColdSnapRemediator {
///     for processName in processNames {
///         Process {
///             ProcessName(processName)
///             ProcessIsNotarised(false)
///             ProcessIsAppleSigned(false)
///         }.reportOnly()
///
///         Process {
///             ProcessName(processName)
///             ProcessIsAppleSigned(false)
///             ProcessMainExecutable(FileYara(YaraMatcher(yaraColdSnap)))
///         }.deleteExecutable(true)
///     }
///     ...(snip)...
/// }
/// ```
public struct ProcessIsNotarised: ProcessCondition {
    public var constraint: Constraint
    public typealias Constraint = Bool
}

/// Evaluates whether the process binary is signed by Apple.
///
/// This condition checks if the process binary is signed by Apple.
///
/// ## Example
/// ```swift
/// ColdSnapRemediator {
///     for processName in processNames {
///         Process {
///             ProcessName(processName)
///             ProcessIsNotarised(false)
///             ProcessIsAppleSigned(false) // false means the process binary is not signed by Apple
///         }.reportOnly()
///
///         Process {
///             ProcessName(processName)
///             ProcessIsAppleSigned(false) // false means the process binary is not signed by Apple
///             ProcessMainExecutable(FileYara(YaraMatcher(yaraColdSnap)))
///         }.deleteExecutable(true)
///     }
///     ...(snip)...
/// }
/// ```
public struct ProcessIsAppleSigned: ProcessCondition {
    public var constraint: Constraint
    public typealias Constraint = Bool
}

/// Applies a list of `FileCondition`s to the process's main executable on disk.
///
/// The initializer accepts a `FileRemediationBuilder` DSL block, allowing to
/// use `FileCondition`-conforming structures to describe conditions that apply
/// to the executable file backing the running process.
///
/// ## Example
/// ```swift
/// AdloadRemediator {
///     for pathPattern in pathPatterns {
///         Process {
///             ProcessIsNotarised(false)
///             ProcessMainExecutable {
///                 FilePath(.StringContains(pathPattern))
///                 FileYara(YaraMatcher(adloadYara))
///             }
///         }                                                                         
///     }
///     ...(snip)...
/// }
/// ```
public struct ProcessMainExecutable: ProcessCondition {
    public var constraint: Constraint
    public typealias Constraint = [AnyFileCondition]
}

/// Evaluates whether the process has an on-disk backing file.
///
/// This condition checks whether the process has an on-disk backing file.
///
/// ## Example
/// ```swift
/// BadGachaRemediator {
///     Process {
///         ProcessHasBackingFile(false)
///     }.reportOnly()
/// }
/// ```
public struct ProcessHasBackingFile: ProcessCondition {
    public var constraint: Constraint
    public typealias Constraint = Bool
}

/// Matches a library or a framework that the process has loaded.
///
/// This condition enables detection of processes that have loaded specific libraries
/// or frameworks.
///
/// ## Example
/// ```swift
/// RedPineScanner {
///     Process {
///         ProcessIsAppleSigned(false)
///         HasLoadedLibrary("/System/Library/PrivateFrameworks/FMCore.framework")
///         HasLoadedLibrary("/System/Library/Frameworks/CoreLocation.framework/CoreLocation")
///         HasLoadedLibrary("/System/Library/Frameworks/AVFoundation.framework/AVFoundation")
///         HasLoadedLibrary("/usr/lib/libsqlite3.dylib")
///     }.reportOnly()
/// }
/// ```
public struct HasLoadedLibrary: ProcessCondition {
    public var constraint: Constraint
    public typealias Constraint = Value
}

// MARK: - File Conditions

/// Type-erased wrapper that allows any concrete struct conforming to `FileCondition` to be stored in a heterogeneous collection.
///
/// This wrapper enables the storage of different file condition types in a single
/// array, enabling the composition of complex file detection rules.
///
/// This type serves as the element type for arrays returned by `FileRemediationBuilder` 
/// when processing DSL blocks. The resulting `[AnyFileCondition]` array is assigned to 
/// the `conditions` property of `File` structures. For ServiceExecutable and
/// ProcessMainExecutable, the `conditions` property is assigned to the `constraint`
/// property.
///
/// The `assess` member contains a function that implements the actual condition evaluation
/// logic derived from the original concrete struct conforming to `FileCondition`.
public struct AnyFileCondition: FileCondition {
    public var constraint: Constraint
    public let assess: (Subject) -> Bool // NOTE: actual property name is _assess
    public typealias Constraint = Any
}

/// Evaluates a file against a YARA rule.
///
/// This condition matches the file against a YARA rule.
///
/// ## Example
/// ```swift
/// let eicarYara = """
/// rule EICAR: Example Test {
///     meta:
///         name = "EICAR.A"
///         version = 1337
///         enabled = true
///     strings:
///         $eicar_substring = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
///     condition:
///         $eicar_substring
/// """
///
/// EicarRemediator {
///     File(path: "/tmp/eicar") {
///         MinFileSize(68)
///         FileYara(YaraMatcher(eicarYara))
///     }
/// }
/// ```
public struct FileYara: FileCondition {
    public var constraint: Constraint
    public typealias Constraint = YaraMatcherProtocol
}

/// Applies the absolute path of the file against a pattern.
///
/// This condition matches the absolute path of the file against a pattern.
///
/// ## Example
/// ```swift
/// let pathPatterns = ["/Library/Application Support/", "/Library/ApplicationSupport/", ".mitmproxy", "/tmp/", "Install.command"]
///
/// AdloadRemediator {
///     for pathPattern in pathPatterns {
///         Process {
///             ProcessIsNotarised(false)
///             ProcessMainExecutable {
///                 FilePath(.StringContains(pathPattern))
///                 FileYara(YaraMatcher(adloadYara))
///             }
///         }
///     }
///     ...(snip)...
/// }
/// ```
public struct FilePath: FileCondition {
    public var constraint: Constraint
    public typealias Constraint = Value
}

/// Unknown (but maybe it matches the MIME type of the file?)
public struct FileMime: FileCondition {
    public var constraint: Constraint
    public typealias Constraint = Value
}

/// Unknown (but maybe it matches the file signature?)
public struct FileMagic: FileCondition {
    public var constraint: Constraint
    public typealias Constraint = Value
}

/// Evaluates whether the file is a Mach-O executable.
///
/// This condition checks whether the file is a Mach-O executable.
///
/// ## Example
/// ```swift
/// AdloadRemediator {
///     Service(tag: nil) {
///         ServiceExecutable {
///             FileMacho(true)
///             FileNotarised(false)
///             FileYara(YaraMatcher(adloadYara))
///         }
///     }
///     ...(snip)...
/// }
/// ```
public struct FileMacho: FileCondition {
    public var constraint: Constraint
    public let logger: XPLogger
    public typealias Constraint = Bool
}

/// Evaluates whether the file is notarized.
///
/// This condition checks whether the file is notarized.
///
/// ## Example
/// ```swift
/// AdloadRemediator {
///     Service(tag: nil) {
///         ServiceExecutable {
///             FileMacho(true)
///             FileNotarised(false)
///             FileYara(YaraMatcher(adloadYara))
///         }
///     }
///     ...(snip)...
/// }
/// ```
public struct FileNotarised: FileCondition {
    public var constraint: Constraint
    public let logger: XPLogger
    public typealias Constraint = Bool
}

/// Unknown (but maybe it evaluates a XOR-decoded view of the file against nested `FileCondition`s?)
///
/// ## Example
/// ```swift
/// ColdSnapRemediator {
///     for fileName in fileNames {
///         File(path: fileName) {
///             MinFileSize(1000)
///             MaxFileSize(2000)
///             FileSingleByteXor(xor_key: nil) { // xor_key is set to nil?
///                 FileYara(YaraMatcher(yaraColdSnapConfig))
///             }
///         }
///     }
///     ...(snip)...
/// }
/// ```
public struct FileSingleByteXor: FileCondition {
    public var constraint: Constraint
    private var xor_key: UInt8? // NOTE: this is a private property, so value type is inferred as UInt8?
    public let logger: XPLogger
    public typealias Constraint = [AnyFileCondition]
}

/// Matches files whose size is less than or equal to the given number of bytes.
///
/// This condition matches files whose size is less than or equal to the given number of bytes.
///
/// ## Example
/// ```swift
/// KeyStealRemediator {
///     File(path: "/Library/Caches/com.apple.server") {
///         MaxFileSize(32)
///     }
///     ...(snip)...
/// }
/// ```
public struct MaxFileSize: FileCondition {
    public var constraint: Constraint
    public typealias Constraint = Int
}

/// Matches files whose size is greater than or equal to the given number of bytes.
///
/// This condition matches files whose size is greater than or equal to the given number of bytes.
///
/// ## Example
/// ```swift
/// EicarRemediator {
///     File(path: "/tmp/eicar") {
///         MinFileSize(68)
///         FileYara(YaraMatcher(eicarYara))
///     }
/// }
/// ```
public struct MinFileSize: FileCondition {
    public var constraint: Constraint
    public typealias Constraint = Int
}

/// Matches the SHA-256 digest of the file's contents.
public struct FileSHA256: FileCondition {
    public var constraint: Constraint
    public typealias Constraint = String
}

/// Matches the CDHash of the executable.
public struct FileCDHash: FileCondition {
    public var constraint: Constraint
    public let logger: XPLogger
    public typealias Constraint = String
}

// MARK: - Safari App Extension Conditions

/// Type-erased wrapper that allows any concrete struct conforming to `SafariAppExtensionCondition` to be stored in a heterogeneous collection.
///
/// This wrapper enables the storage of different Safari App Extension condition types
/// in a single array, enabling the composition of complex Safari App Extension detection
/// rules.
///
/// This type serves as the element type for arrays returned by `SafariAppExtensionRemediationBuilder` 
/// when processing DSL blocks. The resulting `[AnySafariAppExtensionCondition]` array is assigned to 
/// the `conditions` property of `SafariAppExtension` structures.
///
/// The `assess` member contains a function that implements the actual condition evaluation
/// logic derived from the original concrete struct conforming to `SafariAppExtensionCondition`.
public struct AnySafariAppExtensionCondition: SafariAppExtensionCondition {
    public var constraint: Constraint
    public let assess: (Subject) -> Bool // NOTE: actual property name is _assess
    public typealias Constraint = Any
}

/// Evaluates the compiled binary of a Safari App Extension against a YARA rule.
///
/// This condition enables detection of malicious Safari App Extensions by analyzing
/// their compiled binary executables using YARA pattern matching.
///
/// This condition retrieves the executable file of the Safari App Extension bundle
/// (.appex) using NSBundle's `executableURL` property and matches the obtained
/// executable file against the YARA rule specified in the `constraint` property.
///
/// ## Example
/// ```swift
/// SheepSwapRemediator {
///     SafariAppExtension {
///         ExtensionBinaryYara(YaraMatcher(sheepSwapYara1))
///     }
///     ...(snip)...
/// }
/// ```
public struct ExtensionBinaryYara: SafariAppExtensionCondition {
    public var constraint: Constraint
    public typealias Constraint = YaraMatcherProtocol
}

/// Evaluates the JavaScript payload of a Safari App Extension against a YARA rule.
///
/// This condition enables detection of malicious Safari App Extensions by analyzing
/// their JavaScript content against a YARA rule.
///
/// This condition enumerates all files with `.js` extension contained within the
/// Safari App Extension bundle (.appex) and matches them against the specified
/// YARA rule in the `constraint` property.
///
/// ## Example
/// ```swift
/// SheepSwapRemediator {
///     SafariAppExtension {
///         JavaScriptYara(YaraMatcher(sheepSwapYara3))
///     }.reportOnly()
///     ...(snip)...
/// }
/// ```
public struct JavaScriptYara: SafariAppExtensionCondition {
    public var constraint: Constraint
    public typealias Constraint = YaraMatcherProtocol
}

// MARK: - Remediations

/// Remediation that removes proxy configurations.
///
/// This remediation removes proxy configurations from the system.
///
/// ## Example
/// ```swift
/// AdloadRemediator {
///     Service(tag: nil) {
///         ServiceExecutable {
///             FileMacho(true)
///             FileNotarised(false)
///             FileYara(YaraMatcher(adloadYara))
///         }
///     }
///     .followUpRemediation(ProxyRemediation(reportOnly: false, hosts: ["localhost", "0.0.0.0", "::1", "127.0.0.1"], ports: [8080])) // proxy setting is removed as a follow-up remediation after remediating the service
///     ...(snip)...
/// }
/// ```
public struct ProxyRemediation: Remediation {
    public var tag: String?
    public var reportOnly: Bool
    public var followUpRemediations: [any Remediation]
    public let hosts: [String]
    public let ports: [Int]
}

/// Remediation that targets a launchd service.
public struct ServiceRemediation: Remediation, OnMatchable {
    public var tag: String?
    public var reportOnly: Bool
    public var unloadOnly: Bool
    public var deleteBundleToo: Bool
    public var conditions: [AnyServiceCondition]
    public var followUpRemediations: [any Remediation]
    public var onMatchCallbacks: [[(XProtectLaunchdDaemonAgentProtocol) -> RemediationConvertible]]
    public typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

/// Remediation that targets a file on disk.
public struct FileRemediation: Remediation {
    public var tag: String?
    public var reportOnly: Bool
    public var followUpRemediations: [any Remediation]
    public var conditions: [AnyFileCondition]
    public var filepath: XPPluginPathProtocol
}

/// Remediation that targets a Safari App Extension.
public struct SafariAppExtensionRemediation: Remediation {
    public var tag: String?
    public var reportOnly: Bool
    public var followUpRemediations: [any Remediation]
    public var conditions: [AnySafariAppExtensionCondition]
}

/// Remediation that targets a running process.
public struct ProcessRemediation: Remediation {
    public var tag: String?
    public var reportOnly: Bool
    public var deleteExecutable: Bool
    public var includePlatform: Bool
    public var followUpRemediations: [any Remediation]
    public var conditions: [AnyProcessCondition]
}

// MARK: - Builders

/// Result-builder type used to gather `Remediation`s inside a `Remediator` DSL block.
@resultBuilder public enum RemediationArrayBuilder {
    public static func buildBlock(_ components: RemediationConvertible...) -> [any Remediation] {
        return []
    }
}

/// Convenience container that groups multiple remediations.
public struct Remediations {
    public var content: [any Remediation]
}

/// Result-builder type used to gather `ServiceCondition`s inside a `Service` DSL block.
///
/// This result builder enables the declarative composition of service conditions
/// within `Service` remediation blocks. It collects `ServiceCondition` instances
/// and returns them as an array of `AnyServiceCondition` for evaluation.
///
/// ## Example
/// ```swift
/// Service(tag: nil) {
///     ExecutablePath(.PatternGroup([".*/Library/.*"]))
///     ExecutableYara(YaraMatcher(yaraRule))
/// }
/// ```
@resultBuilder public enum ServiceRemediationBuilder {
    // Just a placeholder
    public static func buildBlock(_ components: ServiceConditionConvertible...) -> [AnyServiceCondition] {
        return []
    }
}

/// Entry point for the `Service { ... }` DSL block.
///
/// Builds a declarative `Remediation` that targets launchd services.
public struct Service {
    public var content: ServiceRemediation = ServiceRemediation(reportOnly: false, unloadOnly: false, deleteBundleToo: false, conditions: [], followUpRemediations: [], onMatchCallbacks: [])
    public var unloadOnlyBool: Bool = false
    
    init(tag: String?, @ServiceRemediationBuilder serviceRemediationBuilder: @escaping () -> [AnyServiceCondition]) {
        self.content.tag = tag
        self.content.conditions = serviceRemediationBuilder()
    }    

    public func unloadOnly() -> Service {
        var copy = self
        copy.unloadOnlyBool = true
        return copy
    }
    
    public func deleteBundleToo() -> Service {
        var copy = self
        copy.content.deleteBundleToo = true
        return copy
    }
    
    public func reportOnly() -> Service {
        var copy = self
        copy.content.reportOnly = true
        return copy
    }
}

/// `Remediation` that removes proxy configurations.
public struct Proxy {
    public var hosts: [String]
    public var ports: [Int]
}

/// Result-builder type used to gather `FileCondition`s inside a `File` DSL block.
///
/// This result builder enables the declarative composition of file conditions
/// within `File` remediation blocks. It collects `FileCondition` instances
/// and returns them as an array of `AnyFileCondition` for evaluation.
///
/// ## Example
/// ```swift
/// File(path: "/tmp/suspicious") {
///     FileYara(YaraMatcher(yaraRule))
///     MinFileSize(100)
/// }
/// ```
@resultBuilder public enum FileRemediationBuilder {
    // Just a placeholder
    public static func buildBlock(_ components: FileConditionConvertible...) -> [AnyFileCondition] {
        return []
    }
}

/// Entry point for the `File { ... }` DSL block.
///
/// Builds a declarative `Remediation` that targets arbitrary files.
public struct File {
    public var paths: [XPPluginPathProtocol] = []
    public var predicate: NSPredicate? = nil
    public var searchDir: String? = nil
    public var searchDepth: Int? = nil
    public var regexpArray: [String] = []
    public var isFileSearchRemediation: Bool = false
    public var isPredicateSearchRemediation: Bool = false
    public var reportOnlyBool: Bool = false
    public var conditions: [AnyFileCondition] = []

    init(path: String, @FileRemediationBuilder fileRemediationBuilder: @escaping () -> [AnyFileCondition]) {
        // NOTE: XPPluginPath is not implemented, so we commented out the line below to avoid a build error
        // self.paths = [XPPluginPath(path)]
        self.conditions = fileRemediationBuilder()
    }
    
    init(predicate: NSPredicate, @FileRemediationBuilder fileRemediationBuilder: @escaping () -> [AnyFileCondition]) {
        self.predicate = nil // NOTE: The predicate parameter is not assigned to the predicate property in this initializer
        self.isPredicateSearchRemediation = true
        self.conditions = fileRemediationBuilder()
    }

    init(searchDir: String, regexp: String, searchDepth: Int?, @FileRemediationBuilder fileRemediationBuilder: @escaping () -> [AnyFileCondition]) {
        self.searchDir = searchDir
        self.searchDepth = searchDepth				
        self.isFileSearchRemediation = true
        self.regexpArray.append(regexp)
        self.conditions = fileRemediationBuilder()
    }
    
    func reportOnly() -> File {
        var copy = self
        copy.reportOnlyBool = true
        return copy
    }
}

/// Result-builder type used to gather `SafariAppExtensionCondition`s inside a `SafariAppExtension` DSL block.
///
/// This result builder enables the declarative composition of Safari App Extension conditions
/// within `SafariAppExtension` remediation blocks. It collects `SafariAppExtensionCondition` instances
/// and returns them as an array of `AnySafariAppExtensionCondition` for evaluation.
///
/// ## Example
/// ```swift
/// SafariAppExtension {
///     ExtensionBinaryYara(YaraMatcher(yaraRule))
///     JavaScriptYara(YaraMatcher(jsRule))
/// }
/// ```
@resultBuilder public enum SafariAppExtensionRemediationBuilder {
    // Just a placeholder
    public static func buildBlock(_ components: SafariAppExtensionConditionConvertible...) -> [AnySafariAppExtensionCondition] {
        return []
    }
}

/// Entry point for the `SafariAppExtension { ... }` DSL block.
///
/// Builds a declarative `Remediation` that targets Safari App Extensions.
public struct SafariAppExtension {
    public var conditions: [AnySafariAppExtensionCondition] = []
    public var reportOnlyBool: Bool = false
    
    init(@SafariAppExtensionRemediationBuilder safariAppExtensionBuilder: @escaping () -> [AnySafariAppExtensionCondition]) {
        self.conditions = safariAppExtensionBuilder()
    }

    public func reportOnly() -> SafariAppExtension {
        var copy = self
        copy.reportOnlyBool = true
        return copy
    }
}

/// Result-builder type used to gather `ProcessCondition`s inside a `Process` DSL block.
///
/// This result builder enables the declarative composition of process conditions
/// within `Process` remediation blocks. It collects `ProcessCondition` instances
/// and returns them as an array of `AnyProcessCondition` for evaluation.
///
/// ## Example
/// ```swift
/// Process {
///     ProcessIsAppleSigned(false)
///     HasLoadedLibrary("/System/Library/Frameworks/CoreLocation.framework/CoreLocation")
/// }
/// ```
@resultBuilder public enum ProcessRemediationBuilder {
    // Just a placeholder
    public static func buildBlock(_ components: ProcessConditionConvertible...) -> [AnyProcessCondition] {
        return []
    }
}

/// Entry point for the `Process { ... }` DSL block.
///
/// Builds a declarative `Remediation` that targets running processes.
public struct Process {
    public var processConditions: [AnyProcessCondition] = []
    public var reportOnlyBool: Bool = false
    public var deleteExecutableBool: Bool = false
    public var includePlatformBool: Bool = false
    
    init(@ProcessRemediationBuilder processRemediationBuilder: @escaping () -> [AnyProcessCondition]) {
        self.processConditions = processRemediationBuilder()
    }
    
    public func reportOnly() -> Process {
        var copy = self
        copy.reportOnlyBool = true
        return copy
    }
    
    public func deleteExecutable() -> Process {
        var copy = self
        copy.deleteExecutableBool = true
        return copy    
    }
}

// MARK: - Extensions

extension Array<Remediation>: RemediationConvertible {}
extension Array<AnyServiceCondition>: ServiceConditionConvertible {}
extension Array<AnyFileCondition>: FileConditionConvertible {}

extension Service: RemediationConvertible {}
extension Proxy: RemediationConvertible {}
extension File: RemediationConvertible {}
extension SafariAppExtension: RemediationConvertible {}
extension Process: RemediationConvertible {}

/// Minimal `Remediator` implementation
// struct PlaceholderRemediator {
//     var statusReports: Any // XPPluginStatusCollator
//     var remediations: Remediations
// }
// 
// extension PlaceholderRemediator: Remediator {}
