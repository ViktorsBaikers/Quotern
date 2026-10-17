import AppKit
import CryptoKit
import Darwin
import Foundation

// native011-wrapper-admission:start
enum Native011WrapperAdmissionFailure: String, Error {
    case path = "N011-C-PATH"
    case contents = "N011-C-CONTENTS"
    case bytes = "N011-C-BYTES"
}

struct Native011WrapperFileIdentity: Equatable {
    let device: dev_t
    let inode: ino_t
    let size: off_t
    let modifiedSeconds: time_t
    let modifiedNanoseconds: Int
    let changedSeconds: time_t
    let changedNanoseconds: Int

    init(_ metadata: stat) {
        device = metadata.st_dev
        inode = metadata.st_ino
        size = metadata.st_size
        modifiedSeconds = metadata.st_mtimespec.tv_sec
        modifiedNanoseconds = metadata.st_mtimespec.tv_nsec
        changedSeconds = metadata.st_ctimespec.tv_sec
        changedNanoseconds = metadata.st_ctimespec.tv_nsec
    }
}

struct Native011WrapperIdentity: Equatable {
    let wrapper: URL
    let files: [Native011WrapperFileIdentity]
}

enum Native011WrapperAdmission {
    static let methods: Set<String> = [
        "testCodexNeverEntersStatusItem",
        "testWithheldReadinessNeverOpensPickerOrRegistersSource",
        "testRefusedNativePickerOKExpiresAndClosesWithoutRegistration",
        "testLateAcceptedOKIsRejectedBeforeSourceRegistration",
        "testCancellationRetainsEvidenceAndStopsOnlyOwnedJourney",
    ]

    static func metadataMatches(_ metadata: stat, type: mode_t, permissions: mode_t, owner: uid_t) -> Bool {
        metadata.st_mode & S_IFMT == type && metadata.st_mode & 0o7777 == permissions &&
            metadata.st_uid == owner && (type != S_IFREG || metadata.st_nlink == 1)
    }

    private static func metadata(_ url: URL) throws -> stat {
        var metadata = stat()
        guard lstat(url.path, &metadata) == 0 else { throw Native011WrapperAdmissionFailure.path }
        return metadata
    }

    static func checkAncestry(_ url: URL) throws {
        guard url.isFileURL, url.path == url.standardizedFileURL.path,
              url.path == url.resolvingSymlinksInPath().path else { throw Native011WrapperAdmissionFailure.path }
        var component = url
        while true {
            let metadata = try metadata(component)
            let values: URLResourceValues
            do { values = try component.resourceValues(forKeys: [.isAliasFileKey]) }
            catch { throw Native011WrapperAdmissionFailure.path }
            guard metadata.st_mode & S_IFMT != S_IFLNK, values.isAliasFile == false,
                  component == url || metadata.st_mode & S_IFMT == S_IFDIR else {
                throw Native011WrapperAdmissionFailure.path
            }
            if component.path == "/" { break }
            component.deleteLastPathComponent()
        }
    }

    static func checkedMetadata(_ url: URL, type: mode_t, permissions: mode_t) throws -> stat {
        try checkAncestry(url)
        let metadata = try metadata(url)
        guard metadataMatches(metadata, type: type, permissions: permissions, owner: getuid()) else {
            throw Native011WrapperAdmissionFailure.path
        }
        return metadata
    }

    static func admit(attempt: URL, method: String, original: URL, archive: URL,
                      binary: Data, archiveBytes: Data) throws -> Native011WrapperIdentity {
        let wrapper = attempt.appendingPathComponent("wrappers/" + method + ".app")
        let contents = wrapper.appendingPathComponent("Contents")
        let macos = contents.appendingPathComponent("MacOS")
        let plist = contents.appendingPathComponent("Info.plist")
        let executable = macos.appendingPathComponent("Quotern")
        var identities: [Native011WrapperFileIdentity] = []
        do {
            guard methods.contains(method) else { throw Native011WrapperAdmissionFailure.path }
            for url in [attempt, attempt.appendingPathComponent("wrappers")] { try checkAncestry(url) }
            for (url, type, permissions) in [
                (wrapper, S_IFDIR, mode_t(0o700)), (contents, S_IFDIR, mode_t(0o700)), (macos, S_IFDIR, mode_t(0o700)),
                (plist, S_IFREG, mode_t(0o600)), (executable, S_IFREG, mode_t(0o755)),
                (original, S_IFREG, mode_t(0o755)), (archive, S_IFREG, mode_t(0o644)),
            ] {
                identities.append(Native011WrapperFileIdentity(try checkedMetadata(url, type: type, permissions: permissions)))
            }
        } catch { throw Native011WrapperAdmissionFailure.path }
        do {
            for (directory, names) in [(wrapper, ["Contents"]), (contents, ["Info.plist", "MacOS"]), (macos, ["Quotern"])] {
                guard try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() == names.sorted() else {
                    throw Native011WrapperAdmissionFailure.contents
                }
            }
            let size = try metadata(plist).st_size
            guard size > 0 && size <= 4096 else { throw Native011WrapperAdmissionFailure.contents }
            let bytes = try Data(contentsOf: plist)
            guard bytes.count == size,
                  let object = try PropertyListSerialization.propertyList(from: bytes, options: [], format: nil) as? [String: Any],
                  Set(object.keys) == Set(["CFBundleExecutable", "CFBundleIdentifier", "LSUIElement"]),
                  object["CFBundleExecutable"] as? String == "Quotern",
                  object["CFBundleIdentifier"] as? String == "app.quotern.nativeproof." + method,
                  let agent = object["LSUIElement"] as? NSNumber,
                  CFGetTypeID(agent) == CFBooleanGetTypeID(), agent.boolValue else {
                throw Native011WrapperAdmissionFailure.contents
            }
        } catch { throw Native011WrapperAdmissionFailure.contents }
        do {
            guard !binary.isEmpty, !archiveBytes.isEmpty,
                  try metadata(original).st_size == binary.count,
                  try metadata(executable).st_size == binary.count,
                  try metadata(archive).st_size == archiveBytes.count,
                  try Data(contentsOf: original) == binary, try Data(contentsOf: executable) == binary,
                  try Data(contentsOf: archive) == archiveBytes,
                  archiveBytes.starts(with: Data("!<arch>\n".utf8)) else { throw Native011WrapperAdmissionFailure.bytes }
            try validateMachO(binary)
        } catch { throw Native011WrapperAdmissionFailure.bytes }
        return Native011WrapperIdentity(wrapper: wrapper, files: identities)
    }

    static func requireUnchanged(_ identity: Native011WrapperIdentity, frozen: Native011WrapperIdentity) throws {
        guard identity == frozen else { throw Native011WrapperAdmissionFailure.path }
    }

    private static func validateMachO(_ bytes: Data) throws {
        func word(_ offset: Int) throws -> UInt32 {
            guard offset >= 0 && offset <= bytes.count - 4 else { throw Native011WrapperAdmissionFailure.bytes }
            return (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[offset + $1]) << ($1 * 8) }
        }
        guard try word(0) == 0xfeedfacf && word(4) == 0x0100000c && word(12) == 2 else {
            throw Native011WrapperAdmissionFailure.bytes
        }
        let commands = try word(16), commandBytes = try word(20)
        guard commands > 0 && commands < 1024, bytes.count >= 32,
              commandBytes <= bytes.count - 32 else { throw Native011WrapperAdmissionFailure.bytes }
        let commandEnd = 32 + Int(commandBytes)
        var offset = 32
        var versions: [UInt32] = []
        for _ in 0..<commands {
            guard offset <= commandEnd - 8 else { throw Native011WrapperAdmissionFailure.bytes }
            let command = try word(offset), size = try word(offset + 4)
            guard size >= 8, size % 8 == 0, Int(size) <= commandEnd - offset else {
                throw Native011WrapperAdmissionFailure.bytes
            }
            if command == 0x32 {
                guard size >= 24, try word(offset + 8) == 1 else { throw Native011WrapperAdmissionFailure.bytes }
                versions.append(try word(offset + 12))
            }
            offset += Int(size)
        }
        guard offset == commandEnd, versions == [14 << 16] else { throw Native011WrapperAdmissionFailure.bytes }
    }
}

func native011WrapperAdmissionSelfCheck(proof: URL, binary: Data, archiveBytes: Data) throws -> [String: String] {
    let pathCases = [
        "missing-wrapper", "wrapper-file", "wrong-method", "noncanonical-attempt",
        "attempt-symlink", "wrappers-symlink", "wrapper-symlink", "contents-symlink", "macos-symlink", "plist-symlink", "executable-symlink",
        "attempt-alias", "wrappers-alias", "wrapper-alias", "contents-alias", "macos-alias", "plist-alias", "executable-alias",
        "contents-file", "macos-file", "plist-directory", "executable-directory",
        "wrapper-mode", "contents-mode", "macos-mode", "plist-mode", "executable-mode", "plist-hardlink", "executable-hardlink",
    ]
    let contentsCases = [
        "plist-missing-executable", "plist-missing-identifier", "plist-missing-agent", "plist-extra-key",
        "plist-executable-type", "plist-identifier-type", "plist-agent-type", "plist-executable-value", "plist-sibling-identifier", "plist-agent-false",
        "inventory-extra-file", "inventory-extra-directory",
        "plist-empty", "plist-oversize", "plist-malformed", "plist-array",
    ]
    let byteCases = [
        "executable-drift", "original-drift", "archive-drift", "macho-platform", "macho-deployment", "macho-architecture",
        "macho-short-header", "macho-command-count-zero", "macho-command-count-limit",
        "macho-command-region-truncated", "macho-command-header-truncated", "macho-command-size-small",
        "macho-command-size-unaligned", "macho-command-size-overflow", "macho-command-end-mismatch",
        "macho-build-version-missing", "macho-build-version-duplicate", "macho-build-version-small",
    ]
    var expected = Dictionary(uniqueKeysWithValues: pathCases.map { ($0, "N011-C-PATH") } +
                              contentsCases.map { ($0, "N011-C-CONTENTS") } + byteCases.map { ($0, "N011-C-BYTES") })
    expected["valid"] = "pass"
    guard proof.isFileURL, proof.path == proof.standardizedFileURL.path,
          proof.path == proof.resolvingSymlinksInPath().path,
          !proof.pathComponents.contains("native"), !proof.pathComponents.contains("mutation-inputs") else {
        throw Native011WrapperAdmissionFailure.path
    }
    _ = try Native011WrapperAdmission.checkedMetadata(proof, type: S_IFDIR, permissions: 0o700)
    let manifest = proof.appendingPathComponent("cases.json")
    let manifestMetadata = try Native011WrapperAdmission.checkedMetadata(manifest, type: S_IFREG, permissions: 0o600)
    guard manifestMetadata.st_size > 0 && manifestMetadata.st_size <= 1_048_576 else {
        throw Native011WrapperAdmissionFailure.contents
    }
    let rows: [[String: String]]?
    do { rows = try JSONSerialization.jsonObject(with: Data(contentsOf: manifest)) as? [[String: String]] }
    catch { throw Native011WrapperAdmissionFailure.contents }
    guard let rows, rows.count == expected.count, Set(rows.compactMap { $0["name"] }) == Set(expected.keys) else {
        throw Native011WrapperAdmissionFailure.contents
    }
    func fixtureURL(_ relative: String, noncanonical: Bool = false) throws -> URL {
        guard !relative.isEmpty, relative.utf8.count <= 4096, !relative.hasPrefix("/"), !relative.contains("\0"),
              noncanonical || !relative.split(separator: "/").contains(where: { $0 == ".." || $0 == "." }) else {
            throw Native011WrapperAdmissionFailure.path
        }
        let url = URL(fileURLWithPath: proof.path + "/" + relative)
        guard url.standardizedFileURL.path.hasPrefix(proof.path + "/"),
              url.resolvingSymlinksInPath().path.hasPrefix(proof.path + "/") else {
            throw Native011WrapperAdmissionFailure.path
        }
        return url
    }
    var results: [String: String] = [:]
    for row in rows {
        guard Set(row.keys) == Set(["name", "attempt", "method", "original", "archive", "expected"]),
              let name = row["name"], let method = row["method"], let attemptPath = row["attempt"],
              let originalPath = row["original"], let archivePath = row["archive"], row["expected"] == expected[name] else {
            throw Native011WrapperAdmissionFailure.contents
        }
        let attempt = try fixtureURL(attemptPath, noncanonical: name == "noncanonical-attempt")
        let original = try fixtureURL(originalPath)
        let archive = try fixtureURL(archivePath)
        var frozenBinary = binary
        if name.hasPrefix("macho-") {
            _ = try Native011WrapperAdmission.checkedMetadata(original, type: S_IFREG, permissions: 0o755)
            do { frozenBinary = try Data(contentsOf: original) }
            catch { throw Native011WrapperAdmissionFailure.bytes }
        }
        let observed: String
        var admitted: Native011WrapperIdentity?
        do {
            admitted = try Native011WrapperAdmission.admit(attempt: attempt, method: method, original: original, archive: archive,
                                                   binary: frozenBinary, archiveBytes: archiveBytes)
            observed = "pass"
        } catch let failure as Native011WrapperAdmissionFailure { observed = failure.rawValue }
        guard observed == expected[name] else { throw Native011WrapperAdmissionFailure.contents }
        results[name] = observed
        if name == "valid" { try native011WrapperIdentityControls(admitted: admitted, original: original, results: &results) }
    }
    guard results.count == rows.count + 52 else { throw Native011WrapperAdmissionFailure.contents }
    return results
}

func native011WrapperIdentityControls(admitted: Native011WrapperIdentity?, original: URL, results: inout [String: String]) throws {
    guard let admitted, admitted.files.count == 7 else { throw Native011WrapperAdmissionFailure.path }
    try Native011WrapperAdmission.requireUnchanged(admitted, frozen: admitted)
    results["identity-unchanged"] = "pass"
    func rejectsChanged(_ changed: Native011WrapperIdentity, name: String) throws {
        do {
            try Native011WrapperAdmission.requireUnchanged(changed, frozen: admitted)
        } catch let failure as Native011WrapperAdmissionFailure {
            guard failure == .path else { throw Native011WrapperAdmissionFailure.contents }
            results[name] = failure.rawValue
            return
        }
        throw Native011WrapperAdmissionFailure.contents
    }
    try rejectsChanged(Native011WrapperIdentity(wrapper: admitted.wrapper.appendingPathComponent("changed"), files: admitted.files),
                       name: "identity-wrapper")
    let fields: [(String, (inout stat) -> Void)] = [
        ("device", { $0.st_dev ^= 1 }), ("inode", { $0.st_ino ^= 1 }), ("size", { $0.st_size ^= 1 }),
        ("modified-seconds", { $0.st_mtimespec.tv_sec ^= 1 }), ("modified-nanoseconds", { $0.st_mtimespec.tv_nsec ^= 1 }),
        ("changed-seconds", { $0.st_ctimespec.tv_sec ^= 1 }), ("changed-nanoseconds", { $0.st_ctimespec.tv_nsec ^= 1 }),
    ]
    for (index, component) in ["wrapper", "contents", "macos", "plist", "executable", "original", "archive"].enumerated() {
        let file = admitted.files[index]
        var baseline = stat()
        baseline.st_dev = file.device
        baseline.st_ino = file.inode
        baseline.st_size = file.size
        baseline.st_mtimespec = timespec(tv_sec: file.modifiedSeconds, tv_nsec: file.modifiedNanoseconds)
        baseline.st_ctimespec = timespec(tv_sec: file.changedSeconds, tv_nsec: file.changedNanoseconds)
        for (field, change) in fields {
            var metadata = baseline
            change(&metadata)
            var files = admitted.files
            files[index] = Native011WrapperFileIdentity(metadata)
            try rejectsChanged(Native011WrapperIdentity(wrapper: admitted.wrapper, files: files),
                               name: "identity-" + component + "-" + field)
        }
    }
    var metadata = stat()
    guard lstat(original.path, &metadata) == 0,
          Native011WrapperAdmission.metadataMatches(metadata, type: S_IFREG, permissions: 0o755, owner: getuid()) else {
        throw Native011WrapperAdmissionFailure.path
    }
    metadata.st_uid ^= 1
    guard !Native011WrapperAdmission.metadataMatches(metadata, type: S_IFREG, permissions: 0o755, owner: getuid()) else {
        throw Native011WrapperAdmissionFailure.path
    }
    results["owner-mismatch"] = "N011-C-PATH"
}
// native011-wrapper-admission:end

// native011-ownership-fixture:start
let native011OwnershipFixture = #"""
{"application":{"path":"/fixture/attempt/wrappers/testCodexNeverEntersStatusItem.app/Contents/MacOS/Quotern","pid":13,"sec":100,"uid":501,"usec":3},"application_exit":null,\#
"candidate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","closure":"pending","launcher":{"path":"/usr/bin/open","pid":12,"sec":100,"uid":501,"usec":2},\#
"launcher_argv":["/usr/bin/open","-n","-W","--stdin","/dev/null","--stdout","/fixture/attempt/native/testCodexNeverEntersStatusItem/first/application.stdout.log","--stderr",\#
"/fixture/attempt/native/testCodexNeverEntersStatusItem/first/application.stderr.log","-a","/fixture/attempt/wrappers/testCodexNeverEntersStatusItem.app","--args","--selftest-journey",\#
"--selftest-home","/fixture/attempt/fixtures/testCodexNeverEntersStatusItem/home","--data-dir","/fixture/attempt/fixtures/testCodexNeverEntersStatusItem/data","--now","2026-09-30T12:00:00Z",\#
"--phase","first","--out","/fixture/attempt/native/testCodexNeverEntersStatusItem/first"],"launcher_exit":null,"method":"testCodexNeverEntersStatusItem","phase":"first",\#
"request_state":"app-observed","runner":{"path":"/fixture/attempt/derived-data/Build/Products/Debug/QuoternNativeUITests-Runner.app/Contents/MacOS/QuoternNativeUITests-Runner","pid":11,\#
"sec":100,"uid":501,"usec":1},"sequence":2,"stderr_rel":"native/testCodexNeverEntersStatusItem/first/application.stderr.log",\#
"stdout_rel":"native/testCodexNeverEntersStatusItem/first/application.stdout.log","v":1,"wrapper_rel":"wrappers/testCodexNeverEntersStatusItem.app"}

"""#
// native011-ownership-fixture:end

// native011-launch-binding:start
enum ProofFailure: Error {
    case workDeadline, childExited, ownerChanged, outputInventory, outputSentinel, unexpectedStorage
}

// Finite launch/binding emit seams; no catch-all aliases two of them.
enum Native011LaunchBoundary: String {
    case preexisting = "N011-L01", launcherStart = "N011-L02", launcherExit = "N011-L03", arrival = "N011-L04"
    case identity = "N011-L05", observerInstall = "N011-L06", unobservedExit = "N011-L07", waitStatus = "N011-L08"
    case readiness = "N011-L09", cancellation = "N011-L10", applicationCleanup = "N011-L11", launcherCleanup = "N011-L12"
    case pending = "N011-L13", publication = "N011-L14", bound = "N011-L15"
}

enum Native011Bounds {
    static let caseMs = 180_000, aggregateMs = 900_000, cleanupMs = 5_000
    static let arrivalMs = 60_000, readinessMs = 60_000, exitMs = 120_000, launcherExitMs = 10_000
    static let events = 256, outcomes = 32, retentionErrors = 16, primaryBytes = 4_096, diagnosticBytes = 65_536, receiptBytes = 16_384
    static let secondaryBytes = 16_384
}

let native011SafeCharacters = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-=[] ")

func native011Safe(_ text: String, limit: Int) -> String {
    String(text.prefix(limit).map { native011SafeCharacters.contains($0) ? $0 : "?" })
}

struct Native011LaunchFailure: Error {
    let boundary: String
    let stage: String
    let reason: String

    init(boundary: String, stage: String, reason: String) {
        self.boundary = native011Safe(boundary, limit: 40)
        self.stage = native011Safe(stage, limit: 40)
        self.reason = native011Safe(reason, limit: 80)
    }

    init(_ boundary: Native011LaunchBoundary, stage: String, reason: String) {
        self.init(boundary: boundary.rawValue, stage: stage, reason: reason)
    }
}

func native011FailureDiagnostic(_ error: Error) -> String {
    switch error {
    case let failure as Native011WrapperAdmissionFailure: return failure.rawValue
    case let failure as Native011LaunchFailure: return failure.boundary
    case ProofFailure.workDeadline: return "workDeadline"
    case ProofFailure.childExited: return "childExited"
    case ProofFailure.ownerChanged: return "ownerChanged"
    case ProofFailure.outputInventory: return "outputInventory"
    case ProofFailure.outputSentinel: return "outputSentinel"
    case ProofFailure.unexpectedStorage: return "unexpectedStorage"
    case is CancellationError: return "CancellationError()"
    default: return "native-proof-unclassified-failure"
    }
}

func native011Failure(_ error: Error, stage: String) -> Native011LaunchFailure {
    if let failure = error as? Native011LaunchFailure { return failure }
    if error is CancellationError { return Native011LaunchFailure(.cancellation, stage: stage, reason: "cancelled") }
    return Native011LaunchFailure(boundary: native011FailureDiagnostic(error), stage: stage, reason: "classified")
}

// Bounded redacted class of a launcher start error: only known domains keep their name; no message, path or user info.
// The result is stored in the 80-character failure reason, so both identities are compact and bounded: at most 67 characters.
func native011LaunchFailureDiagnostic(_ error: Error) -> String {
    let failure = error as NSError
    func identity(_ failure: NSError) -> String {
        let domains = [NSCocoaErrorDomain: "cocoa", NSPOSIXErrorDomain: "posix", NSOSStatusErrorDomain: "osstatus", NSMachErrorDomain: "mach"]
        return "\(domains[failure.domain] ?? "redacted"):\(max(-2_147_483_648, min(failure.code, 2_147_483_647)))"
    }
    var diagnostic = "launch primary=" + identity(failure)
    if let underlying = failure.userInfo[NSUnderlyingErrorKey] as? NSError { diagnostic += " underlying=" + identity(underlying) }
    return diagnostic
}

// MARK: strict JSON and the versioned owner receipt (native011-owner-v1)

enum Native011OwnerBoundary: String, Error {
    case size = "N011-S02-RECEIPT-SIZE", json = "N011-S03-RECEIPT-JSON", fields = "N011-S04-RECEIPT-FIELDS"
    case binding = "N011-S05-RECEIPT-BINDING", paths = "N011-S06-RECEIPT-PATHS", identity = "N011-S07-RECEIPT-IDENTITY"
    case exit = "N011-S08-EXIT-STATUS", state = "N011-S09-REQUEST-STATE", continuity = "N011-S10-RECEIPT-CONTINUITY"
}

indirect enum Native011JSON: Equatable {
    case null, bool(Bool), int(Int), string(String), array([Native011JSON]), object([String: Native011JSON])

    var object: [String: Native011JSON]? { if case .object(let value) = self { return value } else { return nil } }
    var array: [Native011JSON]? { if case .array(let value) = self { return value } else { return nil } }
    var intValue: Int? { if case .int(let value) = self { return value } else { return nil } }
    var stringValue: String? { if case .string(let value) = self { return value } else { return nil } }
    var isNull: Bool { if case .null = self { return true } else { return false } }

    static func parse(_ data: Data) throws -> Native011JSON {
        guard !data.isEmpty, data.count <= Native011Bounds.receiptBytes else { throw Native011OwnerBoundary.size }
        var parser = Native011JSONParser(bytes: [UInt8](data))
        return try parser.document()
    }

    // Compact, key-sorted, ASCII: byte-identical to the Python producer's json.dumps(sort_keys, separators).
    func encoded() -> String {
        switch self {
        case .null: return "null"
        case .bool(let value): return value ? "true" : "false"
        case .int(let value): return String(value)
        case .string(let value): return Native011JSON.quoted(value)
        case .array(let values): return "[" + values.map { $0.encoded() }.joined(separator: ",") + "]"
        case .object(let members):
            return "{" + members.keys.sorted().map { Native011JSON.quoted($0) + ":" + members[$0]!.encoded() }.joined(separator: ",") + "}"
        }
    }

    private static func quoted(_ text: String) -> String {
        var output = "\""
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 0x22: output += "\\\""
            case 0x5c: output += "\\\\"
            case 0x08: output += "\\b"
            case 0x0c: output += "\\f"
            case 0x0a: output += "\\n"
            case 0x0d: output += "\\r"
            case 0x09: output += "\\t"
            case 0..<0x20, 0x80...:
                func unit(_ value: UInt32) -> String { "\\u" + String(format: "%04x", value) }
                if scalar.value >= 0x10000 {
                    let offset = scalar.value - 0x10000
                    output += unit(0xd800 + (offset >> 10)) + unit(0xdc00 + (offset & 0x3ff))
                } else { output += unit(scalar.value) }
            default: output.unicodeScalars.append(scalar)
            }
        }
        return output + "\""
    }
}

struct Native011JSONParser {
    let bytes: [UInt8]
    var index = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func document() throws -> Native011JSON {
        let value = try parseValue(depth: 0)
        skipSpace()
        guard index == bytes.count else { throw Native011OwnerBoundary.json }
        return value
    }

    private mutating func skipSpace() {
        while index < bytes.count, [0x20, 0x0a, 0x0d, 0x09].contains(bytes[index]) { index += 1 }
    }

    private mutating func expect(_ byte: UInt8) throws {
        guard index < bytes.count, bytes[index] == byte else { throw Native011OwnerBoundary.json }
        index += 1
    }

    private mutating func parseValue(depth: Int) throws -> Native011JSON {
        guard depth <= 8 else { throw Native011OwnerBoundary.json }
        skipSpace()
        guard index < bytes.count else { throw Native011OwnerBoundary.json }
        switch bytes[index] {
        case UInt8(ascii: "{"): return try parseObject(depth: depth)
        case UInt8(ascii: "["): return try parseArray(depth: depth)
        case UInt8(ascii: "\""): return .string(try parseString())
        case UInt8(ascii: "n"): try literal("null"); return .null
        case UInt8(ascii: "t"): try literal("true"); return .bool(true)
        case UInt8(ascii: "f"): try literal("false"); return .bool(false)
        default: return try parseInteger()
        }
    }

    private mutating func literal(_ word: String) throws {
        let expected = Array(word.utf8)
        guard index + expected.count <= bytes.count, Array(bytes[index..<index + expected.count]) == expected else {
            throw Native011OwnerBoundary.json
        }
        index += expected.count
    }

    private mutating func parseInteger() throws -> Native011JSON {
        var end = index
        if end < bytes.count, bytes[end] == UInt8(ascii: "-") { end += 1 }
        let digits = end
        while end < bytes.count, (0x30...0x39).contains(bytes[end]) { end += 1 }
        guard end > digits, !(bytes[digits] == 0x30 && end - digits > 1) else { throw Native011OwnerBoundary.json }
        if end < bytes.count, [UInt8(ascii: "."), UInt8(ascii: "e"), UInt8(ascii: "E")].contains(bytes[end]) {
            throw Native011OwnerBoundary.json
        }
        guard let text = String(bytes: bytes[index..<end], encoding: .utf8), let value = Int(text) else {
            throw Native011OwnerBoundary.json
        }
        index = end
        return .int(value)
    }

    private mutating func hex4() throws -> UInt32 {
        guard index + 4 <= bytes.count, let text = String(bytes: bytes[index..<index + 4], encoding: .ascii),
              text.allSatisfy(\.isHexDigit), let value = UInt32(text, radix: 16) else { throw Native011OwnerBoundary.json }
        index += 4
        return value
    }

    private mutating func parseString() throws -> String {
        try expect(0x22)
        var output: [UInt8] = []
        while true {
            guard index < bytes.count else { throw Native011OwnerBoundary.json }
            let byte = bytes[index]
            index += 1
            switch byte {
            case 0x22:
                guard let text = String(bytes: output, encoding: .utf8) else { throw Native011OwnerBoundary.json }
                return text
            case 0x5c:
                guard index < bytes.count else { throw Native011OwnerBoundary.json }
                let escape = bytes[index]
                index += 1
                switch escape {
                case 0x22, 0x5c, 0x2f: output.append(escape)
                case UInt8(ascii: "b"): output.append(0x08)
                case UInt8(ascii: "f"): output.append(0x0c)
                case UInt8(ascii: "n"): output.append(0x0a)
                case UInt8(ascii: "r"): output.append(0x0d)
                case UInt8(ascii: "t"): output.append(0x09)
                case UInt8(ascii: "u"):
                    var value = try hex4()
                    if (0xd800...0xdbff).contains(value) {
                        try expect(0x5c)
                        try expect(UInt8(ascii: "u"))
                        let low = try hex4()
                        guard (0xdc00...0xdfff).contains(low) else { throw Native011OwnerBoundary.json }
                        value = 0x10000 + ((value - 0xd800) << 10) + (low - 0xdc00)
                    } else if (0xdc00...0xdfff).contains(value) { throw Native011OwnerBoundary.json }
                    guard let scalar = Unicode.Scalar(value) else { throw Native011OwnerBoundary.json }
                    output.append(contentsOf: Array(String(Character(scalar)).utf8))
                default: throw Native011OwnerBoundary.json
                }
            case 0..<0x20: throw Native011OwnerBoundary.json
            default: output.append(byte)
            }
        }
    }

    private mutating func parseArray(depth: Int) throws -> Native011JSON {
        try expect(UInt8(ascii: "["))
        var values: [Native011JSON] = []
        skipSpace()
        if index < bytes.count, bytes[index] == UInt8(ascii: "]") { index += 1; return .array(values) }
        while true {
            values.append(try parseValue(depth: depth + 1))
            skipSpace()
            guard index < bytes.count else { throw Native011OwnerBoundary.json }
            if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
            try expect(UInt8(ascii: "]"))
            return .array(values)
        }
    }

    private mutating func parseObject(depth: Int) throws -> Native011JSON {
        try expect(UInt8(ascii: "{"))
        var members: [String: Native011JSON] = [:]
        skipSpace()
        if index < bytes.count, bytes[index] == UInt8(ascii: "}") { index += 1; return .object(members) }
        while true {
            skipSpace()
            let key = try parseString()
            guard members[key] == nil else { throw Native011OwnerBoundary.json }
            skipSpace()
            try expect(UInt8(ascii: ":"))
            members[key] = try parseValue(depth: depth + 1)
            skipSpace()
            guard index < bytes.count else { throw Native011OwnerBoundary.json }
            if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
            try expect(UInt8(ascii: "}"))
            return .object(members)
        }
    }
}

struct Native011Identity: Equatable {
    let pid: Int, sec: Int, usec: Int, uid: Int, path: String
    var json: Native011JSON {
        .object(["pid": .int(pid), "sec": .int(sec), "usec": .int(usec), "uid": .int(uid), "path": .string(path)])
    }
    // Process facts only; the typed executable path stays in the ownership receipt, never in diagnostics.
    var facts: Native011JSON { .object(["pid": .int(pid), "sec": .int(sec), "usec": .int(usec), "uid": .int(uid)]) }
}

struct Native011ExitRecord: Equatable {
    let source: String
    let reason: String
    let status: Int
    let rawWaitStatus: Int?

    var json: Native011JSON {
        var members: [String: Native011JSON] = ["source": .string(source), "reason": .string(reason), "status": .int(status)]
        if let rawWaitStatus { members["raw_wait_status"] = .int(rawWaitStatus) }
        return .object(members)
    }

    // Decodes a wait(2) status from the kernel independently of the launcher's Process status.
    static func application(rawWaitStatus raw: Int) -> Native011ExitRecord? {
        guard (0...65_535).contains(raw) else { return nil }
        if raw & 127 == 0 {
            return Native011ExitRecord(source: "EVFILT_PROC_NOTE_EXITSTATUS", reason: "exit", status: (raw >> 8) & 255, rawWaitStatus: raw)
        }
        guard (1..<127).contains(raw & 127) else { return nil }
        return Native011ExitRecord(source: "EVFILT_PROC_NOTE_EXITSTATUS", reason: "uncaughtSignal", status: raw & 127, rawWaitStatus: raw)
    }

    static func launcher(reason: String, status: Int) -> Native011ExitRecord? {
        guard (reason == "exit" && (0...255).contains(status)) || (reason == "uncaughtSignal" && (1...126).contains(status)) else {
            return nil
        }
        return Native011ExitRecord(source: "Process", reason: reason, status: status, rawWaitStatus: nil)
    }
}

enum Native011RequestState: String {
    case prepared, issued, appObserved = "app-observed", appExited = "app-exited", closed, unknown
    var rank: Int {
        switch self {
        case .prepared: return 0
        case .issued: return 1
        case .appObserved: return 2
        case .appExited: return 3
        case .closed: return 4
        case .unknown: return 5
        }
    }
}

enum Native011Closure: String {
    case notRequested = "not-requested", pending, resolved, unknown
}

struct Native011ReceiptContext: Equatable {
    let attempt: String, method: String, phase: String, candidate: String, uid: Int

    var out: String { "\(attempt)/native/\(method)/\(phase)" }
    var wrapperRel: String { "wrappers/\(method).app" }
    var stdoutRel: String { "native/\(method)/\(phase)/application.stdout.log" }
    var stderrRel: String { "native/\(method)/\(phase)/application.stderr.log" }
    var wrapperPath: String { "\(attempt)/\(wrapperRel)" }
    var applicationPath: String { wrapperPath + "/Contents/MacOS/Quotern" }
    var runnerPath: String {
        "\(attempt)/derived-data/Build/Products/Debug/QuoternNativeUITests-Runner.app/Contents/MacOS/QuoternNativeUITests-Runner"
    }
    var journeyArguments: [String] {
        ["--selftest-journey", "--selftest-home", "\(attempt)/fixtures/\(method)/home", "--data-dir", "\(attempt)/fixtures/\(method)/data",
         "--now", "2026-09-30T12:00:00Z", "--phase", phase, "--out", out]
    }
    // The one documented launcher: `open` with attempt-owned stdio and the exact frozen wrapper (23 entries with argv[0]).
    var argv: [String] {
        ["/usr/bin/open", "-n", "-W", "--stdin", "/dev/null", "--stdout", "\(out)/application.stdout.log",
         "--stderr", "\(out)/application.stderr.log", "-a", wrapperPath, "--args"] + journeyArguments
    }
}

struct Native011Receipt: Equatable {
    var version = 1
    let candidate: String, method: String, phase: String
    var sequence: Int
    var requestState: Native011RequestState
    let wrapperRel: String, stdoutRel: String, stderrRel: String
    let runner: Native011Identity
    var launcher: Native011Identity?
    var application: Native011Identity?
    var launcherArgv: [String]?
    var launcherExit: Native011ExitRecord?
    var applicationExit: Native011ExitRecord?
    var closure: Native011Closure

    var json: Native011JSON {
        .object([
            "v": .int(version), "candidate_sha256": .string(candidate), "method": .string(method), "phase": .string(phase),
            "sequence": .int(sequence), "request_state": .string(requestState.rawValue), "wrapper_rel": .string(wrapperRel),
            "stdout_rel": .string(stdoutRel), "stderr_rel": .string(stderrRel), "runner": runner.json,
            "launcher": launcher?.json ?? .null, "application": application?.json ?? .null,
            "launcher_argv": launcherArgv.map { .array($0.map { .string($0) }) } ?? .null,
            "launcher_exit": launcherExit?.json ?? .null, "application_exit": applicationExit?.json ?? .null,
            "closure": .string(closure.rawValue),
        ])
    }

    func encoded() -> Data { Data((json.encoded() + "\n").utf8) }

    private static func identity(_ value: Native011JSON?, path: String, uid: Int) throws -> Native011Identity? {
        guard let value else { throw Native011OwnerBoundary.identity }
        if value.isNull { return nil }
        guard let object = value.object, Set(object.keys) == ["pid", "sec", "usec", "uid", "path"],
              let pid = object["pid"]?.intValue, (1...Int(Int32.max)).contains(pid),
              let sec = object["sec"]?.intValue, sec >= 0,
              let usec = object["usec"]?.intValue, (0...999_999).contains(usec),
              let owner = object["uid"]?.intValue, owner == uid, object["path"]?.stringValue == path else {
            throw Native011OwnerBoundary.identity
        }
        return Native011Identity(pid: pid, sec: sec, usec: usec, uid: owner, path: path)
    }

    private static func exitRecord(_ value: Native011JSON?, application: Bool) throws -> Native011ExitRecord? {
        guard let value else { throw Native011OwnerBoundary.exit }
        if value.isNull { return nil }
        let keys: Set<String> = application ? ["source", "reason", "status", "raw_wait_status"] : ["source", "reason", "status"]
        guard let object = value.object, Set(object.keys) == keys,
              object["source"]?.stringValue == (application ? "EVFILT_PROC_NOTE_EXITSTATUS" : "Process"),
              let reason = object["reason"]?.stringValue, reason == "exit" || reason == "uncaughtSignal",
              let status = object["status"]?.intValue,
              (reason == "exit" ? 0...255 : 1...126).contains(status) else { throw Native011OwnerBoundary.exit }
        guard application else { return Native011ExitRecord(source: "Process", reason: reason, status: status, rawWaitStatus: nil) }
        guard let raw = object["raw_wait_status"]?.intValue, let decoded = Native011ExitRecord.application(rawWaitStatus: raw),
              decoded.reason == reason, decoded.status == status else { throw Native011OwnerBoundary.exit }
        return decoded
    }

    // The actual source decoder: strict bytes, exact fields, source/method/sequence binding, typed identities,
    // independently decoded exit evidence, request-state relations and monotone continuity.
    static func decode(_ data: Data, context: Native011ReceiptContext, previous: Native011Receipt? = nil) throws -> Native011Receipt {
        let value = try Native011JSON.parse(data)
        func need(_ condition: Bool, _ boundary: Native011OwnerBoundary) throws { if !condition { throw boundary } }
        let fields: Set<String> = ["v", "candidate_sha256", "method", "phase", "sequence", "request_state", "wrapper_rel", "stdout_rel",
                                   "stderr_rel", "runner", "launcher", "application", "launcher_argv", "launcher_exit",
                                   "application_exit", "closure"]
        guard let record = value.object, Set(record.keys) == fields else { throw Native011OwnerBoundary.fields }
        let sequence = record["sequence"]?.intValue ?? -1
        try need(record["v"]?.intValue == 1 && record["candidate_sha256"]?.stringValue == context.candidate &&
                 record["method"]?.stringValue == context.method && record["phase"]?.stringValue == context.phase &&
                 (0...256).contains(sequence), .binding)
        var argv: [String]?
        if let items = record["launcher_argv"]?.array {
            let strings = items.compactMap(\.stringValue)
            try need(strings.count == items.count, .paths)
            argv = strings
        } else { try need(record["launcher_argv"]?.isNull == true, .paths) }
        try need(record["wrapper_rel"]?.stringValue == context.wrapperRel && record["stdout_rel"]?.stringValue == context.stdoutRel &&
                 record["stderr_rel"]?.stringValue == context.stderrRel && (argv == nil || argv == context.argv), .paths)
        guard let runner = try identity(record["runner"], path: context.runnerPath, uid: context.uid) else {
            throw Native011OwnerBoundary.identity
        }
        let launcher = try identity(record["launcher"], path: "/usr/bin/open", uid: context.uid)
        let application = try identity(record["application"], path: context.applicationPath, uid: context.uid)
        let pids = [runner.pid] + [launcher?.pid, application?.pid].compactMap { $0 }
        try need(Set(pids).count == pids.count, .identity)
        let launcherExit = try exitRecord(record["launcher_exit"], application: false)
        let applicationExit = try exitRecord(record["application_exit"], application: true)
        try need(launcherExit == nil || launcher != nil, .exit)
        try need(applicationExit == nil || application != nil, .exit)
        guard let stateName = record["request_state"]?.stringValue, let state = Native011RequestState(rawValue: stateName),
              let closureName = record["closure"]?.stringValue, let closure = Native011Closure(rawValue: closureName) else {
            throw Native011OwnerBoundary.state
        }
        switch state {
        case .prepared:
            try need(closure == .notRequested && launcher == nil && application == nil && launcherExit == nil && applicationExit == nil, .state)
        case .issued:
            try need(closure == .pending && application == nil && applicationExit == nil, .state)
        case .appObserved:
            try need(closure == .pending && launcher != nil && application != nil && applicationExit == nil, .state)
        case .appExited:
            try need(closure == .pending && launcher != nil && applicationExit != nil, .state)
        case .closed:
            try need(closure == .resolved && launcherExit != nil && applicationExit != nil, .state)
        case .unknown:
            try need(closure == .unknown, .state)
        }
        if state != .prepared { try need(argv == context.argv, .paths) }
        let decoded = Native011Receipt(candidate: context.candidate, method: context.method, phase: context.phase, sequence: sequence,
                                       requestState: state, wrapperRel: context.wrapperRel, stdoutRel: context.stdoutRel,
                                       stderrRel: context.stderrRel, runner: runner, launcher: launcher, application: application,
                                       launcherArgv: argv, launcherExit: launcherExit, applicationExit: applicationExit, closure: closure)
        if let previous {
            try need(sequence >= previous.sequence && (sequence != previous.sequence || decoded == previous), .continuity)
            try need(previous.launcher == nil || launcher == previous.launcher, .continuity)
            try need(previous.application == nil || application == previous.application, .continuity)
            try need(previous.runner == runner, .continuity)
            try need(previous.launcherExit == nil || launcherExit == previous.launcherExit, .continuity)
            try need(previous.applicationExit == nil || applicationExit == previous.applicationExit, .continuity)
            try need(state.rank >= previous.requestState.rank, .continuity)
        }
        return decoded
    }
}
