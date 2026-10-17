import AppKit
import CryptoKit
import Darwin
import Foundation

#if NATIVE011_BINDING_SELF_CHECK
extension SelfCheck {
    // MARK: final evidence publication precedes deletion admission; the final secondary reaches the actual inventory and scan

    // The native test's own artifacts are supplied clean; every artifact a session retained stays the real file.
    func supplyNativeArtifacts(_ subject: Scenario) {
        for name in ["launch.json", "journey.json", "status.ax.json", "status.png", "Codex-panel.ax.json", "Codex-panel.png",
                     "application.stdout.log", "application.stderr.log"] {
            let contents = Native011RetainedOutput.emptyNames.contains(name) ? Data() : Data("clean".utf8)
            FileManager.default.createFile(atPath: subject.out.appendingPathComponent(name).path, contents: contents, attributes: [.posixPermissions: 0o600])
        }
    }

    // The actual source-owned inventory over one phase directory, with the exact file set the session itself derives.
    func retained(_ subject: Scenario) throws -> Set<URL> {
        let names = Native011RetainedOutput.phaseFiles(phase: subject.receipt.phase, fault: "refused-ok", cancelled: false, sessions: [subject.session])
        guard let resolved = realpath(subject.out.path, nil) else { throw ProofFailure.outputInventory }
        defer { free(resolved) }
        let directory = URL(fileURLWithPath: String(cString: resolved))
        return try Native011RetainedOutput.checked(in: directory, required: Set(names.map { directory.appendingPathComponent($0) }))
    }

    func listing(_ subject: Scenario) -> String {
        do { return try retained(subject).map(\.lastPathComponent).sorted().joined(separator: ",") } catch { return native011FailureDiagnostic(error) }
    }

    func verification(_ subject: Scenario) -> String {
        do { try Native011RetainedOutput.verify(try retained(subject)); return "admitted" } catch { return native011FailureDiagnostic(error) }
    }

    // The complete fixture output directory: the parent of the phase directory, resolved like the native fixture's.
    func outputRoot(_ subject: Scenario) throws -> URL {
        guard let resolved = realpath(subject.out.deletingLastPathComponent().path, nil) else { throw ProofFailure.outputInventory }
        defer { free(resolved) }
        return URL(fileURLWithPath: String(cString: resolved))
    }

    // The actual final consumer the native verifier calls (membership, receipt reconciliation, bytes) over the complete output.
    func finalOutputs(_ subject: Scenario, cleaned: Bool) throws {
        try Native011RetainedOutput.final(output: try outputRoot(subject), fault: "refused-ok", cancelled: false, cleaned: cleaned, sessions: [subject.session])
    }

    func finalVerdict(_ subject: Scenario, cleaned: Bool) -> String {
        do { try finalOutputs(subject, cleaned: cleaned); return "admitted" } catch { return native011FailureDiagnostic(error) }
    }

    func plantSentinel(_ subject: Scenario) throws {
        let url = subject.out.appendingPathComponent("secondary.json")
        guard let bytes = try? Data(contentsOf: url) else { return }
        try (bytes + Data(Native011RetainedOutput.sentinel.utf8)).write(to: url)
    }

    func finalization() async throws {
        let diagnosticRow = "N011-L14:diagnostic-replace:diagnostic-publication"
        let stuckPrimary = primaryBytes("N011-L09", "readiness", "proxy-or-status-item", elapsed: 60_100)
        let headStuck = "1 native testCodexNeverEntersStatusItem first candidate N011-L09:readiness:proxy-or-status-item:60100"
        let without = membership(secondary: false)
        let with = membership(secondary: true)

        // F1: the owners are resolved, the primary is verified and every channel is healthy through owner cleanup. Only the
        // final publication fails; the secondary it creates must exist before the scan, before deletion and before the
        // final verification, which are the actual source-owned inventory and byte scan.
        var armed = false
        let finalOnly = FaultOps { _, op, path, _ in armed && op == "rename" && path.hasSuffix("diagnostic.json") }
        let created = try scenario(ops: finalOnly.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("final.created-secondary.phase", "N011-L09", await run(created))
        supplyNativeArtifacts(created)
        var eligible = "none", atScan = "none", atRemove = "none"
        var atVerifications: [String] = []
        let createdRun = runDeferred(created, wrapper: { armed = true; eligible = String(created.session.mayDelete) },
                                     scan: { atScan = self.listing(created); try Native011RetainedOutput.verify(try self.retained(created)) },
                                     remove: { atRemove = String(created.file("secondary.json") != nil) },
                                     outputs: {
                                         atVerifications.append(self.listing(created))
                                         // The pre-deletion verification admits the clean bytes; the sentinel reaches the terminal one only.
                                         if atVerifications.count == 2 { try self.plantSentinel(created) }
                                         try self.finalOutputs(created, cleaned: self.deferredCleaned)
                                     })
        expect("final.created-secondary.eligible-and-order", "true wrapper,scan,outputs,remove,outputs,outputs", "\(eligible) \(createdRun.order.joined(separator: ","))")
        expect("final.created-secondary.scan-membership", with, atScan)
        expect("final.created-secondary.before-deletion", "true", atRemove)
        expect("final.created-secondary.predeletion-membership", with, atVerifications.first ?? "none")
        expect("final.created-secondary.final-membership", with, atVerifications.dropFirst().first ?? "none")
        expect("final.created-secondary.confirmed-membership", with, atVerifications.dropFirst(2).first ?? "none")
        expect("final.created-secondary.sentinel-rejected", true, createdRun.reports.contains("deferred-outputs: outputSentinel"))
        let createdRecord = secondaryRecord(created)
        expect("final.created-secondary.record", "\(headStuck) \(Array(repeating: diagnosticRow, count: 4).joined(separator: ",")) outputSentinel:deferred-outputs:classified",
               "\(createdRecord.head) \(createdRecord.errors.joined(separator: ",")) \(createdRecord.outcomes.joined(separator: ","))")
        // The same scan over the final bytes: clean admitted, planted sentinel and unexpectedly empty file refused.
        expect("final.created-secondary.clean-admitted", "admitted", verification(created))
        try Data().write(to: created.out.appendingPathComponent("secondary.json"))
        expect("final.created-secondary.empty-rejected", "outputInventory", verification(created))
        try Data(Native011RetainedOutput.sentinel.utf8).write(to: created.out.appendingPathComponent("secondary.json"))
        expect("final.created-secondary.planted-rejected", "outputSentinel", verification(created))

        // F1: the same final-only failure that also loses the secondary: deletion was eligible and must never happen.
        var armedLoss = false
        let finalLoss = FaultOps { _, op, path, _ in armedLoss && op == "rename" && (path.hasSuffix("diagnostic.json") || path.hasSuffix("secondary.json")) }
        let lostFinal = try scenario(ops: finalLoss.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("final.secondary-lost.phase", "N011-L09", await run(lostFinal))
        supplyNativeArtifacts(lostFinal)
        var eligibleLoss = "none", atScanLoss = "none", removals = 0
        let lostRun = runDeferred(lostFinal, wrapper: { armedLoss = true; eligibleLoss = String(lostFinal.session.mayDelete) },
                                  scan: { atScanLoss = self.listing(lostFinal) }, remove: { removals += 1 })
        expect("final.secondary-lost.eligible-before-final", "true", eligibleLoss)
        expect("final.secondary-lost.no-deletion", "0 wrapper,scan,outputs false none",
               "\(removals) \(lostRun.order.joined(separator: ",")) \(lostFinal.session.mayDelete) \(lostFinal.session.secondaryFile ?? "none")")
        expect("final.secondary-lost.reported", "true true",
               "\(lostRun.reports.contains("native retention error retained: N011-L14 secondary-replace")) \(lostRun.reports.contains { $0.contains("deletion withheld") })")
        expect("final.secondary-lost.disk", "true absent", "\(lostFinal.file("primary.json") == stuckPrimary) \(secondaryRecord(lostFinal).head)")
        expect("final.secondary-lost.membership", without, atScanLoss)

        // F2: every failure stage of the secondary publication, reached through the actual final publication. The first
        // primary stays byte-identical, the attribution is exact, the unverified secondary is never named and deletion is withheld.
        let siblings = secondaryLossStages()
        for (stage, onDisk, fails) in siblings {
            var live = false, publishing = false
            let faults = FaultOps { _, op, path, _ in
                guard live else { return false }
                if op == "rename", path.hasSuffix("diagnostic.json") { return true }
                if op == "open" {
                    if path.hasSuffix("secondary.json.tmp") { publishing = true } else if path.hasSuffix("secondary.json") { publishing = false }
                }
                return fails(op, path, publishing)
            }
            let sibling = try scenario(ops: faults.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
            expect("secondary.\(stage).phase", "N011-L09", await run(sibling))
            supplyNativeArtifacts(sibling)
            var before = "none"
            let siblingRun = runDeferred(sibling, wrapper: { live = true; before = String(sibling.session.mayDelete) })
            let record = secondaryRecord(sibling)
            expect("secondary.\(stage).first-primary", true, sibling.file("primary.json") == stuckPrimary)
            expect("secondary.\(stage).disk", onDisk ? "\(headStuck) \(diagnosticRow),\(diagnosticRow) true" : "absent  true",
                   "\(record.head) \(record.errors.joined(separator: ",")) \(sibling.file("secondary.json.tmp") == nil)")
            expect("secondary.\(stage).attribution", "\(diagnosticRow),\(diagnosticRow),N011-L14:secondary-\(stage):secondary-publication",
                   sibling.session.retention.errors.map { "\($0.boundary):\($0.stage):\($0.reason)" }.joined(separator: ","))
            expect("secondary.\(stage).deletion-withheld", "true none wrapper,scan,outputs false",
                   "\(before) \(sibling.session.secondaryFile ?? "none") \(siblingRun.order.joined(separator: ",")) \(sibling.session.mayDelete)")
            expect("secondary.\(stage).reported", "true true",
                   "\(siblingRun.reports.contains("native retention error retained: N011-L14 secondary-\(stage)")) \(siblingRun.reports.contains { $0.contains("deletion withheld") })")
            expect("secondary.\(stage).inventory", onDisk ? "outputInventory" : without, listing(sibling))
            // The actual consumer, after the loss: a renamed-but-unverified secondary is refused though the primary is not a cancellation.
            expect("secondary.\(stage).actual-consumer", onDisk ? "outputInventory" : "admitted", finalVerdict(sibling, cleaned: false))
        }
    }

    func membership(secondary: Bool) -> String {
        let base = "Codex-panel.ax.json,Codex-panel.png,application.stderr.log,application.stdout.log,diagnostic.json,journey.json,launch.json," +
            "ownership.json,primary-fallback.log,primary.json,status.ax.json,status.png"
        return secondary ? base.replacingOccurrences(of: "status.ax.json", with: "secondary.json,status.ax.json") : base
    }

    // Every failure stage of the secondary publication; `onDisk` names the stages that leave an unverified file behind.
    func secondaryLossStages() -> [(stage: String, onDisk: Bool, fails: (String, String, Bool) -> Bool)] {
        [
            ("create", false, { op, path, _ in op == "open" && path.hasSuffix("secondary.json.tmp") }),
            ("write", false, { op, path, _ in op == "write" && path.hasSuffix("secondary.json.tmp") }),
            ("file-sync", false, { op, path, _ in op == "fsync" && path.hasSuffix("secondary.json.tmp") }),
            ("close", false, { op, path, _ in op == "close" && path.hasSuffix("secondary.json.tmp") }),
            ("replace", false, { op, path, _ in op == "rename" && path.hasSuffix("secondary.json") }),
            ("directory-sync", true, { op, path, publishing in op == "fsync" && publishing && !path.hasSuffix(".tmp") }),
            ("readback", true, { op, path, _ in op == "read-short" && path.hasSuffix("secondary.json") }),
        ]
    }

    // MARK: terminal evidence: the final verification settles before the deletion admission, and any evidence it or the
    // later checks produce is verified once more against the actual membership and bytes, never assumed covered by the scan.

    func terminalEvidence() async throws {
        let diagnosticRow = "N011-L14:diagnostic-replace:diagnostic-publication"
        let stuckPrimary = primaryBytes("N011-L09", "readiness", "proxy-or-status-item", elapsed: 60_100)
        let headStuck = "1 native testCodexNeverEntersStatusItem first candidate N011-L09:readiness:proxy-or-status-item:60100"
        let without = membership(secondary: false)
        let with = membership(secondary: true)

        // Persistent diagnostic failure armed inside the first (pre-deletion) verification, with a healthy secondary.
        var armed = false
        let persistent = FaultOps { _, op, path, _ in armed && op == "rename" && path.hasSuffix("diagnostic.json") }
        let created = try scenario(ops: persistent.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("terminal.verify-created.phase", "N011-L09", await run(created))
        supplyNativeArtifacts(created)
        var removals = 0
        var seen: [String] = []
        let createdRun = runDeferred(created, remove: { removals += 1 }, outputs: {
            seen.append(self.listing(created))
            if seen.count == 1 { armed = true; throw ProofFailure.outputInventory }
            try self.finalOutputs(created, cleaned: self.deferredCleaned)
        })
        expect("terminal.verify-created.order-and-deletion", "wrapper,scan,outputs,outputs 0", "\(createdRun.order.joined(separator: ",")) \(removals)")
        expect("terminal.verify-created.membership", "\(without) | \(with)", seen.joined(separator: " | "))
        expect("terminal.verify-created.final-admitted", "admitted", verification(created))
        expect("terminal.verify-created.first-primary", true, created.file("primary.json") == stuckPrimary)
        let createdRecord = secondaryRecord(created)
        expect("terminal.verify-created.record", "\(headStuck) \(diagnosticRow),\(diagnosticRow) outputInventory:deferred-outputs:classified",
               "\(createdRecord.head) \(createdRecord.errors.joined(separator: ",")) \(createdRecord.outcomes.joined(separator: ","))")
        expect("terminal.verify-created.reported", "true true",
               "\(createdRun.reports.contains("deferred-outputs: outputInventory")) \(createdRun.reports.contains { $0.contains("deletion withheld") })")

        // The same failure at each secondary publication stage, before the deletion (arm at verification 1) and after it (arm at 2).
        for armAt in [1, 2] {
            for (stage, onDisk, fails) in secondaryLossStages() {
                let name = "terminal.\(armAt == 1 ? "lost" : "late-lost").\(stage)"
                var live = false, publishing = false
                let faults = FaultOps { _, op, path, _ in
                    guard live else { return false }
                    if op == "rename", path.hasSuffix("diagnostic.json") { return true }
                    if op == "open" {
                        if path.hasSuffix("secondary.json.tmp") { publishing = true } else if path.hasSuffix("secondary.json") { publishing = false }
                    }
                    return fails(op, path, publishing)
                }
                let sibling = try scenario(ops: faults.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
                expect("\(name).phase", "N011-L09", await run(sibling))
                supplyNativeArtifacts(sibling)
                var removed = 0
                var verifications: [String] = []
                let siblingRun = runDeferred(sibling, remove: { removed += 1 }, outputs: {
                    verifications.append(self.listing(sibling))
                    if verifications.count == armAt { live = true; throw ProofFailure.outputInventory }
                    try self.finalOutputs(sibling, cleaned: self.deferredCleaned)
                })
                // Before the deletion: the failing verification, the terminal one and, only when the unverified file stays on disk, a confirmation.
                // After it: the pre-deletion verification, the failing terminal one and the confirmation.
                let order = (armAt == 1 ? ["wrapper", "scan"] + Array(repeating: "outputs", count: onDisk ? 3 : 2)
                                        : ["wrapper", "scan", "outputs", "remove", "outputs", "outputs"]).joined(separator: ",")
                expect("\(name).order-and-deletion", "\(order) \(armAt - 1)", "\(siblingRun.order.joined(separator: ",")) \(removed)")
                let expectedSeen = armAt == 1 ? [without, onDisk ? "outputInventory" : without] + (onDisk ? ["outputInventory"] : [])
                                              : [without, without, onDisk ? "outputInventory" : without]
                expect("\(name).membership", expectedSeen.joined(separator: " | "), verifications.joined(separator: " | "))
                expect("\(name).first-primary", true, sibling.file("primary.json") == stuckPrimary)
                let secondaryRows = Array(repeating: ["\(diagnosticRow)", "\(diagnosticRow)", "N011-L14:secondary-\(stage):secondary-publication"], count: armAt == 1 && onDisk ? 2 : 1).flatMap { $0 }
                expect("\(name).attribution", secondaryRows.joined(separator: ","),
                       sibling.session.retention.errors.map { "\($0.boundary):\($0.stage):\($0.reason)" }.joined(separator: ","))
                expect("\(name).unverified-never-named", "none false \(onDisk ? headStuck : "absent") true",
                       "\(sibling.session.secondaryFile ?? "none") \(sibling.session.mayDelete) \(secondaryRecord(sibling).head) \(sibling.file("secondary.json.tmp") == nil)")
                expect("\(name).reported", "true \(armAt == 1) \(onDisk)",
                       "\(siblingRun.reports.contains("native retention error retained: N011-L14 secondary-\(stage)")) " +
                       "\(siblingRun.reports.contains { $0.contains("deletion withheld") }) " +
                       "\(siblingRun.reports.contains("deferred-outputs-final: outputInventory"))")
            }
        }

        try await terminalEvidenceAfterVerification(stuckPrimary: stuckPrimary, headStuck: headStuck, without: without, with: with)
    }

    func terminalEvidenceAfterVerification(stuckPrimary: Data, headStuck: String, without: String, with: String) async throws {
        // A late overrun found by the pre-deletion verification's own deadline check publishes through the same channels.
        var lateArmed = false
        let lateFaults = FaultOps { _, op, path, _ in lateArmed && op == "rename" && path.hasSuffix("diagnostic.json") }
        let late = try scenario(ops: lateFaults.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("terminal.deadline.phase", "N011-L09", await run(late))
        supplyNativeArtifacts(late)
        var lateRemovals = 0
        var lateSeen: [String] = []
        let lateRun = runDeferred(late, remove: { lateRemovals += 1 }, outputs: {
            lateSeen.append(self.listing(late))
            if lateSeen.count == 1 { lateArmed = true; late.platform.clock += 200_000 }
            try self.finalOutputs(late, cleaned: self.deferredCleaned)
        })
        let lateRecord = secondaryRecord(late)
        expect("terminal.deadline.order-and-deletion", "wrapper,scan,outputs,outputs 0 false", "\(lateRun.order.joined(separator: ",")) \(lateRemovals) \(late.session.mayDelete)")
        expect("terminal.deadline.membership", "\(without) | \(with)", lateSeen.joined(separator: " | "))
        expect("terminal.deadline.record", "\(headStuck) native-deadline:case:elapsed", "\(lateRecord.head) \(lateRecord.outcomes.joined(separator: ","))")
        expect("terminal.deadline.first-primary-and-report", "true true", "\(late.file("primary.json") == stuckPrimary) \(lateRun.reports.contains("case: native-deadline"))")

        // Evidence produced by the terminal verification after the deletion is verified once more, and that last
        // verification does not publish again: its own failure is reported only and the sentinel it finds stays on disk.
        var lastArmed = false
        let lastFaults = FaultOps { _, op, path, _ in lastArmed && op == "rename" && path.hasSuffix("diagnostic.json") }
        let last = try scenario(ops: lastFaults.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("terminal.confirmation.phase", "N011-L09", await run(last))
        supplyNativeArtifacts(last)
        var lastRemovals = 0
        var lastSeen: [String] = []
        let lastRun = runDeferred(last, remove: { lastRemovals += 1 }, outputs: {
            lastSeen.append(self.listing(last))
            switch lastSeen.count {
            case 2: lastArmed = true; throw ProofFailure.outputInventory
            case 3: try self.plantSentinel(last)
            default: break
            }
            try self.finalOutputs(last, cleaned: self.deferredCleaned)
        })
        expect("terminal.confirmation.order-and-deletion", "wrapper,scan,outputs,remove,outputs,outputs 1", "\(lastRun.order.joined(separator: ",")) \(lastRemovals)")
        expect("terminal.confirmation.membership", "\(without) | \(without) | \(with)", lastSeen.joined(separator: " | "))
        expect("terminal.confirmation.reported", "true true", "\(lastRun.reports.contains("deferred-outputs: outputInventory")) \(lastRun.reports.contains("deferred-outputs-final: outputSentinel"))")
        expect("terminal.confirmation.not-republished", "outputSentinel", verification(last))
        expect("terminal.confirmation.first-primary", true, last.file("primary.json") == stuckPrimary)
    }

    // An overrun the confirming verification itself runs into is published after the last verification: it is reported as
    // unverified and nothing verifies it again, so the evidence is never claimed as covered and no further loop starts.
    func terminalUnverified() async throws {
        var armed = false
        let faults = FaultOps { _, op, path, _ in armed && op == "rename" && path.hasSuffix("diagnostic.json") }
        let slow = try scenario(ops: faults.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("terminal.unverified.phase", "N011-L09", await run(slow))
        supplyNativeArtifacts(slow)
        var removals = 0
        var seen: [String] = []
        let slowRun = runDeferred(slow, remove: { removals += 1 }, outputs: {
            seen.append(self.listing(slow))
            switch seen.count {
            case 2: armed = true; throw ProofFailure.outputInventory
            case 3: slow.platform.clock += 200_000
            default: break
            }
            try self.finalOutputs(slow, cleaned: self.deferredCleaned)
        })
        let record = secondaryRecord(slow)
        expect("terminal.unverified.order-and-deletion", "wrapper,scan,outputs,remove,outputs,outputs 1", "\(slowRun.order.joined(separator: ",")) \(removals)")
        expect("terminal.unverified.membership", "\(membership(secondary: false)) | \(membership(secondary: false)) | \(membership(secondary: true))", seen.joined(separator: " | "))
        expect("terminal.unverified.reported", "true true false",
               "\(slowRun.reports.contains("terminal evidence published after the last output verification is unverified")) " +
               "\(slowRun.reports.contains("case: native-deadline")) \(slowRun.reports.contains { $0.hasPrefix("deferred-outputs-final") })")
        expect("terminal.unverified.record", "native-deadline:case:elapsed", record.outcomes.filter { $0.hasPrefix("native-deadline") }.joined(separator: ","))
    }

    // MARK: the persisted sink-inventory receipt follows the final evidence; its names and bucket counts are read back from disk

    // What the native scan writes: the files present when it ran (no evidence the final steps produce yet) and its bucket counts.
    func scanReceipt(_ subject: Scenario) throws {
        let root = try outputRoot(subject)
        let required = Native011RetainedOutput.requiredFiles(output: root, fault: "refused-ok", cancelled: false, cleaned: false, sessions: [subject.session])
        var buckets = ["data-directory files": 1, "UserDefaults domain": 1, "wrapper": 3]
        for url in required where !Native011RetainedOutput.receiptNames.contains(url.lastPathComponent) {
            buckets[Native011RetainedOutput.bucket(url), default: 0] += 1
        }
        for name in ["defaults.plist", "data-absence.json"] { try Data("clean".utf8).write(to: root.appendingPathComponent(name)) }
        try Native011RetainedOutput.receipt(files: required, buckets: buckets, cancelled: false).write(to: root.appendingPathComponent("sink-inventory.json"))
    }

    func cleanupLog(_ subject: Scenario) throws {
        try Data("owned fixture/default cleanup completed\n".utf8).write(to: try outputRoot(subject).appendingPathComponent("cleanup.log"))
    }

    // Independent readback of the persisted receipt: names relative to the output root as stored, bucket counts sorted by key.
    func persistedReceipt(_ subject: Scenario) -> (files: String, buckets: String) {
        guard let root = try? outputRoot(subject), let data = try? Data(contentsOf: root.appendingPathComponent("sink-inventory.json")),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let files = object["files"] as? [String], let buckets = object["buckets"] as? [String: Int] else { return ("unreadable", "unreadable") }
        let prefix = root.path + "/"
        return (files.map { $0.hasPrefix(prefix) ? String($0.dropFirst(prefix.count)) : $0 }.joined(separator: ","),
                buckets.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ","))
    }

    // Independent walk of the output directory, not the actual inventory code.
    func diskNames(_ subject: Scenario) -> String {
        guard let root = try? outputRoot(subject), let walker = FileManager.default.enumerator(atPath: root.path) else { return "unreadable" }
        var names: [String] = []
        for case let name as String in walker {
            var directory: ObjCBool = false
            if FileManager.default.fileExists(atPath: root.appendingPathComponent(name).path, isDirectory: &directory), !directory.boolValue { names.append(name) }
        }
        return names.sorted().joined(separator: ",")
    }

    // Literal expectations: the complete fixture output for the fixed first-phase evidence set.
    func receiptNames(primary: Bool = true, secondary: Bool = false, cleanup: Bool = false) -> String {
        var top = ["data-absence.json", "defaults.plist", "sink-inventory.json"]
        var phase = ["Codex-panel.ax.json", "Codex-panel.png", "application.stderr.log", "application.stdout.log", "diagnostic.json", "journey.json",
                     "launch.json", "ownership.json", "primary-fallback.log", "status.ax.json", "status.png"]
        if primary { phase.append("primary.json") }
        if secondary { phase.append("secondary.json") }
        if cleanup { top.append("cleanup.log") }
        return (top + phase.map { "first/" + $0 }).sorted().joined(separator: ",")
    }

    func receiptBuckets(diagnostics: Int) -> String {
        "UserDefaults domain=1,accessibility tree=2,data-directory files=1,diagnostics=\(diagnostics),native captures=2,self-test journey.json=1,wrapper=3"
    }

    func persistedInventory() async throws {
        // A secondary created after the scan, with the deletion withheld: the receipt names it and counts it, and claims no cleanup file.
        var armed = false
        let persistent = FaultOps { _, op, path, _ in armed && op == "rename" && path.hasSuffix("diagnostic.json") }
        let created = try scenario(ops: persistent.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("inventory.created.phase", "N011-L09", await run(created))
        supplyNativeArtifacts(created)
        var removals = 0, calls = 0
        let createdRun = runDeferred(created, scan: { try self.scanReceipt(created) }, remove: { removals += 1 }, outputs: {
            calls += 1
            if calls == 1 { armed = true; throw ProofFailure.outputInventory }
            try self.finalOutputs(created, cleaned: self.deferredCleaned)
        })
        expect("inventory.created.order-and-deletion", "wrapper,scan,outputs,outputs 0 true", "\(createdRun.order.joined(separator: ",")) \(removals) \(created.session.mayDelete)")
        let createdReceipt = persistedReceipt(created)
        expect("inventory.created.names", receiptNames(secondary: true), createdReceipt.files)
        expect("inventory.created.buckets", receiptBuckets(diagnostics: 8), createdReceipt.buckets)
        expect("inventory.created.matches-disk", diskNames(created), createdReceipt.files)
        // A native artifact the failing journey never produced may be absent; a registered secondary never.
        try FileManager.default.removeItem(at: created.out.appendingPathComponent("status.png"))
        expect("inventory.created.absent-native-artifact", "admitted", finalVerdict(created, cleaned: false))
        let thinner = persistedReceipt(created)
        expect("inventory.created.absent-native-artifact.names", receiptNames(secondary: true).replacingOccurrences(of: "first/status.png,", with: ""), thinner.files)
        expect("inventory.created.absent-native-artifact.buckets", receiptBuckets(diagnostics: 8).replacingOccurrences(of: "native captures=2", with: "native captures=1"), thinner.buckets)
        try FileManager.default.removeItem(at: created.out.appendingPathComponent("secondary.json"))
        expect("inventory.created.registered-secondary-required", "N011-L09 secondary.json outputInventory",
               "\(created.primary) \(created.session.secondaryFile ?? "none") \(finalVerdict(created, cleaned: false))")

        // The deletion completes: the cleanup file appears only then and the terminal verification claims it.
        let deleted = try scenario(configure: { platform, _ in platform.proxy = [.unavailable] })
        expect("inventory.deleted.phase", "N011-L09", await run(deleted))
        supplyNativeArtifacts(deleted)
        var before = ("none", "none")
        let deletedRun = runDeferred(deleted, scan: { try self.scanReceipt(deleted) },
                                     remove: { before = self.persistedReceipt(deleted); try self.cleanupLog(deleted) },
                                     outputs: { try self.finalOutputs(deleted, cleaned: self.deferredCleaned) })
        expect("inventory.deleted.order", "wrapper,scan,outputs,remove,outputs 0", "\(deletedRun.order.joined(separator: ",")) \(deletedRun.reports.count)")
        expect("inventory.deleted.before-deletion", "\(receiptNames()) \(receiptBuckets(diagnostics: 7))", "\(before.0) \(before.1)")
        let deletedReceipt = persistedReceipt(deleted)
        expect("inventory.deleted.names", receiptNames(cleanup: true), deletedReceipt.files)
        expect("inventory.deleted.buckets", receiptBuckets(diagnostics: 8), deletedReceipt.buckets)
        expect("inventory.deleted.matches-disk", diskNames(deleted), deletedReceipt.files)
        // A receipt that cannot be parsed or that describes another kind of case is refused, never silently replaced.
        let receiptURL = try outputRoot(deleted).appendingPathComponent("sink-inventory.json")
        try Data("not json".utf8).write(to: receiptURL)
        expect("inventory.deleted.unparsable-rejected", "outputInventory", finalVerdict(deleted, cleaned: true))
        try Data("{\"buckets\":{},\"cancelled\":true,\"files\":[]}".utf8).write(to: receiptURL)
        expect("inventory.deleted.wrong-kind-rejected", "outputInventory", finalVerdict(deleted, cleaned: true))

        // Without a primary the membership is exact: an extra or a missing file is refused.
        let strict = try scenario()
        expect("inventory.strict.phase", "pass", await run(strict))
        supplyNativeArtifacts(strict)
        let strictRun = runDeferred(strict, scan: { try self.scanReceipt(strict) }, remove: { try self.cleanupLog(strict) },
                                    outputs: { try self.finalOutputs(strict, cleaned: self.deferredCleaned) })
        expect("inventory.strict.order", "wrapper,scan,outputs,remove,outputs 0", "\(strictRun.order.joined(separator: ",")) \(strictRun.reports.count)")
        let strictReceipt = persistedReceipt(strict)
        expect("inventory.strict.names", receiptNames(primary: false, cleanup: true), strictReceipt.files)
        expect("inventory.strict.buckets", receiptBuckets(diagnostics: 7), strictReceipt.buckets)
        try Data("x".utf8).write(to: strict.out.appendingPathComponent("extra.log"))
        expect("inventory.strict.extra-rejected", "outputInventory", finalVerdict(strict, cleaned: true))
        try FileManager.default.removeItem(at: strict.out.appendingPathComponent("extra.log"))
        try FileManager.default.removeItem(at: strict.out.appendingPathComponent("status.png"))
        expect("inventory.strict.missing-rejected", "outputInventory", finalVerdict(strict, cleaned: true))
    }

    // MARK: a secondary that fails its first publication or replaces a verified one

    // `failAt` is the first secondary publication that fails: 1 is the initial one, 2 replaces the verified file. The first publication is
    // carried by the failing deferred wrapper step and the second by the final publication, both through the actual deferred cleanup. A
    // failure before the rename leaves the earlier verified file registered and intact; one after it leaves a file that is not verified and
    // the actual final consumer refuses it.
    func secondaryReplacement() async throws {
        let diagnosticRow = "N011-L14:diagnostic-replace:diagnostic-publication"
        let headStuck = "1 native testCodexNeverEntersStatusItem first candidate N011-L09:readiness:proxy-or-status-item:60100"
        let stuckPrimary = primaryBytes("N011-L09", "readiness", "proxy-or-status-item", elapsed: 60_100)
        for failAt in [1, 2] {
            for (stage, onDisk, fails) in secondaryLossStages() {
                let name = "replacement.\(failAt == 1 ? "initial" : "verified").\(stage)"
                let kept = failAt == 2 && !onDisk
                var live = false, publishing = false, publications = 0
                let faults = FaultOps { _, op, path, _ in
                    guard live else { return false }
                    if op == "rename", path.hasSuffix("diagnostic.json") { return true }
                    if op == "open" {
                        if path.hasSuffix("secondary.json.tmp") { publishing = true; publications += 1 } else if path.hasSuffix("secondary.json") { publishing = false }
                    }
                    return publications >= failAt && fails(op, path, publishing)
                }
                let sibling = try scenario(ops: faults.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
                expect("\(name).phase", "N011-L09", await run(sibling))
                supplyNativeArtifacts(sibling)
                var removals = 0
                let result = runDeferred(sibling, wrapper: { live = true; throw ProofFailure.outputInventory }, remove: { removals += 1 },
                                         outputs: { try self.finalOutputs(sibling, cleaned: self.deferredCleaned) })
                let record = secondaryRecord(sibling)
                expect("\(name).first-primary", true, sibling.file("primary.json") == stuckPrimary)
                expect("\(name).registered", kept ? "secondary.json" : "none", sibling.session.secondaryFile ?? "none")
                expect("\(name).on-disk", kept ? "\(headStuck) \(diagnosticRow),\(diagnosticRow)" : (onDisk ? headStuck : "absent"),
                       kept ? "\(record.head) \(record.errors.joined(separator: ","))" : record.head)
                expect("\(name).tmp-absent", true, sibling.file("secondary.json.tmp") == nil)
                let lost = (failAt == 1 ? 2 : 1) + (onDisk ? 1 : 0)
                expect("\(name).attribution", Array(repeating: "N011-L14:secondary-\(stage):secondary-publication", count: lost).joined(separator: ","),
                       sibling.session.retention.errors.filter { $0.stage.hasPrefix("secondary-") }.map { "\($0.boundary):\($0.stage):\($0.reason)" }.joined(separator: ","))
                expect("\(name).deletion-withheld", "0 false true", "\(removals) \(sibling.session.mayDelete) \(result.reports.contains { $0.contains("deletion withheld") })")
                expect("\(name).inventory", kept ? membership(secondary: true) : (onDisk ? "outputInventory" : membership(secondary: false)), listing(sibling))
                expect("\(name).actual-consumer", "\(onDisk ? "outputInventory" : "admitted") \(onDisk)",
                       "\(finalVerdict(sibling, cleaned: false)) \(result.reports.contains("deferred-outputs: outputInventory"))")
            }
        }
    }

    // MARK: the receipt as stored is scanned before the final consumer rewrites it, and the rewrite is scanned as well

    func receiptPrivacy() async throws {
        let sentinel = Native011RetainedOutput.sentinel
        let variants: [(name: String, receipt: String, verdict: String)] = [
            ("files", "{\"buckets\":{\"diagnostics\":1},\"cancelled\":false,\"files\":[\"\(sentinel)\"]}", "outputSentinel"),
            ("unknown-field", "{\"buckets\":{\"diagnostics\":1},\"cancelled\":false,\"files\":[],\"note\":\"\(sentinel)\"}", "outputSentinel"),
            ("malformed-files", "{\"buckets\":{\"diagnostics\":1},\"cancelled\":false,\"files\":7}", "outputInventory"),
        ]
        for (name, receipt, verdict) in variants {
            let subject = try scenario()
            expect("receipt.\(name).phase", "pass", await run(subject))
            supplyNativeArtifacts(subject)
            let planted = Data(receipt.utf8)
            var removals = 0, calls = 0
            let result = runDeferred(subject, scan: { try self.scanReceipt(subject) }, remove: { removals += 1; try self.cleanupLog(subject) }, outputs: {
                calls += 1
                if calls == 1 { try planted.write(to: self.outputRoot(subject).appendingPathComponent("sink-inventory.json")) }
                try self.finalOutputs(subject, cleaned: self.deferredCleaned)
            })
            expect("receipt.\(name).rejected-and-not-deleted", "true 0", "\(result.reports.contains("deferred-outputs: \(verdict)")) \(removals)")
            expect("receipt.\(name).preimage-kept", true, (try? Data(contentsOf: outputRoot(subject).appendingPathComponent("sink-inventory.json"))) == planted)
            expect("receipt.\(name).actual-consumer", verdict, finalVerdict(subject, cleaned: false))
        }

        // A stored receipt that is clean while its rewrite names the sentinel (here through the output path) is refused too.
        let unresolved = root.appendingPathComponent("s-\(sentinel)")
        try FileManager.default.createDirectory(at: unresolved, withIntermediateDirectories: true)
        guard let resolved = realpath(unresolved.path, nil) else { throw ProofFailure.outputInventory }
        defer { free(resolved) }
        let tainted = URL(fileURLWithPath: String(cString: resolved))
        for url in Native011RetainedOutput.requiredFiles(output: tainted, fault: "withheld-readiness", cancelled: false, cleaned: false, sessions: []) {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try (Native011RetainedOutput.emptyNames.contains(url.lastPathComponent) ? Data() : Data("clean".utf8)).write(to: url)
        }
        try Data("{\"buckets\":{},\"cancelled\":false,\"files\":[]}".utf8).write(to: tainted.appendingPathComponent("sink-inventory.json"))
        var rewritten = "admitted"
        do { try Native011RetainedOutput.final(output: tainted, fault: "withheld-readiness", cancelled: false, cleaned: false, sessions: []) }
        catch { rewritten = native011FailureDiagnostic(error) }
        expect("receipt.rewrite-scanned", "outputSentinel", rewritten)
    }

    // MARK: successful runs: the persisted receipt follows the same final evidence for the positive pair and the cancellation control

    func successInventory(cancelled: Bool) async throws {
        let name = cancelled ? "inventory.cancelled" : "inventory.positive"
        // Literal expectations, independent of the actual inventory code.
        let base = ["application.stderr.log", "application.stdout.log", "diagnostic.json", "journey.json", "launch.json", "ownership.json",
                    "primary-fallback.log", "status.ax.json", "status.png"]
        let panel = ["Codex-panel.ax.json", "Codex-panel.png"]
        let observed = ["checkpoint.json", "observed-popover.ax.json", "observed-popover.png"]
        let opencode = ["OpenCode-panel.ax.json", "OpenCode-panel.png"]
        let layout: [(phase: String, files: [String])] = cancelled
            ? [("first", base + panel + observed + ["ownership-control.json", "primary.json"])]
            : [("first", base + panel + observed + ["popover.png"] + opencode), ("restart", base + ["popover.png"])]
        let top = cancelled ? ["data-absence.json", "defaults.plist", "sink-inventory.json"] : ["defaults.plist", "sink-inventory.json"]
        func names(cleaned: Bool) -> [String] {
            (top + layout.flatMap { entry in entry.files.map { entry.phase + "/" + $0 } } + (cleaned ? ["cleanup.log"] : [])).sorted()
        }
        // The output buckets the scan counted, and the data-directory, defaults and wrapper sinks it counted outside the output directory.
        func buckets(cleaned: Bool) -> [String: Int] {
            var result = ["UserDefaults domain": 2, "data-directory files": 5, "wrapper": 7,
                          "accessibility tree": cancelled ? 3 : 5, "native captures": cancelled ? 3 : 5,
                          "self-test journey.json": cancelled ? 2 : 3, "diagnostics": (cancelled ? 8 : 12) + (cleaned ? 1 : 0)]
            if !cancelled { result["self-test popover.png"] = 2 }
            return result
        }
        func text(_ counts: [String: Int]) -> String { counts.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ",") }

        let first = try scenario()
        var scenarios = [first]
        if !cancelled { scenarios.append(try scenario(phase: "restart", sharing: first)) }
        if cancelled {
            _ = await run(first, body: { try first.session.input { throw CancellationError() } })
            expect("\(name).phase", "N011-L10", first.primary)
        } else {
            for subject in scenarios { expect("\(name).\(subject.receipt.phase).phase", "pass", await run(subject)) }
        }
        // The native test's own artifacts: every expected name that no session produced.
        let owned: Set = ["application.stderr.log", "application.stdout.log", "diagnostic.json", "ownership.json", "primary-fallback.log", "primary.json"]
        for (subject, entry) in zip(scenarios, layout) {
            for file in entry.files where !owned.contains(file) {
                FileManager.default.createFile(atPath: subject.out.appendingPathComponent(file).path, contents: Data("clean".utf8), attributes: [.posixPermissions: 0o600])
            }
        }
        let root = try outputRoot(first)
        var before = ("none", "none")
        var removals = 0
        let result = runDeferred(first, with: Array(scenarios.dropFirst()), scan: {
            for file in top where file != "sink-inventory.json" { try Data("clean".utf8).write(to: root.appendingPathComponent(file)) }
            let stored: [String: Any] = ["files": names(cleaned: false).map { root.path + "/" + $0 }, "buckets": buckets(cleaned: false), "cancelled": cancelled]
            try JSONSerialization.data(withJSONObject: stored, options: [.sortedKeys]).write(to: root.appendingPathComponent("sink-inventory.json"))
        }, remove: {
            removals += 1
            before = self.persistedReceipt(first)
            try self.cleanupLog(first)
        }, outputs: {
            try Native011RetainedOutput.final(output: root, fault: nil, cancelled: cancelled, cleaned: self.deferredCleaned, sessions: scenarios.map(\.session))
        })
        expect("\(name).order-and-deletion", "wrapper,scan,outputs,remove,outputs 0 1", "\(result.order.joined(separator: ",")) \(result.reports.count) \(removals)")
        expect("\(name).before-deletion", "\(names(cleaned: false).joined(separator: ",")) \(text(buckets(cleaned: false)))", "\(before.0) \(before.1)")
        let after = persistedReceipt(first)
        expect("\(name).after-deletion", "\(names(cleaned: true).joined(separator: ",")) \(text(buckets(cleaned: true)))", "\(after.files) \(after.buckets)")
        expect("\(name).matches-disk", diskNames(first), after.files)
    }

    // MARK: independent fail-closed branches of the fallback channel after successful preparation

    func fallbackFailClosed() async throws {
        let branches: [(name: String, stage: String, fails: (FaultOps, String, String, Int) -> Bool)] = [
            ("sync", "fallback-sync", { _, op, path, count in op == "fsync" && path.hasSuffix("primary-fallback.log") && count == 2 }),
            ("readback-open", "fallback-readback", { _, op, path, count in op == "open" && path.hasSuffix("primary-fallback.log") && count == 3 }),
            ("readback-short", "fallback-readback", { _, op, path, count in op == "read-short" && path.hasSuffix("primary-fallback.log") && count == 2 }),
            ("readback-drift", "fallback-readback", { _, op, path, count in op == "read-drift" && path.hasSuffix("primary-fallback.log") && count == 2 }),
        ]
        for (name, stage, branch) in branches {
            let faults = FaultOps { faults, op, path, count in
                (op == "open" && path.hasSuffix("primary.json.tmp")) || branch(faults, op, path, count)
            }
            let subject = try scenario(ops: faults.ops, configure: { platform, _ in platform.proxy = [.unavailable] })
            expect("fallback.\(name).result", "N011-L09", await run(subject))
            let primary = subject.session.retention.primary
            expect("fallback.\(name).original-primary", "N011-L09 readiness proxy-or-status-item", "\(primary?.boundary ?? "none") \(primary?.stage ?? "none") \(primary?.reason ?? "none")")
            let errors = subject.session.retention.errors.map { "\($0.boundary):\($0.stage):\($0.reason)" }.joined(separator: ",")
            expect("fallback.\(name).attribution", "N011-L14:primary-create:primary-publication,N011-L14:\(stage):fallback-publication", errors)
            expect("fallback.\(name).unknown-closed", "unknown closed N011-L10", "\(subject.session.retention.disposition.rawValue) \(subject.session.admission.rawValue) \(inputOutcome(subject))")
            subject.session.cleanup()
            let deferred = runDeferred(subject)
            expect("fallback.\(name).no-signals-no-scan-no-deletion", "0 0 false false wrapper,outputs",
                   "\(subject.app.terminations) \(subject.platform.launcher?.terminations ?? -1) \(subject.session.mayScan) \(subject.session.mayDelete) \(deferred.order.joined(separator: ","))")
            expect("fallback.\(name).unresolved", "app-observed app[nil] launcher[nil] true", "\(subject.summary) \(subject.file("primary.json") == nil)")
        }
    }

    // MARK: cancellation primaries are durable and exact at the first cleanup effect of each owner

    func cancellationFirstEffect() async throws {
        var appSnapshot: Data?, launcherSnapshot: Data?
        var appSignals = 0, launcherSignals = 0
        var location: URL?
        // `owners` is the scenario's literal expectation: which owner is signalled at all, and that its first signal found the exact record.
        func exact(_ name: String, _ subject: Scenario, expected: Data, owners: String) {
            func seen(_ signals: Int, _ snapshot: Data?) -> String { signals == 0 ? "unused" : (snapshot == expected ? "exact" : "wrong") }
            expect("cancel-effect.\(name).primary-at-first-signals", owners, "\(seen(appSignals, appSnapshot)) \(seen(launcherSignals, launcherSnapshot))")
            expect("cancel-effect.\(name).primary-after-cleanup", true, subject.file("primary.json") == expected)
        }
        func probe(_ platform: ScriptedPlatform, _ app: ScriptedApp) {
            app.onSignal = {
                appSignals += 1
                if appSnapshot == nil, let location { appSnapshot = try? Data(contentsOf: location.appendingPathComponent("primary.json")) }
            }
            platform.launcherTerminateProbe = {
                launcherSignals += 1
                if launcherSnapshot == nil, let location { launcherSnapshot = try? Data(contentsOf: location.appendingPathComponent("primary.json")) }
            }
        }
        func reset() { appSnapshot = nil; launcherSnapshot = nil; appSignals = 0; launcherSignals = 0 }

        // Cancelled while the launch is unresolved: only the launcher can be signalled first.
        reset()
        var launchRaised = -1
        let launch = try scenario(configure: { platform, app in
            probe(platform, app)
            platform.workCheckHook = { if platform.log.contains("launcher-start") { launchRaised = platform.clock; throw CancellationError() } }
        })
        location = launch.out
        _ = await run(launch)
        launch.session.cleanup()
        exact("launch", launch, expected: primaryBytes("N011-L10", "phase", "cancelled", elapsed: launchRaised), owners: "unused exact")

        // Cancelled during readiness: application first, launcher after it; a refused application signal is a secondary failure.
        for refused in [false, true] {
            reset()
            var raised = -1
            let ready = try scenario(configure: { platform, app in
                probe(platform, app)
                app.terminateRefused = refused
                platform.proxy = [.unavailable]
                platform.workCheckHook = { if platform.proxyCalls >= 2 { if raised < 0 { raised = platform.clock }; throw CancellationError() } }
            })
            location = ready.out
            _ = await run(ready)
            ready.session.cleanup()
            let name = refused ? "readiness-refused" : "readiness"
            exact(name, ready, expected: primaryBytes("N011-L10", "phase", "cancelled", elapsed: raised), owners: refused ? "exact exact" : "exact unused")
            expect("cancel-effect.\(name).secondary", refused ? "true" : "false", String(ready.session.retention.outcomes.contains { $0.boundary == "N011-L11" }))
        }

        reset()
        var inputRaised = -1
        let input = try scenario(configure: { platform, app in probe(platform, app) })
        location = input.out
        _ = await run(input, body: { try input.session.input { inputRaised = input.platform.clock; throw CancellationError() } })
        input.session.cleanup()
        exact("input", input, expected: primaryBytes("N011-L10", "phase", "cancelled", elapsed: inputRaised), owners: "exact unused")

        reset()
        var teardownRaised = -1
        let teardown = try scenario(configure: { platform, app in
            probe(platform, app)
            platform.workCheckHook = { if platform.log.contains("input") { if teardownRaised < 0 { teardownRaised = platform.clock }; throw CancellationError() } }
        })
        location = teardown.out
        _ = await run(teardown)
        teardown.session.cleanup()
        exact("teardown", teardown, expected: primaryBytes("N011-L10", "phase", "cancelled", elapsed: teardownRaised), owners: "exact unused")

        reset()
        var explicitAt = -1
        var reopening: Native011LaunchSession?
        let explicit = try scenario(configure: { platform, app in
            probe(platform, app)
            app.isFinishedLaunching = false
            platform.pauseHook = { platform in
                guard platform.clock >= 200, explicitAt < 0 else { return }
                explicitAt = platform.clock
                app.isFinishedLaunching = true
                reopening?.cancel(stage: "readiness")
            }
        })
        reopening = explicit.session
        location = explicit.out
        _ = await run(explicit)
        explicit.session.cleanup()
        exact("explicit", explicit, expected: primaryBytes("N011-L10", "readiness", "cancelled", elapsed: explicitAt), owners: "exact unused")
    }
}

@main
struct Native011BindingSelfCheck {
    @MainActor static func main() async {
        guard CommandLine.arguments.dropFirst().first == "--self-check" else {
            FileHandle.standardError.write(Data("usage: native-binding-selfcheck --self-check\n".utf8))
            Darwin.exit(2)
        }
        var code: Int32 = 1
        do {
            let check = try SelfCheck()
            defer {
                try? FileManager.default.removeItem(at: check.root)
                try? FileManager.default.removeItem(at: check.wrapperParent)
            }
            try check.codec()
            try await check.happyPath()
            try await check.admissionRejections()
            try await check.readiness()
            try await check.exits()
            try await check.launchFaults()
            try await check.cancellation()
            try await check.ownerRefusals()
            try await check.retention()
            try await check.deferredCleanup()
            try await check.bounds()
            try await check.earlyExit()
            try await check.wrapperDrift()
            try await check.staggeredArrivals()
            try await check.eventCap()
            try await check.deadlines()
            try await check.diagnosticFailures()
            try await check.finalization()
            try await check.terminalEvidence()
            try await check.terminalUnverified()
            try await check.persistedInventory()
            try await check.secondaryReplacement()
            try await check.receiptPrivacy()
            try await check.successInventory(cancelled: false)
            try await check.successInventory(cancelled: true)
            try await check.fallbackFailClosed()
            try await check.cancellationFirstEffect()
            check.liveLeaves()
            let failures = check.rows.filter { $0.expected != $0.actual }
            for row in failures {
                FileHandle.standardError.write(Data("FAIL \(row.name): expected [\(row.expected)] actual [\(row.actual)]\n".utf8))
            }
            let fixtureDigest = SHA256.hash(data: Data(native011OwnershipFixture.utf8)).map { String(format: "%02x", $0) }.joined()
            let rows = check.rows.map {
                Native011JSON.object(["case": .string($0.name), "expected": .string($0.expected), "actual": .string($0.actual)])
            }
            let report = Native011JSON.object([
                "checked": .int(rows.count), "failed": .int(failures.count), "fixture_sha256": .string(fixtureDigest), "rows": .array(rows),
                "scope": .string("offline actual-source receipt, lifecycle, retention and cleanup; no native launch, XCTest binding, sandbox capability or acceptance"),
            ])
            print(report.encoded())
            code = failures.isEmpty && !rows.isEmpty ? 0 : 1
        } catch {
            FileHandle.standardError.write(Data("self-check aborted: \(native011FailureDiagnostic(error))\n".utf8))
        }
        Darwin.exit(code)
    }
}
#endif
