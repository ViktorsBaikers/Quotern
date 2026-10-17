import AppKit
import CryptoKit
import Darwin
import Foundation

// MARK: the launch session: one request, two separately owned processes

@MainActor final class Native011LaunchSession {
    enum Admission: String { case pending, open, closed }
    struct Event {
        let elapsedMs: Int
        let stage: String
        let boundary: String?
        let detail: String?
    }

    let context: Native011LaunchContext
    let retention: Native011Retention
    private let platform: any Native011Platform
    private let ops: Native011FileOps
    private let workCheck: () throws -> Void
    private let verifyWrapper: () throws -> Void
    private let startMs: Int
    private let caseStartMs: Int
    private let aggregateStartMs: Int
    private var receipt: Native011Receipt?

    private(set) var admission = Admission.pending
    private(set) var requested = false
    private(set) var launcherIdentity: Native011Identity?
    private(set) var admitted: Native011AdmittedApplication?
    private(set) var applicationExit: Native011ExitRecord?
    private(set) var launcherExit: Native011ExitRecord?
    private(set) var receiptState = Native011RequestState.prepared
    private(set) var events: [Event] = []
    private var launcher: (any Native011Launcher)?
    private var arrivals: (any Native011Arrivals)?
    private var observer: (any Native011ExitObserver)?
    private var applicationEnded = false
    private var lateArrival = false
    private var eventBound: Native011LaunchFailure?
    private var lastRelation: String?
    private var cleanupBegan = false
    private var cleanupStartMs: Int?
    private var overruns: Set<String> = []
    // Failures retained from cleanup entry on: after a clean phase none is expected, so the caller reports each one.
    private(set) var problems: [String] = []
    // A diagnostic failure that no republication could carry, with a primary already retained, is kept in `secondary.json`.
    static let secondaryName = "secondary.json"
    private var secondaryPublished = false
    private var secondaryLost = false
    // Counts every evidence-producing entry (a claimed failure or a diagnostic publication), so the deferred cleanup can tell
    // whether anything was published after its last observation of the retained outputs.
    private(set) var evidenceWrites = 0
    var secondaryFile: String? { secondaryPublished ? Self.secondaryName : nil }

    init(context: Native011LaunchContext, platform: any Native011Platform, ops: Native011FileOps = Native011FileOps(),
         caseStartMs: Int, aggregateStartMs: Int, workCheck: @escaping () throws -> Void, verifyWrapper: @escaping () throws -> Void) {
        self.context = context
        self.platform = platform
        self.ops = ops
        self.workCheck = workCheck
        self.verifyWrapper = verifyWrapper
        self.caseStartMs = caseStartMs
        self.aggregateStartMs = aggregateStartMs
        startMs = platform.now()
        retention = Native011Retention(directory: context.out, candidate: context.receipt.candidate, ops: ops)
    }

    var hasExited: Bool {
        pollExit()
        return applicationEnded
    }

    // Unknown retention, an unresolved request, a late arrival or an exceeded bound each forbid deleting disposable state.
    var mayDelete: Bool {
        retention.disposition != .unknown && (!requested || receiptState == .closed) && !lateArrival && overruns.isEmpty && !secondaryLost
    }

    var mayScan: Bool { retention.disposition != .unknown }

    // MARK: evidence

    private func event(_ stage: String, boundary: String? = nil, detail: String? = nil) {
        guard events.count < Native011Bounds.events else {
            overflowEvents(stage)
            return
        }
        events.append(Event(elapsedMs: max(0, platform.now() - startMs), stage: native011Safe(stage, limit: 40), boundary: boundary,
                            detail: detail.map { native011Safe($0, limit: 80) }))
    }

    // The cap is terminal for work and input. It is retained without emitting another event (no recursion), so an
    // incoming first failure that overflows the cap is already the primary and the overflow is only a secondary.
    private func overflowEvents(_ stage: String) {
        guard eventBound == nil else { return }
        let failure = Native011LaunchFailure(.bound, stage: stage, reason: "events")
        eventBound = failure
        admission = .closed
        claim(failure)
    }

    // The first failure becomes the immutable primary and is durably verified before this returns; later ones are secondary.
    private func claim(_ failure: Native011LaunchFailure) {
        evidenceWrites += 1
        if cleanupBegan, problems.count < Native011Bounds.outcomes { problems.append("\(failure.stage): \(failure.boundary)") }
        if let primary = retention.primary {
            if primary.boundary != failure.boundary || primary.stage != failure.stage || primary.reason != failure.reason {
                retention.note(failure)
            }
            return
        }
        let disposition = retention.retain(Native011Primary(boundary: failure.boundary, stage: failure.stage, reason: failure.reason,
                                                            observedMs: max(0, platform.now() - startMs)))
        if disposition == .unknown { admission = .closed }
    }

    // The failure is claimed before its diagnostic event, so the event cap can never replace it.
    func recordFailure(_ failure: Native011LaunchFailure) {
        claim(failure)
        event(failure.stage, boundary: failure.boundary, detail: failure.reason)
        publishDiagnostics()
    }

    private func work() throws {
        try workCheck()
        if let eventBound { throw eventBound }
    }

    private var primaryJSON: Native011JSON {
        retention.primary.map {
            .object(["boundary": .string($0.boundary), "stage": .string($0.stage), "reason": .string($0.reason),
                     "observed_elapsed_ms": .int($0.observedMs)])
        } ?? .null
    }

    private func diagnosticRecord() -> Native011JSON {
        let rows = events.map { event -> Native011JSON in
            .object(["t": .int(event.elapsedMs), "stage": .string(event.stage), "boundary": event.boundary.map { .string($0) } ?? .null,
                     "detail": event.detail.map { .string($0) } ?? .null])
        }
        return .object([
            "v": .int(1), "source_sha256": .string(context.receipt.candidate), "method": .string(context.receipt.method),
            "phase": .string(context.receipt.phase), "admission": .string(admission.rawValue),
            "request_state": .string(receiptState.rawValue), "launcher": launcherIdentity?.facts ?? .null,
            "application": admitted?.identity.facts ?? .null, "launcher_exit": launcherExit?.json ?? .null,
            "application_exit": applicationExit?.json ?? .null, "primary": primaryJSON,
            "outcomes": .array(retention.outcomes.map(\.json)),
            "retention": .object(["disposition": .string(retention.disposition.rawValue), "errors": .array(retention.errors.map(\.json))]),
            "elapsed_ms": .int(max(0, platform.now() - startMs)), "events": .array(rows),
        ])
    }

    @discardableResult private func writeDiagnostics() -> Bool {
        let bytes = Data((diagnosticRecord().encoded() + "\n").utf8)
        guard bytes.count <= Native011Bounds.diagnosticBytes else {
            retention.noteError(Native011LaunchFailure(.bound, stage: "diagnostic", reason: "record-size"))
            return false
        }
        do {
            try Native011SafeFile.publish(bytes, as: "diagnostic.json", in: context.out, replace: true,
                                          bound: Native011Bounds.diagnosticBytes, ops: ops)
            return true
        } catch let failure as Native011FileFailure {
            retention.noteError(Native011LaunchFailure(.publication, stage: "diagnostic-" + failure.stage, reason: "diagnostic-publication"))
        } catch { retention.noteError(Native011LaunchFailure(.publication, stage: "diagnostic", reason: "diagnostic-publication")) }
        NSLog("native011-diagnostic-publication-failure")
        return false
    }

    // A diagnostic failure is retained through the remaining channel and never only in memory: as the first primary when
    // none exists (primary file, then fallback; with neither verified retention is unknown, input closes and nothing is
    // signalled or deleted), otherwise as a retention error carried by one verified republication or, when that also fails,
    // by the bounded `secondary.json`. The caller reports every retention error, so the failure is always returned before
    // the session is disposed.
    func publishDiagnostics() {
        evidenceWrites += 1
        guard !writeDiagnostics() else { return }
        if retention.primary == nil, let error = retention.errors.last {
            let disposition = retention.retain(Native011Primary(boundary: error.boundary, stage: error.stage, reason: error.reason,
                                                                observedMs: max(0, platform.now() - startMs)))
            if disposition == .unknown { admission = .closed }
        } else if !writeDiagnostics() { writeSecondary() }
    }

    // The primary is immutable and diagnostic.json cannot be written, so the later attribution (every outcome and retention
    // error, at most 48 bounded rows) goes to a second file with the same verified publication. If that fails too the failure is
    // a retention error and fixture/default deletion is withheld: the evidence would otherwise exist only in memory.
    private func secondaryRecord() -> Native011JSON {
        .object([
            "v": .int(1), "source_sha256": .string(context.receipt.candidate), "method": .string(context.receipt.method),
            "phase": .string(context.receipt.phase), "producer": .string("native"), "primary": primaryJSON,
            "disposition": .string(retention.disposition.rawValue), "outcomes": .array(retention.outcomes.map(\.json)),
            "errors": .array(retention.errors.map(\.json)),
        ])
    }

    private func writeSecondary() {
        let bytes = Data((secondaryRecord().encoded() + "\n").utf8)
        do {
            try Native011SafeFile.publish(bytes, as: Self.secondaryName, in: context.out, replace: true,
                                          bound: Native011Bounds.secondaryBytes, ops: ops)
            secondaryPublished = true
            secondaryLost = false
            return
        } catch let failure as Native011FileFailure {
            // A failure before the rename leaves the earlier verified version in place; after it the pathname names an unverified one.
            if Native011SafeFile.renamedStages.contains(failure.stage) { secondaryPublished = false }
            retention.noteError(Native011LaunchFailure(.publication, stage: "secondary-" + failure.stage, reason: "secondary-publication"))
        } catch { retention.noteError(Native011LaunchFailure(.publication, stage: "secondary", reason: "secondary-publication")) }
        secondaryLost = true
    }

    private func publish(_ state: Native011RequestState, _ closure: Native011Closure) throws {
        let sequence = max((receipt?.sequence ?? -1) + 1, state.rank)
        guard sequence <= 256 else { throw Native011LaunchFailure(.bound, stage: "ownership", reason: "sequence") }
        let next = Native011Receipt(
            candidate: context.receipt.candidate, method: context.receipt.method, phase: context.receipt.phase, sequence: sequence,
            requestState: state, wrapperRel: context.receipt.wrapperRel, stdoutRel: context.receipt.stdoutRel,
            stderrRel: context.receipt.stderrRel, runner: context.runner, launcher: state == .prepared ? nil : launcherIdentity,
            application: state == .prepared || state == .issued ? nil : admitted?.identity,
            launcherArgv: state == .prepared ? nil : context.receipt.argv, launcherExit: launcherExit, applicationExit: applicationExit,
            closure: closure)
        let data = next.encoded()
        do { _ = try Native011Receipt.decode(data, context: context.receipt, previous: receipt) }
        catch let boundary as Native011OwnerBoundary {
            throw Native011LaunchFailure(.publication, stage: "ownership-encode", reason: boundary.rawValue)
        }
        do {
            try Native011SafeFile.publish(data, as: "ownership.json", in: context.out, replace: true,
                                          bound: Native011Bounds.receiptBytes, ops: ops)
        } catch let failure as Native011FileFailure {
            throw Native011LaunchFailure(.publication, stage: "ownership-" + failure.stage, reason: "ownership-publication")
        }
        receipt = next
        receiptState = state
    }

}

extension Native011LaunchSession {
    // MARK: launch

    private func matches(_ app: any Native011RunningApp) -> Bool {
        app.bundleURL?.standardizedFileURL == context.wrapper || app.executableURL?.standardizedFileURL == context.executable
    }

    func launch(beforeRequest: () throws -> Void) throws {
        guard admission == .pending, !requested else { throw Native011LaunchFailure(.cancellation, stage: "launch", reason: "admission-closed") }
        event("setup")
        try retention.prepare()
        for name in ["application.stdout.log", "application.stderr.log"] {
            do { try Native011SafeFile.createEmpty(context.out.appendingPathComponent(name), ops: ops) }
            catch let failure as Native011FileFailure {
                throw Native011LaunchFailure(.publication, stage: "stdio-" + failure.stage, reason: "stdio-preparation")
            }
        }
        try publish(.prepared, .notRequested)
        try work()
        let observation = platform.startArrivalObservation()
        arrivals = observation
        event("application-observation-installed")
        guard !observation.baseline.contains(where: matches) else {
            throw Native011LaunchFailure(.preexisting, stage: "preexisting-application", reason: "reused-owner")
        }
        try beforeRequest()
        try publish(.issued, .pending)
        requested = true
        do { launcher = try platform.startLauncher(argv: context.receipt.argv) }
        catch {
            throw Native011LaunchFailure(.launcherStart, stage: "launcher-start", reason: native011LaunchFailureDiagnostic(error))
        }
        event("launcher-started")
        guard let launcher else { throw Native011LaunchFailure(.launcherStart, stage: "launcher-start", reason: "no-launcher") }
        guard let identity = platform.identity(pid: launcher.pid), identity.pid == Int(launcher.pid), identity.path == "/usr/bin/open",
              identity.uid == context.receipt.uid, identity.pid != context.runner.pid else {
            captureLauncherExit()
            throw Native011LaunchFailure(.launcherExit, stage: "launcher-identity", reason: launcher.isRunning ? "unverified" : "exited")
        }
        launcherIdentity = identity
        try waitForArrival()
        try waitReady()
        try work()
        if admission == .pending { admission = .open }
        event("input-admitted")
        publishDiagnostics()
    }

    private func waitForArrival() throws {
        guard let arrivals else { throw Native011LaunchFailure(.arrival, stage: "arrival", reason: "unobserved") }
        let end = platform.now() + Native011Bounds.arrivalMs
        while true {
            try work()
            try checkLauncher()
            let candidates = arrivals.arrived().filter(matches)
            guard candidates.count <= 1 else { throw Native011LaunchFailure(.arrival, stage: "arrival", reason: "ambiguous") }
            if let app = candidates.first { try admit(app); return }
            guard platform.now() < end else { throw Native011LaunchFailure(.arrival, stage: "arrival", reason: "missing") }
            platform.pause()
        }
    }

    private func admit(_ app: any Native011RunningApp) throws {
        guard !app.isTerminated else {
            throw Native011LaunchFailure(.unobservedExit, stage: "arrival", reason: "terminated-before-observation")
        }
        guard app.bundleURL?.standardizedFileURL == context.wrapper else {
            throw Native011LaunchFailure(.identity, stage: "bundle-url", reason: app.bundleURL == nil ? "missing" : "mismatch")
        }
        guard app.executableURL?.standardizedFileURL == context.executable else {
            throw Native011LaunchFailure(.identity, stage: "executable", reason: app.executableURL == nil ? "missing" : "mismatch")
        }
        // A runtime bundle identifier may be absent; a present one must be the exact private identifier.
        if let identifier = app.bundleIdentifier, identifier != context.expectedBundleID {
            throw Native011LaunchFailure(.identity, stage: "bundle-identifier", reason: identifier.isEmpty ? "empty" : "conflict")
        }
        guard let identity = platform.identity(pid: app.pid), identity.pid == Int(app.pid), identity.path == context.executable.path,
              identity.uid == context.receipt.uid, identity.pid != context.runner.pid, identity.pid != launcherIdentity?.pid else {
            throw Native011LaunchFailure(.identity, stage: "process-identity", reason: "mismatch")
        }
        admitted = Native011AdmittedApplication(app: app, identity: identity, executable: context.executable, bundleURL: context.wrapper)
        do { observer = try platform.observeExit(pid: app.pid) }
        catch Native011ObserverFailure.alreadyExited {
            throw Native011LaunchFailure(.unobservedExit, stage: "exit-observer", reason: "exited-before-observation")
        } catch {
            throw Native011LaunchFailure(.observerInstall, stage: "exit-observer", reason: "observer-unavailable")
        }
        event("exit-observer-installed")
        try publish(.appObserved, .pending)
    }

    private func waitReady() throws {
        let end = platform.now() + Native011Bounds.readinessMs
        while true {
            try work()
            try requireRunning()
            let current = try verifyOwnerIdentity()
            try checkArrivals()
            let finished = current.isFinishedLaunching
            var relation = "finished=\(finished)"
            if finished {
                let state = platform.proxyState()
                relation += " proxy=\(state.rawValue)"
                if relation != lastRelation { event("readiness", detail: relation); lastRelation = relation }
                if state == .runningBackground || state == .runningForeground, platform.statusItemOwned() { return }
            } else if relation != lastRelation { event("readiness", detail: relation); lastRelation = relation }
            guard platform.now() < end else {
                throw Native011LaunchFailure(.readiness, stage: "readiness", reason: finished ? "proxy-or-status-item" : "not-finished")
            }
            platform.pause()
        }
    }

    // MARK: ownership checks and input

    @discardableResult private func verifyOwnerIdentity() throws -> any Native011RunningApp {
        guard let admitted else { throw Native011LaunchFailure(.identity, stage: "owner", reason: "unadmitted") }
        guard let current = platform.application(pid: admitted.app.pid), !current.isTerminated,
              current.isSameObject(as: admitted.app),
              current.bundleURL?.standardizedFileURL == admitted.bundleURL,
              current.executableURL?.standardizedFileURL == admitted.executable,
              platform.identity(pid: admitted.app.pid) == admitted.identity else {
            throw Native011LaunchFailure(.identity, stage: "owner-refresh", reason: "changed")
        }
        return current
    }

    // Exactly one matching application may ever arrive for this request. A second one, even after admission, is ambiguity:
    // it blocks deletion and receipt resolution and is never signalled, because it was never admitted.
    private func checkArrivals() throws {
        guard let admitted, let arrivals else { return }
        guard arrivals.arrived().filter(matches).allSatisfy({ $0.isSameObject(as: admitted.app) }) else {
            lateArrival = true
            throw Native011LaunchFailure(.arrival, stage: "arrival", reason: "ambiguous")
        }
    }

    func pollExit() {
        guard applicationExit == nil, !applicationEnded, let observer else { return }
        switch observer.poll() {
        case .pending: return
        case .exited(let raw):
            applicationEnded = true
            guard let record = Native011ExitRecord.application(rawWaitStatus: raw) else {
                recordFailure(Native011LaunchFailure(.waitStatus, stage: "exit-status", reason: "invalid-wait-status"))
                return
            }
            applicationExit = record
            event("application-exit", detail: "\(record.reason) \(record.status)")
            do { try publish(.appExited, .pending) }
            catch { recordFailure(native011Failure(error, stage: "ownership-app-exited")) }
        case .exitedWithoutStatus:
            applicationEnded = true
            recordFailure(Native011LaunchFailure(.waitStatus, stage: "exit-status", reason: "missing"))
        }
    }

    private func captureLauncherExit() {
        guard launcherExit == nil, let launcher, !launcher.isRunning, let exit = launcher.exit else { return }
        guard let record = Native011ExitRecord.launcher(reason: exit.reason, status: exit.status) else {
            recordFailure(Native011LaunchFailure(.launcherExit, stage: "launcher-exit", reason: "invalid-status"))
            return
        }
        launcherExit = record
        event("launcher-exit", detail: "\(record.reason) \(record.status)")
    }

    private func checkLauncher() throws {
        guard let launcher, !launcher.isRunning else { return }
        captureLauncherExit()
        pollExit()
        guard applicationEnded else {
            throw Native011LaunchFailure(.launcherExit, stage: "launcher-exit", reason: "before-application-exit")
        }
    }

    func requireRunning() throws {
        pollExit()
        if applicationEnded { throw ProofFailure.childExited }
        try checkLauncher()
    }

    func verifyOwners() throws {
        try requireRunning()
        try verifyOwnerIdentity()
    }

    // Every actual input rechecks the owners, the arrival set and the frozen wrapper immediately before the effect.
    func input(_ action: () throws -> Void) throws {
        guard admission == .open else { throw Native011LaunchFailure(.cancellation, stage: "input", reason: "admission-closed") }
        try verifyOwners()
        try checkArrivals()
        try verifyWrapper()
        // The verifier is synchronous filesystem work: the work and cancellation deadline is rechecked after it, immediately
        // before the effect, so a late successful verification never reaches native input.
        try work()
        try action()
    }

    // Cancellation closes native input admission permanently; it is itself a primary when none exists.
    func cancel(stage: String) {
        admission = .closed
        recordFailure(Native011LaunchFailure(.cancellation, stage: stage, reason: "cancelled"))
    }

    func awaitApplicationExit() throws {
        let end = platform.now() + Native011Bounds.exitMs
        while true {
            try work()
            try checkArrivals()
            pollExit()
            if applicationEnded { break }
            try checkLauncher()
            guard platform.now() < end else { throw ProofFailure.workDeadline }
            platform.pause()
        }
        guard applicationExit != nil else { throw Native011LaunchFailure(.waitStatus, stage: "exit-status", reason: "unproven") }
    }

    func finishLauncher() throws {
        guard let launcher else { return }
        let end = platform.now() + Native011Bounds.launcherExitMs
        while launcher.isRunning {
            try work()
            guard platform.now() < end else { throw Native011LaunchFailure(.launcherExit, stage: "launcher-exit", reason: "lingering") }
            platform.pause()
        }
        captureLauncherExit()
        try checkArrivals()
        guard launcherExit != nil, applicationExit != nil else {
            throw Native011LaunchFailure(.launcherExit, stage: "launcher-exit", reason: "unproven")
        }
        if receiptState != .closed { try publish(.closed, .resolved) }
    }

    // The actual wiring shared by every native phase: prelaunch recheck, launch and readiness, inputs,
    // observed exits, then post-exit assertions. Any failure closes admission and retains the primary
    // before this method returns control to deferred cleanup.
    func runPhase(prelaunch: () throws -> Void, body: () async throws -> Void, postexit: () throws -> Void) async throws {
        do {
            try launch(beforeRequest: prelaunch)
            try await body()
            try awaitApplicationExit()
            try finishLauncher()
            try postexit()
        } catch {
            admission = .closed
            recordFailure(native011Failure(error, stage: "phase"))
            throw error
        }
    }

    // MARK: cleanup

    func signalApplication(_ cached: Native011AdmittedApplication) throws {
        guard retention.disposition != .unknown else {
            throw Native011LaunchFailure(.applicationCleanup, stage: "signal", reason: "retention-unknown")
        }
        guard let current = platform.application(pid: cached.app.pid), !current.isTerminated,
              current.isSameObject(as: cached.app),
              current.bundleURL?.standardizedFileURL == cached.bundleURL,
              current.executableURL?.standardizedFileURL == cached.executable,
              platform.identity(pid: cached.app.pid) == cached.identity else {
            throw Native011LaunchFailure(.applicationCleanup, stage: "signal-identity", reason: "refused")
        }
        // The identity effects above consume the budget: no signal is issued once a bound is exceeded.
        guard withinBounds(cleanup: true) else {
            throw Native011LaunchFailure(.applicationCleanup, stage: "signal", reason: "deadline")
        }
        guard current.forceTerminate() else {
            throw Native011LaunchFailure(.applicationCleanup, stage: "signal", reason: "termination-refused")
        }
    }

    private func stopApplication(until end: Int) {
        guard let admitted else {
            if requested {
                lateArrival = true
                let late = arrivals?.arrived().contains(where: matches) ?? false
                recordFailure(Native011LaunchFailure(.pending, stage: "pending-launch", reason: late ? "late-arrival" : "unobserved"))
            }
            return
        }
        pollExit()
        if applicationEnded { return }
        do { try signalApplication(admitted) }
        catch {
            recordFailure(native011Failure(error, stage: "application-cleanup"))
            return
        }
        while platform.now() < end {
            pollExit()
            if applicationEnded { return }
            if observer == nil, platform.application(pid: admitted.app.pid)?.isTerminated ?? true {
                applicationEnded = true
                return
            }
            platform.pause()
        }
        pollExit()
        if !applicationEnded {
            recordFailure(Native011LaunchFailure(.applicationCleanup, stage: "termination-wait", reason: "unconfirmed"))
        }
    }

    private func stopLauncher(until end: Int) {
        guard let launcher else { return }
        if launcher.isRunning {
            let natural = min(end, platform.now() + 2_000)
            while launcher.isRunning, platform.now() < natural { platform.pause() }
            if launcher.isRunning {
                guard let launcherIdentity, platform.identity(pid: launcher.pid) == launcherIdentity else {
                    recordFailure(Native011LaunchFailure(.launcherCleanup, stage: "signal-identity", reason: "refused"))
                    return
                }
                guard withinBounds(cleanup: true) else {
                    recordFailure(Native011LaunchFailure(.launcherCleanup, stage: "signal", reason: "deadline"))
                    return
                }
                launcher.terminate()
                while launcher.isRunning, platform.now() < end { platform.pause() }
            }
        }
        guard !launcher.isRunning else {
            recordFailure(Native011LaunchFailure(.launcherCleanup, stage: "termination-wait", reason: "unconfirmed"))
            return
        }
        captureLauncherExit()
    }

    // Resolved only by an observed exact application exit and a reaped launcher with no ambiguous arrival; an ambiguity
    // that appears before closure turns an otherwise closed request unknown.
    private func resolveReceipt() {
        guard requested else { return }
        let resolved = applicationExit != nil && launcherExit != nil && !lateArrival
        guard receiptState != (resolved ? .closed : .unknown) else { return }
        do { try publish(resolved ? .closed : .unknown, resolved ? .resolved : .unknown) }
        catch { recordFailure(native011Failure(error, stage: "ownership-resolve")) }
    }

    // The shared deadline guard. The cleanup bound spans owner cleanup; the case and aggregate bounds span every final
    // effect through the last publication and close. An exceeded bound is retained once and then forbids every later
    // signal and deletion. Synchronous OS calls are not hard-bounded: this measures, it does not interrupt.
    @discardableResult func withinBounds(cleanup: Bool = false) -> Bool {
        let now = platform.now()
        var exceeded: [String] = []
        if cleanup, let cleanupStartMs, now - cleanupStartMs > Native011Bounds.cleanupMs { exceeded.append("cleanup") }
        if now - caseStartMs > Native011Bounds.caseMs { exceeded.append("case") }
        if now - aggregateStartMs > Native011Bounds.aggregateMs { exceeded.append("aggregate") }
        for stage in exceeded where overruns.insert(stage).inserted {
            recordFailure(Native011LaunchFailure(boundary: "native-deadline", stage: stage, reason: "elapsed"))
        }
        return overruns.isEmpty
    }

    // Each owner is verified and handled independently; one refusal never grants authority over the other
    // owner and never closes the request. With unknown retention nothing is signalled.
    func cleanup() {
        admission = .closed
        cleanupBegan = true
        let start = platform.now()
        cleanupStartMs = start
        let end = min(start + Native011Bounds.cleanupMs, caseStartMs + Native011Bounds.caseMs, aggregateStartMs + Native011Bounds.aggregateMs)
        event("cleanup-begin")
        guard retention.disposition != .unknown else {
            event("cleanup-withheld", boundary: Native011LaunchBoundary.publication.rawValue, detail: "retention-unknown")
            publishDiagnostics()
            withinBounds(cleanup: true)
            return
        }
        stopApplication(until: end)
        stopLauncher(until: end)
        // A later request of the same wrapper after closure is a new request, not an arrival of this one.
        if receiptState != .closed, !lateArrival {
            do { try checkArrivals() } catch { recordFailure(native011Failure(error, stage: "cleanup")) }
        }
        arrivals?.stop()
        resolveReceipt()
        withinBounds(cleanup: true)
        publishDiagnostics()
        // The final publication is part of owner cleanup: its elapsed time is measured and an overrun forbids deletion.
        withinBounds(cleanup: true)
    }

    // The final effects: fallback close, the last publication and the last elapsed measurement. A failure found here is
    // retained through the remaining channel by `recordFailure`/`publishDiagnostics` and returned to the caller through
    // `problems` and the retention errors before the session is disposed.
    func finalize() {
        cleanupBegan = true
        if !retention.close() { recordFailure(Native011LaunchFailure(.publication, stage: "fallback-close", reason: "close")) }
        publishDiagnostics()
        withinBounds()
    }
}

// The shared frozen-wrapper recheck (admission plus unchanged identity), used before launch, before every native input and after exit.
func native011RecheckWrapper(attempt: URL, method: String, original: URL, archive: URL, binary: Data, archiveBytes: Data,
                                     frozen: Native011WrapperIdentity) throws {
    let identity = try Native011WrapperAdmission.admit(attempt: attempt, method: method, original: original, archive: archive,
                                                       binary: binary, archiveBytes: archiveBytes)
    try Native011WrapperAdmission.requireUnchanged(identity, frozen: frozen)
}

// The shared wait: cancellation and deadline first, then application exit before and after every evaluation of the condition.
@MainActor func native011Wait(_ session: Native011LaunchSession?, allowsExit: Bool, check: () throws -> Void,
                                      pause: () -> Void, condition: () throws -> Bool) throws {
    while true {
        try check()
        if !allowsExit { try session?.requireRunning() }
        if try condition() { return }
        if !allowsExit { try session?.requireRunning() }
        pause()
    }
}
