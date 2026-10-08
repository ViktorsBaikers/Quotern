import AppKit
import QuoternCore

let delegate: NSApplicationDelegate
switch SelfTestArguments.parse(CommandLine.arguments) {
case nil:
    delegate = AppDelegate()
case .success(.journey(let options))?:
    delegate = SelfTestJourney(options: options)
case .success(.startup(let options))?:
    delegate = SelfTestStartup(options: options)
case .failure(let refusal)?:
    FileHandle.standardError.write(Data("selftest refused: \(refusal.reason)\n".utf8))
    exit(2)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
app.delegate = delegate
app.run()
