// PROPOSAL ONLY: additive XCTest helper, no product source or web-JS injection.
import XCTest
import CryptoKit
import Network
@MainActor final class V15InstalledUITests: XCTestCase {
    private let iconName = "V15 Audio Lab"
    private let host = XCUIApplication(bundleIdentifier: "com.apple.webapp")
    private var largeWitnessMayExist = false
    private var ciSession: [String: Any]? = nil
    private let ciClientNonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    private var ciDone = false
    override func setUpWithError() throws { continueAfterFailure = false }

    override func tearDownWithError() throws {
        if ciSession != nil && !ciDone { _ = try? ciPost("/abort", extra: ["message": "Native test ended before full carrier DONE"]) }
        guard (testRun?.failureCount ?? 0) > 0 else { return }
        screen("v15-failure-screen")
        let app = XCUIApplication(bundleIdentifier: "com.apple.webapp")
        let names = ["Pin actual playlist", "Prepare playback", "Start pilot and run", "Start bare native", "Export all", "Freeze", "Pack frozen witness"]
        var counts: [String: Int] = [:]
        for name in names { counts[name] = app.buttons.matching(identifier: name).count }
        let data = try JSONSerialization.data(withJSONObject: ["scope": "Small diagnostic AX button counts only; never a carrier", "largeWitnessMayExist": largeWitnessMayExist, "counts": counts], options: [.sortedKeys])
        attachment("v15-failure-small-AX", String(decoding: data, as: UTF8.self))
        if !largeWitnessMayExist {
            attachment("v15-failure-prefreeze-AX-prefix", String(app.debugDescription.prefix(8000)))
            attachment("v15-failure-safari-AX-prefix", String(XCUIApplication(bundleIdentifier: "com.apple.mobilesafari").debugDescription.prefix(8000)))
            attachment("v15-failure-home-AX-prefix", String(XCUIApplication(bundleIdentifier: "com.apple.springboard").debugDescription.prefix(4000)))
        }
    }
    private func nativeSummaryTap(_ name: String, in app: XCUIApplication) {
        let primary = app.buttons.matching(identifier: name).allElementsBoundByIndex.filter { $0.exists && $0.isHittable }
        let hits = primary.isEmpty ? app.otherElements.matching(identifier: name).allElementsBoundByIndex.filter { $0.exists && $0.isHittable } : primary
        XCTAssertEqual(hits.count, 1, "Ambiguous/unqualified actual summary AX type: " + name)
        guard hits.count == 1 else { return }; hits[0].tap()
    }
    private func ensureQuickControls(in app: XCUIApplication) {
        _ = text(".*V15.*aca842c376c4.*", in: app, timeout: 30)
        if !(app.buttons["Pin actual playlist"].exists && app.buttons["Pin actual playlist"].isHittable) {
            nativeSummaryTap("V15 verification controls", in: app)
        }
        XCTAssertTrue(app.buttons["Pin actual playlist"].waitForExistence(timeout: 8))
        XCTAssertTrue(app.buttons["Pin actual playlist"].isHittable)
    }
    private func ciPost(_ path: String, extra: [String: Any] = [:]) throws -> [String: Any] {
        let session = try XCTUnwrap(ciSession)
        let keys = ["schema", "runId", "runAttempt", "expectedUDID", "serverNonce", "sourceSHA256", "entrySHA256"]
        var payload: [String: Any] = [:]
        for key in keys { payload[key] = session[key] }
        payload["clientNonce"] = ciClientNonce
        for (key, value) in extra { payload[key] = value }
        let response = try ciWire(path, body: payload)
        for key in keys { XCTAssertEqual(response[key] as? String, session[key] as? String, "Own handshake binding changed") }
        return response
    }
    private func waitForOwnedCapture(pin: String, prepared: String) throws {
        let session = try ciWire("/session")
        XCTAssertEqual(session["schema"] as? String, "owned-ci-v15-loopback-v1")
        XCTAssertEqual(session["sourceSHA256"] as? String, "27fd46cd8ecb653e2d6e4cc78c49b67ff9852adfac10a72d08d98ff253436e5d")
        XCTAssertEqual(session["entrySHA256"] as? String, "aca842c376c4711adbfef638afca7142639645015f839f03051c01b37a60e30a")
        ciSession = session
        var extra: [String: Any] = ["pinAX": pin, "preparedAX": prepared, "nativeUptimeSeconds": ProcessInfo.processInfo.systemUptime]
        if let actual = ProcessInfo.processInfo.environment["SIMULATOR_UDID"] { extra["nativeEnvironmentUDID"] = actual }
        _ = try ciPost("/ready", extra: extra)
        let until = ProcessInfo.processInfo.systemUptime + 12
        while ProcessInfo.processInfo.systemUptime < until {
            let reply = try ciPost("/ack")
            if reply["captureStarted"] as? Bool == true {
                attachment("v15-native-capture-ack", String(decoding: try JSONSerialization.data(withJSONObject: reply), as: UTF8.self))
                return
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        throw CIWireError.refused("No actual owned OS-capture ACK before real pilot tap")
    }
    private func attachment(_ name: String, _ text: String) {
        let item = XCTAttachment(string: text); item.name = name; item.lifetime = .keepAlways; add(item)
    }
    private func screen(_ name: String) {
        let item = XCTAttachment(screenshot: XCUIScreen.main.screenshot()); item.name = name; item.lifetime = .keepAlways; add(item)
    }
    private func uniqueTap(_ name: String, in app: XCUIApplication) {
        let q = app.buttons.matching(NSPredicate(format: "label == %@", name))
        XCTAssertTrue(q.firstMatch.waitForExistence(timeout: 12), "Missing " + name)
        XCTAssertEqual(q.count, 1, "Ambiguous " + name)
        XCTAssertTrue(q.element.isEnabled && q.element.isHittable, "Unavailable " + name)
        q.element.tap()
    }
    private func text(_ pattern: String, in app: XCUIApplication, timeout: TimeInterval) -> XCUIElement {
        let q = app.staticTexts.matching(NSPredicate(format: "label MATCHES %@", pattern))
        XCTAssertTrue(q.firstMatch.waitForExistence(timeout: timeout), "Expected actual AX text: " + pattern)
        return q.firstMatch
    }
    private func retainHome(_ name: String, home: XCUIApplication) {
        screen("v15-" + name)
        // Home-flow receipts occur only before any large page export.
        attachment("v15-" + name + "-hierarchy", home.debugDescription)
    }
    private func launchHomeIcon() {
        let home = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        // Add may already reveal the newly installed icon. A second Home press
        // resets the selected page, so press only when Springboard is not foreground.
        if home.state != .runningForeground { XCUIDevice.shared.press(.home) }
        XCTAssertTrue(home.wait(for: .runningForeground, timeout: 5), "Springboard not foreground")
        let q = home.icons.matching(identifier: iconName)
        XCTAssertTrue(q.firstMatch.waitForExistence(timeout: 8), "No installed Home icon")
        XCTAssertEqual(q.count, 1, "Unique actual V15 Home icon required")
        let icon = q.element
        for _ in 0..<4 {
            if icon.isHittable { break }
            let indicators = home.pageIndicators.matching(identifier: "Page control")
            guard indicators.count == 1, let value = indicators.element.value as? String else {
                retainHome("home-page-indicator-unavailable", home: home)
                XCTFail("Unique actual Home-page indicator required"); break
            }
            let words = value.split(separator: " ")
            guard words.count == 4, words[0] == "Page", words[2] == "of",
                  let page = Int(words[1]), let total = Int(words[3]),
                  page >= 1, total >= page, total <= 5, page < total else {
                retainHome("home-page-boundary-refused", home: home)
                XCTFail("Refuse unknown/last Home page; never swipe into App Library: " + value); break
            }
            let expected = "Page \(page + 1) of \(total)"
            retainHome("home-before-next-page-\(page)", home: home)
            home.swipeLeft()
            let changed = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == %@", expected), object: indicators.element)
            guard XCTWaiter.wait(for: [changed], timeout: 3) == .completed else {
                retainHome("home-page-transition-refused", home: home)
                XCTFail("Actual Home page did not advance exactly to " + expected); break
            }
        }
        retainHome("home-before-installed-icon-tap", home: home)
        XCTAssertTrue(icon.isHittable, "Installed icon not visible on verified Home pages")
        icon.tap()
        // Query the real Web Clip host; never activate it or forge standalone flags.
        ensureQuickControls(in: host)
        screen("v15-home-icon-launched")
    }
    func testInstallV15FromSafari() throws {
        let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
        safari.activate()
        ensureQuickControls(in: safari)
        attachment("v15-before-share-hierarchy", safari.debugDescription)
        uniqueTap("Share", in: safari)
        // Exact selector established by retained iOS18.6 Cell witness; toy rerun gate still applies.
        let actions = safari.collectionViews["activityCollectionView"]
        XCTAssertTrue(actions.waitForExistence(timeout: 5))
        let q = actions.cells.matching(identifier: "Add to Home Screen")
        for _ in 0..<4 { if q.firstMatch.exists && q.firstMatch.isHittable { break }; actions.swipeUp() }
        XCTAssertEqual(q.count, 1); XCTAssertTrue(q.element.isHittable)
        attachment("v15-real-share-actions", safari.debugDescription); q.element.tap()
        screen("v15-real-add-confirmation")
        // Manifest/meta title must supply the intended icon name; do not guess/change it silently.
        let name = safari.textFields.firstMatch
        XCTAssertTrue(name.waitForExistence(timeout: 5)); XCTAssertEqual(name.value as? String, iconName)
        uniqueTap("Add", in: safari)
        launchHomeIcon()
        attachment("v15-installed-initial-hierarchy", host.debugDescription)
        // Actual standalone proof is checked later in the unmodified source rows, not invented here.
    }
    func testV15InstalledAudioProtocol() throws {
        launchHomeIcon()
        uniqueTap("Pin actual playlist", in: host)
        // Reveal the existing original status; no helper/source changes. Fail if summary AX differs.
        nativeSummaryTap("V15 OS audio test", in: host)
        let pinAX = text("playlist=PINNED assets=6 .*", in: host, timeout: 20).label
        uniqueTap("Prepare playback", in: host)
        let preparedAX = text("READY: native playing and unmuted\\..*", in: host, timeout: 12).label
        screen("v15-prepared-unmuted")
        // Collapse original detail to keep quick actions visible and huge later Export text out of AX.
        nativeSummaryTap("V15 OS audio test", in: host)
        // Actual DOM is <a role="button" aria-label="Close">. Bind observed XCUI semantics.
        let closeCandidates = host.buttons.matching(identifier: "Close").allElementsBoundByIndex + host.links.matching(identifier: "Close").allElementsBoundByIndex
        let actualClose = closeCandidates.filter { $0.exists }
        XCTAssertEqual(actualClose.count, 1, "Must observe unique actual Close before phases")
        let close = try XCTUnwrap(actualClose.first)
        attachment("v15-actual-close-AX", "type=\(close.elementType.rawValue); label=\(close.label)")
        // Xcode bootstrap is outside capture. Host ACK must precede this real pilot/run tap.
        try waitForOwnedCapture(pin: pinAX, prepared: preparedAX)
        uniqueTap("Start pilot and run", in: host)
        _ = text("RUNNING: original pilot and product phases armed once\\.", in: host, timeout: 8)
        screen("v15-original-protocol-running")
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate { _,_ in !close.exists }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [gone], timeout: 48), .completed, "Actual Close not observed")
        screen("v15-after-actual-product-close")
        uniqueTap("Start bare native", in: host)
        nativeSummaryTap("V15 OS audio test", in: host)
        _ = text("playlist=PINNED assets=6 bare-native source=LIVE .*", in: host, timeout: 8)
        let cleanupAX = text("playlist=PINNED assets=6 bare-native source=stopped .*cleanup=true", in: host, timeout: 25).label
        screen("v15-source-cleanup")
        nativeSummaryTap("V15 OS audio test", in: host)
        largeWitnessMayExist = true
        uniqueTap("Export all", in: host)
        uniqueTap("Freeze", in: host)
        _ = text("Frozen [0-9]+ UTF-8 bytes;.*", in: host, timeout: 15)
        uniqueTap("Pack frozen witness", in: host)
        let packedStatus = text("Packed [0-9]+ UTF-8 carrier bytes; SHA-256 [0-9a-f]{64};.*", in: host, timeout: 20).label
        attachment("v15-packed-status", packedStatus)
        // Never query/debugDescription after large Freeze. Read one actual AX label and verify it.
        let candidates = host.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "{\"format\":\"v13-gzip-export-carrier-v1\""))
        XCTAssertTrue(candidates.firstMatch.waitForExistence(timeout: 8))
        let bodies = Set(candidates.allElementsBoundByIndex.map(\.label))
        XCTAssertEqual(bodies.count, 1, "Ambiguous/truncated native carrier AX labels")
        let carrier = try XCTUnwrap(bodies.first); let bytes = Data(carrier.utf8)
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(packedStatus.hasPrefix("Packed \(bytes.count) UTF-8 carrier bytes; SHA-256 \(digest);"), "Native AX truncation/hash mismatch")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(object["format"] as? String, "v13-gzip-export-carrier-v1")
        let packing = try XCTUnwrap(object["packing"] as? [String: Any])
        XCTAssertEqual(packing["trustedClick"] as? Bool, true)
        XCTAssertEqual(packing["roundTripVerified"] as? Bool, true)
        attachment("v15-full-native-carrier-json", carrier)
        attachment("v15-native-carrier-receipt", "{\"bytes\":\(bytes.count),\"sha256\":\"\(digest)\",\"input\":\"actual XCUI AX label\",\"standaloneInjected\":false}")
        screen("v15-packed-complete")
        _ = try ciPost("/done", extra: ["carrierBytes": bytes.count, "carrierSHA256": digest, "packedAX": packedStatus, "cleanupAX": cleanupAX, "nativeUptimeSeconds": ProcessInfo.processInfo.systemUptime])
        ciDone = true
        XCUIDevice.shared.press(.home)
    }
}
