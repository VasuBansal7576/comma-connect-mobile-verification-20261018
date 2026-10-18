// PROPOSAL ONLY: additive XCTest helper, no product source or web-JS injection.
import XCTest
import CryptoKit
import Network
@MainActor final class V16InstalledUITests: XCTestCase {
    private let iconName = "V16 Audio Lab"
    private let host = XCUIApplication(bundleIdentifier: "com.apple.webapp")
    private var largeWitnessMayExist = false
    private var addNameSelectorFailureRecorded = false
    private var lastInstallCheckpoint = "not-started"
    private var homeSearchFacts: [String: Any] = [:]
    private var ciSession: [String: Any]? = nil
    private let ciClientNonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    private var ciDone = false
    override func setUpWithError() throws { continueAfterFailure = false }

    override func tearDownWithError() throws {
        if ciSession != nil && !ciDone { _ = try? ciPost("/abort", extra: ["message": "Native test ended before full carrier DONE"]) }
        guard (testRun?.failureCount ?? 0) > 0 else { return }
        let failedAfter = lastInstallCheckpoint
        installCheckpoint("failure-teardown.before-screenshot")
        screen("v16-failure-screen")
        let facts: [String: Any] = ["failedAfter": failedAfter,
            "largeWitnessMayExist": largeWitnessMayExist,
            "addNameSelectorFailureRecorded": addNameSelectorFailureRecorded,
            "ciSessionPresent": ciSession != nil, "ciDone": ciDone,
            "homeSearch": homeSearchFacts,
            "scope": "Already-computed flags/checkpoints only; no post-failure AX queries. Source carriers remain separate."]
        let encoded = try JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys])
        FileHandle.standardOutput.write(Data("V16_FAILURE_FACTS ".utf8) + encoded + Data("\n".utf8))
        attachment("v16-failure-computed-facts", String(decoding: encoded, as: UTF8.self))
        installCheckpoint("failure-teardown.complete")
    }
    private func installCheckpoint(_ stage: String) {
        lastInstallCheckpoint = stage
        // Direct small stdout write: no AX, app state, server or UI action needed to emit a checkpoint.
        let line = "V16_INSTALL_CHECKPOINT " + stage + " uptimeSeconds="
            + String(format: "%.3f", ProcessInfo.processInfo.systemUptime) + "\n"
        FileHandle.standardOutput.write(Data(line.utf8))
    }
    private func retainSmallContext(_ name: String, in app: XCUIApplication,
                                    targets: [(kind: String, label: String, query: XCUIElementQuery)]) {
        installCheckpoint("context." + name + ".before")
        var rows: [[String: Any]] = []
        for target in targets.prefix(12) {
            let count = target.query.count
            var row: [String: Any] = ["kind": target.kind, "label": String(target.label.prefix(128)), "count": count]
            if count == 1 {
                let element = target.query.element
                row["exists"] = element.exists
                row["enabled"] = element.isEnabled
                row["hittable"] = element.isHittable
                if target.kind == "pageIndicator", let value = element.value as? String {
                    row["pageValue"] = String(value.prefix(128))
                    row["pageValueTruncated"] = value.count > 128
                }
            }
            rows.append(row)
        }
        let payload: [String: Any] = ["name": name, "appStateRaw": app.state.rawValue,
            "queriedTargets": rows, "targetLimit": 12, "omittedTargets": max(0, targets.count - 12),
            "scope": "Small typed diagnostic queries only. Each AX query may still block; caller deadline applies. Not a source/carrier/runtime success witness."]
        let encoded = (try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
            ?? Data("{\"diagnosticSerializationFailed\":true}".utf8)
        attachment(name, String(decoding: encoded, as: UTF8.self))
        installCheckpoint("context." + name + ".after")
    }
    private func nativeSummaryTap(_ name: String, in app: XCUIApplication) {
        func candidates() -> [XCUIElement] {
            let primary = app.buttons.matching(identifier: name).allElementsBoundByIndex.filter { $0.exists }
            return primary.isEmpty
                ? app.otherElements.matching(identifier: name).allElementsBoundByIndex.filter { $0.exists } : primary
        }
        for swipes in 0...3 {
            let hits = candidates()
            guard hits.count == 1 else { XCTFail("Unique actual summary required: " + name); return }
            let target = hits[0]
            if target.isHittable {
                guard target.isEnabled else { XCTFail("Actual summary disabled: " + name); return }
                target.tap(); return
            }
            guard swipes < 3 else { XCTFail("Summary remains offscreen after three native swipes: " + name); return }
            installCheckpoint("Summary.visibility-swipe.before")
            app.swipeUp()
            installCheckpoint("Summary.visibility-swipe.after")
        }
    }
    private func openEvidenceExport() {
        let summaries = host.buttons.matching(identifier: "Evidence export").allElementsBoundByIndex
            + host.otherElements.matching(identifier: "Evidence export").allElementsBoundByIndex
        // Existing offscreen child means main is already open; hittability is not open state.
        if !summaries.contains(where: { $0.exists }) { nativeSummaryTap("V16 verification controls", in: host) }
        let menu = host.links.matching(NSPredicate(format: "label == %@", "Menu"))
        if !menu.firstMatch.exists { nativeSummaryTap("Evidence export", in: host) }
        XCTAssertTrue(menu.firstMatch.waitForExistence(timeout: 8), "Actual Evidence Menu child required")
        XCTAssertEqual(menu.count, 1, "Unique Evidence Menu child required")
    }
    private func revealEvidenceMenu() {
        openEvidenceExport()
        let menu = host.links.matching(NSPredicate(format: "label == %@", "Menu"))
        for _ in 0..<3 { if menu.element.isHittable { break }; host.swipeUp() }
        XCTAssertTrue(menu.element.isHittable, "Actual Evidence Menu remains offscreen")
    }
    private func revealQuickResult(_ name: String, in app: XCUIApplication) {
        // Stored Quick layout places these original buttons before Evidence export.
        let query = app.buttons.matching(identifier: name)
        for swipes in 0...3 {
            let hits = query.allElementsBoundByIndex.filter { $0.exists }
            guard hits.count == 1 else { XCTFail("Unique original Quick result required: " + name); return }
            if hits[0].isHittable { return }
            guard swipes < 3 else { XCTFail("Quick result remains offscreen after three native swipes: " + name); return }
            app.swipeDown()
        }
    }
    private func ensureQuickControls(in app: XCUIApplication) {
        _ = text(".*V16.*e7ab13f79d01.*", in: app, timeout: 30)
        if !(app.buttons["Pin actual playlist"].exists && app.buttons["Pin actual playlist"].isHittable) {
            nativeSummaryTap("V16 verification controls", in: app)
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
        XCTAssertEqual(session["schema"] as? String, "owned-ci-v16-loopback-v1")
        XCTAssertEqual(session["sourceSHA256"] as? String, "24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b")
        XCTAssertEqual(session["entrySHA256"] as? String, "e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641")
        ciSession = session
        var extra: [String: Any] = ["pinAX": pin, "preparedAX": prepared, "nativeUptimeSeconds": ProcessInfo.processInfo.systemUptime]
        if let actual = ProcessInfo.processInfo.environment["SIMULATOR_UDID"] { extra["nativeEnvironmentUDID"] = actual }
        _ = try ciPost("/ready", extra: extra)
        let until = ProcessInfo.processInfo.systemUptime + 12
        while ProcessInfo.processInfo.systemUptime < until {
            let reply = try ciPost("/ack")
            if reply["captureStarted"] as? Bool == true {
                attachment("v16-native-capture-ack", String(decoding: try JSONSerialization.data(withJSONObject: reply), as: UTF8.self))
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
    private func homePage(_ value: String) -> (page: Int, total: Int)? {
        let words = value.split(separator: " ")
        guard words.count == 4, words[0] == "Page", words[2] == "of",
              let page = Int(words[1]), let total = Int(words[3]),
              page >= 1, page <= total, total <= 5 else { return nil }
        return (page, total)
    }
    private func nextHomePage(_ value: String, visited: Set<Int>, swipes: Int) -> Int? {
        guard swipes < 5, let current = homePage(value) else { return nil }
        let remaining = (1...current.total).filter { $0 != current.page && !visited.contains($0) }
        guard let target = remaining.min(by: {
            let left = abs($0 - current.page), right = abs($1 - current.page)
            return left == right ? $0 < $1 : left < right
        }) else { return nil }
        return current.page + (target > current.page ? 1 : -1)
    }
    private func installedHomeIcon() -> XCUIElement? {
        let home = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let icons = home.icons.matching(identifier: iconName)
        let indicators = home.pageIndicators.matching(identifier: "Page control")
        func visibleIcon() -> XCUIElement? {
            guard icons.count == 1 else { return nil }
            let icon = icons.element
            return icon.exists && icon.isHittable ? icon : nil
        }
        func actualPageValue() -> String? {
            guard indicators.count == 1 else { return nil }
            let indicator = indicators.element
            guard indicator.exists && indicator.isHittable,
                  let value = indicator.value as? String, homePage(value) != nil else { return nil }
            return value
        }
        installCheckpoint("Home.find.begin")
        let initialCount = icons.count
        homeSearchFacts = ["initialIconCount": initialCount, "pressedHome": false, "swipes": 0]
        guard initialCount <= 1 else { XCTFail("Ambiguous installed V16 Home icon"); return nil }
        if let icon = visibleIcon() {
            homeSearchFacts["uniqueVisibleIcon"] = true
            return icon
        }
        // Springboard also owns App Switcher. Its foreground state alone is not Home.
        installCheckpoint("Home.press.before")
        XCUIDevice.shared.press(.home)
        installCheckpoint("Home.press.after")
        homeSearchFacts["pressedHome"] = true
        guard home.wait(for: .runningForeground, timeout: 5) else {
            XCTFail("Springboard did not become foreground after actual Home press"); return nil
        }
        let ready = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            visibleIcon() != nil || actualPageValue() != nil
        }, object: nil)
        guard XCTWaiter.wait(for: [ready], timeout: 8) == .completed else {
            XCTFail("Actual Home requires a visible icon or qualified Page control; App Switcher is insufficient"); return nil
        }
        var visited = Set<Int>()
        for swipes in 0...5 {
            let count = icons.count
            homeSearchFacts["iconCount"] = count
            homeSearchFacts["swipes"] = swipes
            guard count <= 1 else { XCTFail("Ambiguous installed V16 Home icon"); return nil }
            if let icon = visibleIcon() { homeSearchFacts["uniqueVisibleIcon"] = true; return icon }
            guard let value = actualPageValue(), let current = homePage(value) else {
                XCTFail("Unique hittable actual Home Page control required before paging"); return nil
            }
            visited.insert(current.page)
            homeSearchFacts["pageValue"] = value
            homeSearchFacts["visitedPages"] = visited.sorted()
            guard let next = nextHomePage(value, visited: visited, swipes: swipes) else {
                XCTFail("Installed icon absent within verified Home pages or five-swipe bound"); return nil
            }
            let expected = "Page \(next) of \(current.total)"
            homeSearchFacts["expectedPage"] = expected
            installCheckpoint("Home.page-swipe.before")
            if next > current.page { home.swipeLeft() } else { home.swipeRight() }
            let changed = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == %@", expected), object: indicators.element)
            guard XCTWaiter.wait(for: [changed], timeout: 3) == .completed else {
                XCTFail("Actual Home page did not move exactly to " + expected); return nil
            }
            installCheckpoint("Home.page-swipe.after")
        }
        return nil
    }
    private func launchHomeIcon(requireAudioControls: Bool = true) {
        guard let icon = installedHomeIcon() else { return }
        screen("v16-home-before-installed-icon-tap")
        XCTAssertTrue(icon.isHittable, "Installed icon must be visible on actual verified Home")
        installCheckpoint("Home.icon-tap.before")
        icon.tap()
        installCheckpoint("Home.icon-tap.after")
        // Query the real Web Clip host; never activate it or forge standalone flags.
        if requireAudioControls {
            ensureQuickControls(in: host)
        } else {
            XCTAssertTrue(host.wait(for: .runningForeground, timeout: 8), "Installed WebClip did not become foreground")
            _ = text(".*V16.*e7ab13f79d01.*", in: host, timeout: 30)
        }
        screen("v16-home-icon-launched")
    }
    private func retainAddNameSelectorFailure(facts: [String: Any]) {
        // Facts were computed once by the actual selector; never enumerate or requery AX here.
        addNameSelectorFailureRecorded = true
        installCheckpoint("Add.name-selector.failure.before")
        let encoded = (try? JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys]))
            ?? Data("{\"diagnosticSerializationFailed\":true}".utf8)
        FileHandle.standardOutput.write(Data("V16_ADD_NAME_SELECTOR_FACTS ".utf8) + encoded + Data("\n".utf8))
        attachment("v16-add-name-selector-failure", String(decoding: encoded, as: UTF8.self))
        screen("v16-add-name-selector-failure")
        installCheckpoint("Add.name-selector.failure.after")
    }
    func testInstallV16FromSafari() throws {
        installCheckpoint("install.begin")
        let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
        let labURL = try XCTUnwrap(URL(string: "https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/nqa?candidate=v16&experiment=nqa"))
        installCheckpoint("Safari.launch.before")
        safari.launch()
        installCheckpoint("Safari.launch.after")
        installCheckpoint("Safari.open.before")
        safari.open(labURL)
        installCheckpoint("Safari.open.after")
        installCheckpoint("Safari.quick-controls.before")
        ensureQuickControls(in: safari)
        installCheckpoint("Safari.quick-controls.after")
        retainSmallContext("v16-before-share-context", in: safari, targets: [
            ("button", "Share", safari.buttons.matching(identifier: "Share")),
            ("button", "Pin actual playlist", safari.buttons.matching(identifier: "Pin actual playlist"))])
        installCheckpoint("Share.tap.before")
        uniqueTap("Share", in: safari)
        installCheckpoint("Share.tap.after")
        // Exact selector established by retained iOS18.6 Cell witness; toy rerun gate still applies.
        let actions = safari.collectionViews["activityCollectionView"]
        installCheckpoint("share-actions.wait.before")
        XCTAssertTrue(actions.waitForExistence(timeout: 5))
        installCheckpoint("share-actions.wait.after")
        let q = actions.cells.matching(identifier: "Add to Home Screen")
        for _ in 0..<4 { if q.firstMatch.exists && q.firstMatch.isHittable { break }; actions.swipeUp() }
        XCTAssertEqual(q.count, 1); XCTAssertTrue(q.element.isHittable)
        retainSmallContext("v16-real-share-context", in: safari, targets: [
            ("collectionView", "activityCollectionView", safari.collectionViews.matching(identifier: "activityCollectionView")),
            ("cell", "Add to Home Screen", q)])
        installCheckpoint("AddToHomeScreen.cell.tap.before")
        q.element.tap()
        installCheckpoint("AddToHomeScreen.cell.tap.after")
        screen("v16-real-add-confirmation")
        // Manifest/meta title must supply the intended icon name; do not guess/change it silently.
        installCheckpoint("Add.name-selector.before")
        let addBars = safari.navigationBars.matching(identifier: "Add to Home Screen")
        let addContextReady = addBars.firstMatch.waitForExistence(timeout: 5)
        let addBarCount = addBars.count
        // Actual iOS18.6 witness is a TextField with this exact value. This is observation,
        // not an edit/tap: enabled and hittable are required for the Add button below only.
        let nameFields = safari.textFields.matching(NSPredicate(format: "value == %@", iconName))
        let nameReady = nameFields.firstMatch.waitForExistence(timeout: 15)
        let nameCount = nameFields.count
        let actualName = nameReady && nameCount == 1 ? nameFields.firstMatch : nil
        let nameExists = actualName?.exists ?? false
        let observedValue = nameExists ? actualName?.value as? String : nil
        let exactValue = observedValue == iconName
        if !addContextReady || addBarCount != 1 || !nameReady || nameCount != 1 || !nameExists || !exactValue {
            retainAddNameSelectorFailure(facts: [
                "expectedExactValue": iconName, "expectedNavigationTitle": "Add to Home Screen",
                "addContextReady": addContextReady, "addBarCount": addBarCount,
                "nameReady": nameReady, "nameCount": nameCount, "nameExists": nameExists,
                "observedValue": observedValue.map { String($0.prefix(1024)) as Any } ?? NSNull(),
                "observedValueTruncated": observedValue.map { $0.count > 1024 } ?? false,
                "exactValue": exactValue,
                "scope": "Already-computed exact TextField/context facts only; no typing, editing or additional AX queries."])
        }
        XCTAssertTrue(addContextReady, "Actual Add to Home Screen navigation context missing")
        XCTAssertEqual(addBarCount, 1, "Unique actual Add navigation bar required")
        XCTAssertTrue(nameReady, "Expected manifest/meta icon title not present in actual TextField")
        XCTAssertEqual(nameCount, 1, "Unique exact-value Add name TextField required")
        XCTAssertTrue(nameExists, "Actual Add name TextField must exist")
        XCTAssertEqual(observedValue, iconName)
        installCheckpoint("Add.name-selector.after")
        installCheckpoint("Add.confirm.tap.before")
        uniqueTap("Add", in: safari)
        installCheckpoint("Add.confirm.tap.after")
        installCheckpoint("Home.launch.before")
        launchHomeIcon()
        installCheckpoint("Home.launch.after")
        retainSmallContext("v16-installed-initial-context", in: host, targets: [
            ("button", "Pin actual playlist", host.buttons.matching(identifier: "Pin actual playlist")),
            ("button", "Prepare playback", host.buttons.matching(identifier: "Prepare playback")),
            ("button", "Freeze", host.buttons.matching(identifier: "Freeze"))])
        // Actual standalone proof is checked later in the unmodified source rows, not invented here.
        installCheckpoint("install.end")
    }
    private func audioFreshEntryFromCurrentMenu() throws {
        // Same WebClip navigation only. Start from NF/URL/current App without requiring audio controls.
        XCTAssertEqual(host.state, .runningForeground)
        revealEvidenceMenu()
        func visibleMenu() -> [XCUIElement] {
            let buttons = host.buttons.matching(NSPredicate(format: "label == %@", "Menu")).allElementsBoundByIndex
            let links = host.links.matching(NSPredicate(format: "label == %@", "Menu")).allElementsBoundByIndex
            return (buttons + links).filter { $0.exists && $0.isEnabled && $0.isHittable }
        }
        let menuReady = XCTNSPredicateExpectation(predicate: NSPredicate { _,_ in visibleMenu().count == 1 }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [menuReady], timeout: 12), .completed, "Unique real same-WebClip Menu required")
        let menus = visibleMenu(); XCTAssertEqual(menus.count, 1)
        try XCTUnwrap(menus.first).tap()
        // Exact current public menu anchor /v16/nqa. No URL command or DOM/JS navigation.
        let audio = host.links.matching(NSPredicate(format: "label == %@", "V16 silent OS audio comparison"))
        XCTAssertTrue(audio.firstMatch.waitForExistence(timeout: 12))
        XCTAssertEqual(audio.count, 1)
        let link = audio.element
        for _ in 0..<8 { if link.isHittable { break }; host.swipeUp() }
        XCTAssertTrue(link.isEnabled && link.isHittable)
        link.tap()
        XCTAssertTrue(host.wait(for: .runningForeground, timeout: 8), "Audio link left actual installed WebClip")
    }
    func testV16InstalledAudioProtocol() throws {
        launchHomeIcon(requireAudioControls: false)
        try audioFreshEntryFromCurrentMenu()
        ensureQuickControls(in: host)
        uniqueTap("Pin actual playlist", in: host)
        // Reveal the existing original status; no helper/source changes. Fail if summary AX differs.
        nativeSummaryTap("V16 OS audio test", in: host)
        let pinAX = text("playlist=PINNED assets=6 .*", in: host, timeout: 20).label
        uniqueTap("Prepare playback", in: host)
        let preparedAX = text("READY: native playing and unmuted\\..*", in: host, timeout: 12).label
        screen("v16-prepared-unmuted")
        // Collapse original detail to keep quick actions visible and huge later Export text out of AX.
        nativeSummaryTap("V16 OS audio test", in: host)
        // Actual DOM is <a role="button" aria-label="Close">. Bind observed XCUI semantics.
        let closeCandidates = host.buttons.matching(identifier: "Close").allElementsBoundByIndex + host.links.matching(identifier: "Close").allElementsBoundByIndex
        let actualClose = closeCandidates.filter { $0.exists }
        XCTAssertEqual(actualClose.count, 1, "Must observe unique actual Close before phases")
        let close = try XCTUnwrap(actualClose.first)
        attachment("v16-actual-close-AX", "type=\(close.elementType.rawValue); label=\(close.label)")
        // Xcode bootstrap is outside capture. Host ACK must precede this real pilot/run tap.
        try waitForOwnedCapture(pin: pinAX, prepared: preparedAX)
        uniqueTap("Start pilot and run", in: host)
        _ = text("RUNNING: original pilot and product phases armed once\\.", in: host, timeout: 8)
        screen("v16-original-protocol-running")
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate { _,_ in !close.exists }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [gone], timeout: 48), .completed, "Actual Close not observed")
        screen("v16-after-actual-product-close")
        uniqueTap("Start bare native", in: host)
        nativeSummaryTap("V16 OS audio test", in: host)
        _ = text("playlist=PINNED assets=6 bare-native source=LIVE .*", in: host, timeout: 8)
        let cleanupAX = text("playlist=PINNED assets=6 bare-native source=stopped .*cleanup=true", in: host, timeout: 25).label
        screen("v16-source-cleanup")
        nativeSummaryTap("V16 OS audio test", in: host)
        largeWitnessMayExist = true
        revealQuickResult("Export all", in: host)
        uniqueTap("Export all", in: host)
        revealQuickResult("Freeze", in: host)
        uniqueTap("Freeze", in: host)
        _ = text("Frozen [0-9]+ UTF-8 bytes;.*", in: host, timeout: 15)
        revealQuickResult("Pack frozen witness", in: host)
        uniqueTap("Pack frozen witness", in: host)
        revealEvidenceMenu()
        let packedStatus = text("Packed [0-9]+ UTF-8 carrier bytes; SHA-256 [0-9a-f]{64};.*", in: host, timeout: 20).label
        attachment("v16-packed-status", packedStatus)
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
        attachment("v16-full-native-carrier-json", carrier)
        attachment("v16-native-carrier-receipt", "{\"bytes\":\(bytes.count),\"sha256\":\"\(digest)\",\"input\":\"actual XCUI AX label\",\"standaloneInjected\":false}")
        screen("v16-packed-complete")
        _ = try ciPost("/done", extra: ["carrierBytes": bytes.count, "carrierSHA256": digest, "packedAX": packedStatus, "cleanupAX": cleanupAX, "nativeUptimeSeconds": ProcessInfo.processInfo.systemUptime])
        ciDone = true
        XCUIDevice.shared.press(.home)
    }
}
