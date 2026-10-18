// PROPOSAL: append this extension to the SAME ios/V16InstalledUITests.swift.
// It uses the file-private native Home install helpers. Do not add as a separate file.
extension V16InstalledUITests {
    private struct URLCarrierReceipt {
        let phase: String
        let document: String
    }

    private func urlVisibleControls(_ label: String) -> [XCUIElement] {
        let buttons = host.buttons.matching(NSPredicate(format: "label == %@", label)).allElementsBoundByIndex
        let links = host.links.matching(NSPredicate(format: "label == %@", label)).allElementsBoundByIndex
        return (buttons + links).filter { $0.exists && $0.isEnabled && $0.isHittable }
    }

    private func urlTapControl(_ label: String) throws {
        let ready = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            self.urlVisibleControls(label).count == 1
        }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [ready], timeout: 12), .completed, "Unique native action unavailable: " + label)
        let hits = urlVisibleControls(label)
        XCTAssertEqual(hits.count, 1, "Ambiguous native action: " + label)
        try XCTUnwrap(hits.first).tap()
    }

    private func urlTapLink(_ label: String) throws {
        try nativeTapReviewedMenuLink(label)
    }

    private func urlDockOpen() {
        nativeEnsureMainOpen(in: host)
    }

    private func urlEvidencePanel() {
        urlDockOpen()
        openEvidenceExport()
        revealQuickResult("Freeze", in: host)
        XCTAssertTrue(host.buttons["Freeze"].isHittable, "Actual current Freeze must be AX-accessible")
    }

    private func urlMenu() throws {
        try nativeMenuEntry()
        XCTAssertTrue(host.links["V16 URL/state controls"].waitForExistence(timeout: 12))
    }

    private func urlHistory(_ label: String) throws {
        nativeEnsureDisclosureOpen("Declared browser navigation", in: host,
            childExists: { self.host.buttons["Browser Back"].exists })
        try urlTapControl(label)
    }

    private func urlSnapshot(_ phase: String) throws -> URLCarrierReceipt {
        XCTAssertEqual(host.state, .runningForeground, "Actual WebClip host required")
        XCTAssertNotEqual(XCUIApplication(bundleIdentifier: "com.apple.mobilesafari").state, .runningForeground)
        urlEvidencePanel()
        largeWitnessMayExist = true
        uniqueTap("Freeze", in: host)
        let frozen = text("Frozen [0-9]+ UTF-8 bytes;.*", in: host, timeout: 15).label
        revealQuickResult("Pack frozen witness", in: host)
        uniqueTap("Pack frozen witness", in: host)
        revealEvidenceMenu()
        let packets = host.staticTexts.matching(NSPredicate(
            format: "label BEGINSWITH %@", "{\"format\":\"v13-gzip-export-carrier-v1\""
        ))
        XCTAssertTrue(packets.firstMatch.waitForExistence(timeout: 20))
        let unique = Set(packets.allElementsBoundByIndex.map(\.label))
        XCTAssertEqual(unique.count, 1, "Ambiguous native carrier")
        let carrier = try XCTUnwrap(unique.first)
        let bytes = Data(carrier.utf8)
        XCTAssertLessThan(bytes.count, 2 * 1024 * 1024, "Bound native transfer size")
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let packed = text("Packed \(bytes.count) UTF-8 carrier bytes; SHA-256 \(digest);.*", in: host, timeout: 15).label
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let original = try XCTUnwrap(object["original"] as? [String: Any])
        let packing = try XCTUnwrap(object["packing"] as? [String: Any])
        XCTAssertEqual(object["format"] as? String, "v13-gzip-export-carrier-v1")
        XCTAssertEqual(original["originalUIStatus"] as? String, frozen, "Old carrier cannot satisfy new Freeze")
        XCTAssertEqual(original["candidateEntrySHA256"] as? String, "e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641")
        XCTAssertEqual(original["candidateSourceTreeSHA256"] as? String, "24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b")
        XCTAssertEqual(packing["trustedClick"] as? Bool, true)
        XCTAssertEqual(packing["roundTripVerified"] as? Bool, true)
        XCTAssertEqual(packing["productStateModified"] as? Bool, false)
        XCTAssertEqual(packing["nativeMediaModified"] as? Bool, false)
        let document = try XCTUnwrap(original["documentInstance"] as? String)
        XCTAssertFalse(document.isEmpty)
        attachment("v16-url-\(phase)-carrier-json", carrier)
        var receipt: [String: Any] = [
            "schema": "v16-installed-url-xcui-receipt-v1", "phase": phase,
            "carrierBytes": bytes.count, "carrierSHA256": digest,
            "documentInstance": document, "originalSHA256": original["sha256"] ?? NSNull(),
            "frozenAX": frozen, "packedAX": packed,
            "input": "actual XCUI AX label", "host": "com.apple.webapp",
            "standaloneInjected": false, "nativeHostForeground": host.state == .runningForeground
        ]
        if let nativeUDID = ProcessInfo.processInfo.environment["SIMULATOR_UDID"] { receipt["nativeEnvironmentUDID"] = nativeUDID }
        attachment("v16-url-\(phase)-native-receipt", String(decoding:
            try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys]), as: UTF8.self))
        screen("v16-url-\(phase)")
        // Never use full AX/debugDescription after Freeze.
        nativeSummaryTap("Evidence export", in: host)
        nativeSummaryTap("V16 verification controls", in: host)
        return URLCarrierReceipt(phase: phase, document: document)
    }

    func testV16InstalledURLStateAndHistory() throws {
        // Dedicated URL-only CI run: fresh real Safari install precedes this test.
        // Never call Pin/Prepare/Unmute, OS audio capture, WebDriver JS or UA overrides.
        launchHomeIcon(requireAudioControls: false)
        try urlMenu()
        try urlTapLink("V16 referrals alias controls")
        try requireNativeReferralsHeading()
        let initial = try urlSnapshot("referrals-initial")
        try urlTapControl("referrals") // actual product gift/header toggle
        let closed = try urlSnapshot("referrals-closed")
        XCTAssertEqual(closed.document, initial.document)
        try urlHistory("Browser Back")
        let back = try urlSnapshot("referrals-back")
        XCTAssertEqual(back.document, initial.document)
        try urlHistory("Browser Forward")
        let forward = try urlSnapshot("referrals-forward")
        XCTAssertEqual(forward.document, initial.document)
        try urlHistory("Browser Back")
        let beforeReload = try urlSnapshot("referrals-before-reload")
        XCTAssertEqual(beforeReload.document, initial.document)
        try urlHistory("Reload document")
        _ = text(".*V16.*e7ab13f79d01.*", in: host, timeout: 30)
        let reloaded = try urlSnapshot("referrals-reloaded")
        XCTAssertNotEqual(reloaded.document, initial.document)

        try urlMenu()
        try urlTapLink("V16 URL/state controls")
        _ = text("Device settings", in: host, timeout: 15)
        _ = text("acced23acced2302", in: host, timeout: 8)
        screen("v16-url-settings-cold-modal")
        attachment("v16-url-settings-cold-modal-native",
                   "Actual native Device settings and device B caption; full state is not inferred from this screenshot.")
        try urlTapControl("Close")
        let settingsClosed = try urlSnapshot("settings-closed")
        try urlHistory("Browser Back")
        _ = text("Device settings", in: host, timeout: 12)
        _ = text("acced23acced2302", in: host, timeout: 8)
        screen("v16-url-settings-back-reopened-modal")
        // Modal aria-hidden behavior can make external lab buttons unavailable to AX.
        // Use the real modal Close, and prove the closed-state payload after both visits.
        try urlTapControl("Close")
        let settingsClosedAgain = try urlSnapshot("settings-closed-again")
        XCTAssertEqual(settingsClosedAgain.document, settingsClosed.document)
        XCUIDevice.shared.press(.home)
    }
}

