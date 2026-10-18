// V2 PROPOSAL ONLY. Append to the SAME current mobile-CI V16InstalledUITests.swift file after review.
// Uses existing private AX/attachment helpers. No new installation or audio graph.
import CoreFoundation
extension V16InstalledUITests {
    private func nfNativeLink(_ label: String) throws {
        let query = host.links.matching(NSPredicate(format: "label == %@", label))
        XCTAssertTrue(query.firstMatch.waitForExistence(timeout: 8), "Missing reviewed same-shell link: " + label)
        XCTAssertEqual(query.count, 1)
        // Real bounded gestures only; do not click a guessed coordinate or alter page URL.
        for _ in 0..<3 { if query.element.isHittable { break }; host.swipeUp() }
        XCTAssertTrue(query.element.isHittable); query.element.tap()
    }
    private func nfSummaryExists(_ name: String) -> Bool {
        let queries = host.buttons.matching(identifier: name).allElementsBoundByIndex
            + host.otherElements.matching(identifier: name).allElementsBoundByIndex
        return queries.contains { $0.exists }
    }
    private func nfOpenMain() {
        // Child presence distinguishes collapsed dock from a closed nested detail.
        // Stop on inaccessible/ambiguous actual AX instead of toggling it speculatively.
        if !nfSummaryExists("Native failure input controls") && !nfSummaryExists("Evidence export") {
            nativeSummaryTap("V16 verification controls", in: host)
        }
    }
    private func nfOpenWitnessControls() {
        nfOpenMain()
        if !host.buttons["Freeze actual native witness"].exists {
            nativeSummaryTap("Native failure input controls", in: host)
        }
        XCTAssertTrue(host.buttons["Freeze actual native witness"].isHittable)
    }
    private func nfExposeProduct() {
        XCTAssertTrue(nfSummaryExists("Native failure input controls"))
        nativeSummaryTap("V16 verification controls", in: host)
    }
    private func nfMenu() throws {
        openEvidenceExport()
        try nfNativeLink("Menu")
    }
    private func nfLaunchInstalledIcon() {
        // Shared actual-Home search; audio-only quick controls are not required after NF/NG.
        launchHomeIcon(requireAudioControls: false)
    }
    private func nfNumber(_ value: Any?) throws -> Double {
        let number = try XCTUnwrap(value as? NSNumber)
        XCTAssertNotEqual(CFGetTypeID(number), CFBooleanGetTypeID(), "Numeric source field required")
        let result = number.doubleValue; XCTAssertTrue(result.isFinite); return result
    }
    private func nfObject(_ value: Any?) throws -> [String: Any] {
        try XCTUnwrap(value as? [String: Any])
    }
    private func nfFreeze(_ count: Int, name: String) throws -> [String: Any] {
        nfOpenWitnessControls(); largeWitnessMayExist = true
        uniqueTap("Freeze actual native witness", in: host)
        _ = text("Frozen \(count) complete", in: host, timeout: 12)
        let query = host.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "{\"format\":\"actual-native-MediaError-fixture-v1\""))
        XCTAssertTrue(query.firstMatch.waitForExistence(timeout: 8))
        let strings = Set(query.allElementsBoundByIndex.map(\.label))
        XCTAssertEqual(strings.count, 1, "Actual NF AX report must be complete and unambiguous")
        let raw = try XCTUnwrap(strings.first), bytes = Data(raw.utf8)
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let report = try nfObject(JSONSerialization.jsonObject(with: bytes))
        let points = try XCTUnwrap(report["freezes"] as? [[String: Any]])
        XCTAssertEqual(points.count, count)
        let point = try XCTUnwrap(points.last), config = try nfObject(point["config"])
        let document = try XCTUnwrap(point["documentInstance"] as? String); XCTAssertFalse(document.isEmpty)
        for frozen in points {
            let frozenConfig = try nfObject(frozen["config"])
            XCTAssertEqual(frozen["documentInstance"] as? String, document)
            XCTAssertEqual(frozen["trusted"] as? Bool, true)
            XCTAssertEqual(frozen["standaloneNavigator"] as? Bool, true); XCTAssertEqual(frozen["standaloneDisplay"] as? Bool, true)
            XCTAssertEqual(frozenConfig["entrySHA256"] as? String, "e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641")
            XCTAssertEqual(frozenConfig["candidateSourceTreeSHA256"] as? String, "24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b")
        }
        for (left, right) in zip(points, points.dropFirst()) {
            XCTAssertLessThan(try nfNumber(left["atMs"]), try nfNumber(right["atMs"]))
        }
        XCTAssertEqual(point["trusted"] as? Bool, true)
        XCTAssertEqual(point["standaloneNavigator"] as? Bool, true)
        XCTAssertEqual(point["standaloneDisplay"] as? Bool, true)
        XCTAssertEqual(config["entrySHA256"] as? String, "e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641")
        XCTAssertEqual(config["candidateSourceTreeSHA256"] as? String, "24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b")
        attachment("v16-nf-" + name + "-AX-json", raw)
        attachment("v16-nf-" + name + "-AX-receipt", "bytes=\(bytes.count); sha256=\(digest); actual complete AX label; not a Frozen-status hash")
        screen("v16-nf-" + name)
        return report
    }
    private func nfLatest(_ report: [String: Any]) throws -> [String: Any] {
        try XCTUnwrap((report["freezes"] as? [[String: Any]])?.last)
    }
    private func nfTransport(_ point: [String: Any], name: String) throws -> String {
        let native = try nfObject(point["native"]), drive = try nfObject(point["driveVideo"])
        let cap = try nfObject(point["capabilities"]), adapter = try nfObject(drive["nativeAdapter"])
        let uri = native["src"] as? String ?? ""
        let branch: String
        if uri.hasPrefix("https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/"),
           cap["hlsEnginePresent"] as? Bool == false, drive["hlsSource"] is NSNull,
           adapter["nativeSourceAttachedForCurrentLoad"] as? Bool == true {
            branch = "ACTUAL_NATIVE_HTTP_NO_HLS_ENGINE"
        } else if uri.hasPrefix("blob:"), cap["hlsEnginePresent"] as? Bool == true,
                  (drive["hlsSource"] as? String)?.hasPrefix("https://") == true,
                  adapter["readyForCurrentTransport"] as? Bool == true,
                  adapter["nativeSourceAttachedForCurrentLoad"] as? Bool == false {
            branch = "ACTUAL_BLOB_HLS_TRANSPORT_MSE_OR_MMS_CLASS_NOT_DIRECTLY_OBSERVED"
        } else { branch = "ACTUAL_TRANSPORT_UNQUALIFIED" }
        attachment("v16-nf-" + name + "-transport", String(decoding: try JSONSerialization.data(withJSONObject:
            ["branch": branch, "nativeSrc": uri, "capabilities": cap, "nativeAdapter": adapter,
             "scope": "Actual source/binding. MSE versus MMS constructor identity is not present in this witness; capability presence alone cannot identify it."], options: [.sortedKeys]), as: UTF8.self))
        return branch
    }
    private func nfRequireNativeHTTP(_ point: [String: Any]) throws {
        guard try nfTransport(point, name: "failure") == "ACTUAL_NATIVE_HTTP_NO_HLS_ENGINE" else {
            throw XCTSkip("NATIVE_HTTP_BRANCH_UNACQUIRED: preserve actual blob/MMS/MSE branch. No UA/API override permitted.")
        }
    }
    private func nfVerifyOwnedRecovery(_ report: [String: Any], latest: [String: Any],
                                        restored: [String: Any], recovered: [String: Any]) throws {
        let latestDrive = try nfObject(latest["driveVideo"]), request = try nfObject(latestDrive["seekRequest"])
        let requestID = try nfNumber(request["id"]), targetMs = try nfNumber(request["offset"])
        let target = targetMs / 1000, restoredAt = try nfNumber(restored["atMs"])
        let good = try nfObject(recovered["native"]), newOwner = try nfNumber(good["owner"])
        let newLoad = try nfNumber(try nfObject(recovered["driveVideo"])["loadId"])
        XCTAssertEqual(try nfNumber(latestDrive["videoStartOffset"]), 0,
                       "This generated fixture's route/native mapping must actually be identity")
        let events = try XCTUnwrap(report["events"] as? [[String: Any]])
        let ownedEvents = events.filter { event in
            guard event["trusted"] as? Bool == true, let t = event["atMs"] as? NSNumber,
                  let n = event["native"] as? [String: Any], let owner = n["owner"] as? NSNumber else { return false }
            return t.doubleValue > restoredAt && owner.doubleValue == newOwner
        }
        let seeking = try XCTUnwrap(ownedEvents.first { $0["kind"] as? String == "native:seeking" })
        let seekingAt = try nfNumber(seeking["atMs"])
        let seeked = try XCTUnwrap(ownedEvents.first { $0["kind"] as? String == "native:seeked" })
        let seekedAt = try nfNumber(seeked["atMs"])
        let playing = try XCTUnwrap(ownedEvents.first { $0["kind"] as? String == "native:playing" && (($0["atMs"] as? NSNumber)?.doubleValue ?? -1) >= seekedAt })
        XCTAssertLessThan(seekingAt, seekedAt); XCTAssertLessThanOrEqual(seekedAt, try nfNumber(playing["atMs"]))
        let seekingNative = try nfObject(seeking["native"]), seekedNative = try nfObject(seeked["native"])
        XCTAssertEqual(seekingNative["seeking"] as? Bool, true)
        // Reuse product ownsSeekCompletion's1µs floating-point roundoff contract only
        // while actual native seeking is still true, before the moving seeked getter.
        XCTAssertEqual(try nfNumber(seekingNative["currentTime"]), target, accuracy: 0.000001)
        XCTAssertEqual(seekedNative["seeking"] as? Bool, false)
        XCTAssertGreaterThanOrEqual(try nfNumber(seekedNative["readyState"]), 2)
        XCTAssertTrue(seekedNative["error"] is NSNull)
        XCTAssertEqual(try nfObject(playing["native"])["paused"] as? Bool, false)
        // The owned command's target is stationary. A post-resume seeked getter is moving.
        // Match the target/request/load/source/element/engine in an actual retained NF row.
        let rows = try XCTUnwrap(report["rows"] as? [[String: Any]])
        let owned = try XCTUnwrap(rows.first { row in
            guard let time = row["atMs"] as? NSNumber, time.doubleValue > restoredAt,
                  let n = row["native"] as? [String: Any], (n["owner"] as? NSNumber)?.doubleValue == newOwner,
                  let d = row["driveVideo"] as? [String: Any], (d["loadId"] as? NSNumber)?.doubleValue == newLoad,
                  let req = d["seekRequest"] as? [String: Any], (req["id"] as? NSNumber)?.doubleValue == requestID,
                  (req["offset"] as? NSNumber)?.doubleValue == targetMs,
                  (d["appliedSeekId"] as? NSNumber)?.doubleValue == requestID,
                  let cmd = d["seekCompletion"] as? [String: Any] else { return false }
            return (cmd["seekId"] as? NSNumber)?.doubleValue == requestID
                && (cmd["target"] as? NSNumber)?.doubleValue == target
                && abs(((cmd["routeMs"] as? NSNumber)?.doubleValue ?? .infinity) - targetMs) <= 0.000001
                && ["elementMatchesNative", "engineMatchesCurrent", "sourceMatchesCurrent", "loadIdMatchesCurrent", "seekIdMatchesCurrent"].allSatisfy { cmd[$0] as? Bool == true }
        }, "Latest owned request/completion row missing from bounded120-row NF history; cannot prove exact target")
        XCTAssertEqual(try nfObject(owned["native"])["src"] as? String, good["src"] as? String)
        XCTAssertEqual(seekingNative["src"] as? String, good["src"] as? String)
        XCTAssertEqual(seekedNative["src"] as? String, good["src"] as? String)
        // No arbitrary target±Nms test on playing getters. Retain actual numeric clocks and
        // require monotonic recovery chronology; exact target proof above is command ownership.
        attachment("v16-nf-owned-recovery-target-and-events", String(decoding: try JSONSerialization.data(withJSONObject:
            ["latestRequest": request, "ownedCompletionRow": owned, "firstOwnedSeeking": seeking,
             "firstOwnedSeeked": seeked, "firstOwnedPlayingAfterSeeked": playing,
             "scope": "Exact observed command target and owned native event chronology; no direct native setter interception or frozen moving-clock equality claim."], options: [.sortedKeys]), as: UTF8.self))
    }
    private func nfVerifyEOFEvents(_ report: [String: Any], final: [String: Any]) throws {
        let n = try nfObject(final["native"]), owner = try nfNumber(n["owner"])
        let cutoff = try nfNumber(final["atMs"]), uri = try XCTUnwrap(n["src"] as? String)
        let events = try XCTUnwrap(report["events"] as? [[String: Any]]).filter { event in
            event["trusted"] as? Bool == true
                && ((event["atMs"] as? NSNumber)?.doubleValue ?? .infinity) <= cutoff
                && ((event["native"] as? [String: Any])?["owner"] as? NSNumber)?.doubleValue == owner
        }
        let ends = events.filter { $0["kind"] as? String == "native:ended" }
        XCTAssertGreaterThanOrEqual(ends.count, 3)
        for (index, end) in ends.enumerated() {
            let at = try nfNumber(end["atMs"])
            let until = index + 1 < ends.count ? try nfNumber(ends[index + 1]["atMs"]) : cutoff
            let interval = events.filter { (($0["atMs"] as? NSNumber)?.doubleValue ?? -1) > at
                && (($0["atMs"] as? NSNumber)?.doubleValue ?? .infinity) <= until }
            let seeking = try XCTUnwrap(interval.first { $0["kind"] as? String == "native:seeking" })
            let seeked = try XCTUnwrap(interval.first { $0["kind"] as? String == "native:seeked" })
            let seekedAt = try nfNumber(seeked["atMs"])
            let playing = try XCTUnwrap(interval.first { $0["kind"] as? String == "native:playing"
                && (($0["atMs"] as? NSNumber)?.doubleValue ?? -1) >= seekedAt })
            XCTAssertLessThan(try nfNumber(seeking["atMs"]), seekedAt)
            XCTAssertEqual(interval.filter { $0["kind"] as? String == "native:seeking" }.count, 1)
            XCTAssertEqual(interval.filter { $0["kind"] as? String == "native:seeked" }.count, 1)
            let start = try nfObject(seeking["native"]), done = try nfObject(seeked["native"])
            XCTAssertEqual(start["seeking"] as? Bool, true)
            XCTAssertEqual(try nfNumber(start["currentTime"]), 1.001, accuracy: 0.000001)
            XCTAssertEqual(done["seeking"] as? Bool, false); XCTAssertGreaterThanOrEqual(try nfNumber(done["readyState"]), 2)
            XCTAssertTrue(done["error"] is NSNull)
            for event in [end, seeking, seeked, playing] {
                XCTAssertEqual(try nfObject(event["native"])["src"] as? String, uri)
            }
            XCTAssertEqual(try nfObject(playing["native"])["paused"] as? Bool, false)
        }
        // Native-clock prehandler EOF endpoint and retained frames are verified offline in the
        // exact global source. Trusted NF ended listener may run after product already rewound.
    }
    private func nfHTTPReceipts(_ report: [String: Any]) throws -> Bool {
        // Server response-byte receipts, not a client wire-body capture. State is isolate-local.
        let healthy: [String: (bytes: Int, sha256: String)] = [
            "segment-00.ts": (381264, "14548b6cf62bf4d8ebbbe08d6205ed5c8aa3db7e62b67971cefe1acce039f3df"),
            "segment-01.ts": (411156, "49d2b2af14ffd1b864220bb27d9135d8de0dbd44dc23eb73b78d80f58fa640af"),
            "segment-02.ts": (404764, "8f295563899026335ecec7c5bd7367123fa38ea20d126cb2c4a0063f23047246"),
            "segment-03.ts": (416232, "3936b2e4d655e15085ed1fb3a05c4469176c7cac193b38d49a9c99e9867e1e41"),
            "segment-04.ts": (380888, "3c1a06ac49412684260c5cf1f68122cc6a9a78f732f7cf92caa352e033fe6926"),
            "segment-05.ts": (397056, "86eb43913676c8636a2c4ae44300dc0bb655bbe0a055135029da7ed7192bd4eb")
        ]
        let fixture = try nfObject(report["fixture"]), id = try XCTUnwrap(fixture["id"] as? String)
        var states = [fixture]
        for point in (report["freezes"] as? [[String: Any]] ?? []) {
            if let value = point["fixtureAtCapture"] as? [String: Any] { states.append(value) }
        }
        let events = report["events"] as? [[String: Any]] ?? []
        let restore = try XCTUnwrap(events.first { $0["kind"] as? String == "fixture-http-restored" && $0["trusted"] as? Bool == true })
        if let value = restore["fixture"] as? [String: Any] { states.append(value) }
        XCTAssertFalse(id.isEmpty); XCTAssertTrue(states.allSatisfy { $0["id"] as? String == id })
        let receipts = states.flatMap { $0["requests"] as? [[String: Any]] ?? [] }
        let bad = receipts.filter { $0["mode"] as? String == "broken" }
        let good = receipts.filter { $0["mode"] as? String == "healthy" }
        let badValid = bad.allSatisfy { ($0["status"] as? NSNumber)?.intValue == 200
            && ($0["bytes"] as? NSNumber)?.intValue == 12032
            && $0["sha256"] as? String == "12a42cfe372b164bdba3fcaf9084fc39b2032c8aec11bdf0c2acb46a6b614fb7" }
        let goodValid = good.allSatisfy { receipt in
            guard let uri = receipt["uri"] as? String, let url = URL(string: uri),
                  let signature = healthy[url.lastPathComponent] else { return false }
            return (receipt["status"] as? NSNumber)?.intValue == 200
                && (receipt["bytes"] as? NSNumber)?.intValue == signature.bytes
                && receipt["sha256"] as? String == signature.sha256
        }
        XCTAssertTrue(badValid, "Observed broken response receipt does not match generated malformed200 bytes")
        XCTAssertTrue(goodValid, "Observed healthy response receipt does not match frozen generated segment bytes")
        let date = ISO8601DateFormatter(); date.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let restoredFixture = try nfObject(restore["fixture"])
        let restoredUTC = (restoredFixture["restoredUTC"] as? String).flatMap { date.date(from: $0) }
        let pairs = bad.flatMap { broken in good.compactMap { healthyReceipt -> [String: Any]? in
            guard let uri = broken["uri"] as? String, healthyReceipt["uri"] as? String == uri,
                  let beforeUTC = broken["atUTC"] as? String, let afterUTC = healthyReceipt["atUTC"] as? String,
                  let before = date.date(from: beforeUTC), let after = date.date(from: afterUTC),
                  let restoredUTC, before <= restoredUTC, restoredUTC <= after else { return nil }
            return ["uri": uri, "broken": broken, "healthy": healthyReceipt]
        } }
        let observed = badValid && goodValid && !pairs.isEmpty
        attachment("v16-nf-same-URI-HTTP-byte-receipts", String(decoding: try JSONSerialization.data(withJSONObject:
            ["status": observed ? "OBSERVED_SAME_URI_MALFORMED200_THEN_HEALTHY_SERVER_BODY_RECEIPTS" : "HTTP_BYTES_UNACQUIRED_OR_MISMATCH",
             "states": states, "sameURIPairs": pairs,
             "scope": "Real exported generated-server body/hash receipts only. Cookie mode or metadata declarations alone do not prove response bytes; absent isolate history remains missing. No client wire-body/physical network inference."], options: [.sortedKeys]), as: UTF8.self))
        return observed
    }
    private func nfPackGlobal(_ name: String) throws {
        // Collapse NF body before revealing the original export; no audio Export-all prerequisite.
        nfOpenMain()
        if host.buttons["Freeze actual native witness"].exists {
            nativeSummaryTap("Native failure input controls", in: host)
        }
        openEvidenceExport()
        revealQuickResult("Freeze", in: host)
        XCTAssertTrue(host.buttons["Freeze"].isHittable)
        uniqueTap("Freeze", in: host)
        let frozen = text("Frozen [0-9]+ UTF-8 bytes;.*", in: host, timeout: 15).label
        revealQuickResult("Pack frozen witness", in: host)
        uniqueTap("Pack frozen witness", in: host)
        revealEvidenceMenu()
        let status = text("Packed [0-9]+ UTF-8 carrier bytes; SHA-256 [0-9a-f]{64};.*", in: host, timeout: 20).label
        let q = host.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "{\"format\":\"v13-gzip-export-carrier-v1\""))
        XCTAssertTrue(q.firstMatch.waitForExistence(timeout: 8))
        let values = Set(q.allElementsBoundByIndex.map(\.label)); XCTAssertEqual(values.count, 1)
        let raw = try XCTUnwrap(values.first), bytes = Data(raw.utf8)
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(status.hasPrefix("Packed \(bytes.count) UTF-8 carrier bytes; SHA-256 \(digest);"))
        let carrier = try nfObject(JSONSerialization.jsonObject(with: bytes)), packing = try nfObject(carrier["packing"])
        XCTAssertEqual(packing["trustedClick"] as? Bool, true); XCTAssertEqual(packing["roundTripVerified"] as? Bool, true)
        attachment("v16-nf-" + name + "-full-carrier", raw)
        attachment("v16-nf-" + name + "-original-status", frozen)
        attachment("v16-nf-" + name + "-packed-status", status)
    }
    func testV16InstalledNativeFailureContinuation() throws {
        // Requires reviewed menu correction published, actual V16 install already complete.
        nfLaunchInstalledIcon(); defer { XCUIDevice.shared.press(.home) }; try nfMenu()
        try nfNativeLink("Native MediaError and ordinary Play /nf") // href now /v16/nf
        _ = text(".*V16.*e7ab13f79d01.*", in: host, timeout: 20)
        Thread.sleep(forTimeInterval: 5)
        let firstReport = try nfFreeze(1, name: "initial-failure"), first = try nfLatest(firstReport)
        do { try nfRequireNativeHTTP(first) } catch {
            try nfPackGlobal("observed-nonnative-branch"); throw error
        }
        let native = try nfObject(first["native"]), drive = try nfObject(first["driveVideo"])
        let mediaError = native["error"] as? [String: Any]
        let code4 = (mediaError?["code"] as? NSNumber)?.intValue == 4
        let unavailableNull = native["error"] is NSNull && drive["selectionUnavailable"] as? Bool == true
            && native["ended"] as? Bool == true && drive["videoError"] is String
            && (drive["desiredPlaySpeed"] as? NSNumber)?.doubleValue == 0
        guard code4 || unavailableNull else {
            try nfPackGlobal("failure-shape-not-reproduced")
            throw XCTSkip("Expected native error4 or ended/error-null unavailable shape not acquired; no generic500/PWA-pass substitution")
        }
        let firstEvents = try XCTUnwrap(firstReport["events"] as? [[String: Any]])
        let failedOwner = try nfNumber(native["owner"])
        let realFailureEvent = firstEvents.first { event in
            guard event["trusted"] as? Bool == true, let observed = event["native"] as? [String: Any],
                  (observed["owner"] as? NSNumber)?.doubleValue == failedOwner else { return false }
            if code4 { return event["kind"] as? String == "native:error" && ((observed["error"] as? [String: Any])?["code"] as? NSNumber)?.intValue == 4 }
            return event["kind"] as? String == "native:ended" && observed["error"] is NSNull
        }
        guard realFailureEvent != nil else {
            try nfPackGlobal("failure-event-unacquired"); throw XCTSkip("Real failure shape observed but matching trusted native error/ended event not retained")
        }
        attachment("v16-nf-failure-class", code4 ? "actual-native-MediaError-code4" : "actual-ended-error-null-unavailable")
        nfExposeProduct(); uniqueTap("Jump forward 10 seconds", in: host)
        let latestReport = try nfFreeze(2, name: "latest-request"), latest = try nfLatest(latestReport)
        let firstRequest = try nfObject(drive["seekRequest"])
        let latestRequest = try nfObject(try nfObject(latest["driveVideo"])["seekRequest"])
        XCTAssertGreaterThan(try nfNumber(latestRequest["id"]), try nfNumber(firstRequest["id"]))
        XCTAssertEqual(try nfNumber(latestRequest["offset"]), try nfNumber(firstRequest["offset"]) + 10000)
        XCTAssertEqual(try nfNumber(try nfObject(latest["native"])["owner"]), failedOwner)
        XCTAssertEqual(try nfNumber(try nfObject(latest["driveVideo"])["loadId"]), try nfNumber(drive["loadId"]))
        XCTAssertEqual(try nfNumber(try nfObject(latest["driveVideo"])["desiredPlaySpeed"]), 0)
        uniqueTap("Restore generated bytes only", in: host)
        _ = text("HTTP restored; native/player untouched; press actual product Play\\.", in: host, timeout: 12)
        let restoredReport = try nfFreeze(3, name: "HTTP-restored-only"), restored = try nfLatest(restoredReport)
        let restoredNative = try nfObject(restored["native"]), restoredDrive = try nfObject(restored["driveVideo"])
        XCTAssertEqual(try nfNumber(restoredNative["owner"]), try nfNumber(native["owner"]))
        XCTAssertEqual(try nfNumber(restoredDrive["loadId"]), try nfNumber(drive["loadId"]))
        XCTAssertEqual(try nfNumber(restoredDrive["desiredPlaySpeed"]), 0)
        XCTAssertFalse((restoredNative["error"] is NSNull)
            && (restoredDrive["selectionUnavailable"] as? Bool != true),
            "HTTP restore alone must remain failed/unavailable; no new owner or Play has occurred")
        nfExposeProduct(); uniqueTap("Unpause", in: host) // actual ordinary App Play; never Retry
        Thread.sleep(forTimeInterval: 4)
        let recoveredReport = try nfFreeze(4, name: "ordinary-Play-recovered"), recovered = try nfLatest(recoveredReport)
        let good = try nfObject(recovered["native"]), goodDrive = try nfObject(recovered["driveVideo"])
        XCTAssertNotEqual(try nfNumber(good["owner"]), try nfNumber(native["owner"]))
        XCTAssertGreaterThan(try nfNumber(goodDrive["loadId"]), try nfNumber(drive["loadId"]))
        XCTAssertEqual(good["src"] as? String, native["src"] as? String)
        XCTAssertGreaterThanOrEqual(try nfNumber(good["readyState"]), 2)
        XCTAssertEqual(good["paused"] as? Bool, false); XCTAssertTrue(good["error"] is NSNull)
        XCTAssertEqual(goodDrive["selectionUnavailable"] as? Bool, false)
        XCTAssertTrue(goodDrive["videoError"] is NSNull); XCTAssertEqual(goodDrive["isBufferingVideo"] as? Bool, false)
        XCTAssertGreaterThan(try nfNumber(goodDrive["desiredPlaySpeed"]), 0)
        XCTAssertEqual(recovered["documentInstance"] as? String, first["documentInstance"] as? String)
        try nfRequireNativeHTTP(recovered)
        try nfVerifyOwnedRecovery(recoveredReport, latest: latest, restored: restored, recovered: recovered)
        let observedHTTPBytes = try nfHTTPReceipts(recoveredReport)
        try nfPackGlobal("failure-recovery-complete")
        if !observedHTTPBytes {
            throw XCTSkip("RECOVERY_NATIVE_FACTS_RETAINED_BUT_SAME_URI_HTTP_BYTES_UNACQUIRED: isolate receipts unavailable; no malformed200/healthy bytes claim")
        }
        // Offline native assessor still requires frame proof,
        // original/packed hashes and distinct native-error4 vs ended/error-null event predicates.
    }
    func testV16InstalledNaturalEOFContinuation() throws {
        nfLaunchInstalledIcon(); defer { XCUIDevice.shared.press(.home) }; try nfMenu()
        try nfNativeLink("V16 natural EOF 20-second request")
        _ = text(".*V16.*e7ab13f79d01.*", in: host, timeout: 20)
        Thread.sleep(forTimeInterval: 3)
        let first = try nfLatest(nfFreeze(1, name: "wide-EOF-requested"))
        let loop = try nfObject(try nfObject(first["media"])["loop"])
        XCTAssertEqual(try nfNumber(loop["startTime"]), 1001)
        XCTAssertEqual(try nfNumber(loop["startTime"]) + nfNumber(loop["duration"]), 20000)
        let firstTransport = try nfTransport(first, name: "EOF-initial")
        guard firstTransport != "ACTUAL_TRANSPORT_UNQUALIFIED" else {
            try nfPackGlobal("EOF-transport-unqualified"); throw XCTSkip("EOF transport not qualified from actual source/binding")
        }
        let initial = try nfObject(first["native"])
        XCTAssertGreaterThan(20, try nfNumber(initial["duration"]))
        XCTAssertEqual(initial["paused"] as? Bool, false); XCTAssertEqual(initial["muted"] as? Bool, true)
        XCTAssertGreaterThanOrEqual(try nfNumber(initial["readyState"]), 2)
        nfExposeProduct(); Thread.sleep(forTimeInterval: 38)
        let finalReport = try nfFreeze(2, name: "three-natural-EOF-observation"), final = try nfLatest(finalReport)
        let events = try XCTUnwrap(finalReport["events"] as? [[String: Any]])
        let ended = events.filter { $0["kind"] as? String == "native:ended" && $0["trusted"] as? Bool == true }
        XCTAssertGreaterThanOrEqual(ended.count, 3, "Actual EOF events required; internal3s selection is not a substitute")
        let finalTransport = try nfTransport(final, name: "EOF-final")
        XCTAssertEqual(firstTransport, finalTransport)
        XCTAssertEqual(first["documentInstance"] as? String, final["documentInstance"] as? String)
        XCTAssertEqual(try nfNumber(try nfObject(first["driveVideo"])["loadId"]), try nfNumber(try nfObject(final["driveVideo"])["loadId"]))
        let good = try nfObject(final["native"]), drive = try nfObject(final["driveVideo"])
        XCTAssertEqual(good["owner"] as? NSNumber, initial["owner"] as? NSNumber)
        XCTAssertEqual(good["src"] as? String, initial["src"] as? String)
        XCTAssertEqual(good["paused"] as? Bool, false); XCTAssertEqual(good["muted"] as? Bool, true)
        XCTAssertGreaterThanOrEqual(try nfNumber(good["readyState"]), 2); XCTAssertTrue(good["error"] is NSNull)
        XCTAssertEqual(drive["isBufferingVideo"] as? Bool, false); XCTAssertTrue(drive["videoError"] is NSNull)
        XCTAssertGreaterThan(try nfNumber(drive["desiredPlaySpeed"]), 0)
        try nfVerifyEOFEvents(finalReport, final: final)
        try nfPackGlobal("wide-natural-EOF-complete")
        // Offline pairs each EOF with owned1.001 command/real seeking, seeked/playing chronology, current frame/adapter
        // owners and unchanged document/load. Transport is classified from actual source/engine.
        // This is settled EOF coverage, NOT an exact in-flight loop-seek/Pause race hit.
    }
}
