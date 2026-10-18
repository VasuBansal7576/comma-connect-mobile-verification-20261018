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
    private func reviewedCurrentMenu() -> Bool {
        let audio = host.links.matching(NSPredicate(format: "label == %@", "V16 silent OS audio comparison"))
        let urls = host.links.matching(NSPredicate(format: "label == %@", "V16 URL/state controls"))
        let badge = host.staticTexts.matching(NSPredicate(format: "label MATCHES %@", ".*V16.*e7ab13f79d01.*"))
        // Presence, not visibility: these reviewed anchors can be below the current menu viewport.
        return audio.count == 1 && audio.element.exists && urls.count == 1 && urls.element.exists
            && badge.firstMatch.exists
    }
    private func nativeMainChildPresent(in app: XCUIApplication) -> Bool {
        app.buttons["Pin actual playlist"].exists
            || app.buttons["Evidence export"].exists || app.otherElements["Evidence export"].exists
            || app.buttons["Native failure input controls"].exists || app.otherElements["Native failure input controls"].exists
    }
    private func nativeEnsureDisclosureOpen(_ name: String, in app: XCUIApplication,
                                            childExists: @escaping () -> Bool) {
        if childExists() { return } // A present offscreen child is still proof that this disclosure is open.
        func summaryState() -> (count: Int, value: String?) {
            let buttons = app.buttons.matching(identifier: name)
            let query = buttons.firstMatch.exists ? buttons : app.otherElements.matching(identifier: name)
            let count = query.count
            return (count, count == 1 && query.element.exists ? query.element.value as? String : nil)
        }
        func retain(_ stage: String, _ state: (count: Int, value: String?), child: Bool) {
            let facts: [String: Any] = ["summary": name, "summaryCount": state.count,
                "summaryValue": state.value.map { String($0.prefix(256)) as Any } ?? NSNull(),
                "knownChildPresent": child, "scope": "Native disclosure navigation only; no source/media/phase assignments."]
            let data = (try? JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys])) ?? Data()
            attachment("v16-disclosure-" + stage, String(decoding: data, as: UTF8.self))
        }
        func waitForChild() -> Bool {
            let ready = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in childExists() }, object: nil)
            return XCTWaiter.wait(for: [ready], timeout: 8) == .completed
        }
        let before = summaryState()
        retain("before", before, child: false)
        // Explicit expanded native state with a late child must never be toggled closed.
        let performedPrimary = before.value?.hasPrefix("▾") != true
        if performedPrimary { nativeSummaryTap(name, in: app) }
        var ready = waitForChild()
        if !ready && performedPrimary && !childExists() {
            let after = summaryState()
            retain("after-primary", after, child: false)
            // The actual retained iOS AX collapsed marker qualifies this sole additional input.
            if after.count == 1, after.value?.hasPrefix("▸") == true {
                nativeSummaryTap(name, in: app)
                ready = waitForChild()
            }
        }
        retain("complete", summaryState(), child: ready)
        XCTAssertTrue(ready, "Actual disclosure child required after bounded expansion: " + name)
    }
    private func nativeEnsureMainOpen(in app: XCUIApplication) {
        nativeEnsureDisclosureOpen("V16 verification controls", in: app,
            childExists: { self.nativeMainChildPresent(in: app) })
    }
    private func nativeReveal(_ query: XCUIElementQuery, name: String, in app: XCUIApplication,
                              insideDock: Bool, maxSwipes: Int = 12) -> XCUIElement? {
        for swipes in 0...maxSwipes {
            let hits = query.allElementsBoundByIndex.filter { $0.exists }
            guard hits.count == 1 else { XCTFail("Unique actual reveal target required: " + name); return nil }
            let target = hits[0]
            guard target.isEnabled else { XCTFail("Actual reveal target disabled: " + name); return nil }
            if target.isHittable { return target }
            guard swipes < maxSwipes else { XCTFail("Actual target remains offscreen: " + name); return nil }
            let frame = target.frame
            let appFrame = app.frame
            var viewport = appFrame
            var measuredSummary: XCUIElement?
            var measuredSummaryFrame: CGRect?
            if insideDock {
                let summaries = app.buttons.matching(identifier: "V16 verification controls").allElementsBoundByIndex.filter { $0.exists }
                guard summaries.count == 1 else { XCTFail("Unique actual dock summary required"); return nil }
                measuredSummary = summaries[0]
                let summaryFrame = summaries[0].frame
                measuredSummaryFrame = summaryFrame
                let top = summaryFrame.maxY
                viewport = CGRect(x: viewport.minX, y: top, width: viewport.width, height: viewport.maxY - top)
            }
            let values = [frame.minX, frame.minY, frame.width, frame.height,
                          viewport.minX, viewport.minY, viewport.width, viewport.height]
            guard values.allSatisfy({ $0.isFinite }), frame.width > 0, frame.height > 0,
                  viewport.width > 0, viewport.height > 0, frame.height <= viewport.height,
                  frame.maxX > viewport.minX, frame.minX < viewport.maxX else {
                XCTFail("Unknown native reveal geometry: " + name); return nil
            }
            let direction: String
            if frame.minY < viewport.minY { direction = "down" }
            else if frame.maxY > viewport.maxY { direction = "up" }
            else { XCTFail("Nonhittable target inside observed viewport; refusing unknown obstruction: " + name); return nil }
            installCheckpoint("Reveal." + direction + ".before")
            if insideDock {
                // A full-app gesture can begin above this fixed panel and scroll the page.
                // Keep this native drag inside the freshly observed body below its summary.
                guard let summaryFrame = measuredSummaryFrame,
                      [appFrame.minX, appFrame.minY, appFrame.width, appFrame.height,
                       summaryFrame.minX, summaryFrame.minY, summaryFrame.width, summaryFrame.height].allSatisfy({ $0.isFinite }),
                      appFrame.width > 0, appFrame.height > 0, summaryFrame.width > 0, summaryFrame.height > 0,
                      summaryFrame.minX >= appFrame.minX, summaryFrame.maxX <= appFrame.maxX,
                      summaryFrame.minY >= appFrame.minY, summaryFrame.maxY < appFrame.maxY,
                      viewport.minX >= appFrame.minX, viewport.maxX <= appFrame.maxX,
                      viewport.minY > appFrame.minY, viewport.maxY <= appFrame.maxY else {
                    XCTFail("Unknown current app/summary/body geometry before dock gesture: " + name); return nil
                }
                let fromY = viewport.minY + viewport.height * (direction == "up" ? 0.7 : 0.3)
                let toY = viewport.minY + viewport.height * (direction == "up" ? 0.3 : 0.7)
                let start = app.coordinate(withNormalizedOffset: CGVector(
                    dx: (viewport.midX - appFrame.minX) / appFrame.width,
                    dy: (fromY - appFrame.minY) / appFrame.height))
                let end = app.coordinate(withNormalizedOffset: CGVector(
                    dx: (viewport.midX - appFrame.minX) / appFrame.width,
                    dy: (toY - appFrame.minY) / appFrame.height))
                let from = start.screenPoint, to = end.screenPoint
                let points = [from.x, from.y, to.x, to.y]
                guard points.allSatisfy({ $0.isFinite }), from.x == to.x,
                      from.x > viewport.minX, from.x < viewport.maxX,
                      from.y > viewport.minY, from.y < viewport.maxY,
                      to.y > viewport.minY, to.y < viewport.maxY,
                      direction == "up" ? to.y < from.y : to.y > from.y else {
                    XCTFail("Native dock gesture must remain inside measured positive body: " + name); return nil
                }
                let targetIdentifier = target.identifier, targetLabel = target.label
                let targetType = target.elementType
                let summaryIdentifier = measuredSummary?.identifier, summaryLabel = measuredSummary?.label
                let summaryType = measuredSummary?.elementType
                attachment("v16-dock-scroll-geometry", "target=\(name); direction=\(direction); app=\(appFrame); body=\(viewport); summary=\(String(describing: measuredSummaryFrame)); from=\(from); to=\(to)")
                let freshTargets = query.allElementsBoundByIndex.filter { $0.exists }
                let freshSummaries = app.buttons.matching(identifier: "V16 verification controls").allElementsBoundByIndex.filter { $0.exists }
                guard freshTargets.count == 1, freshSummaries.count == 1,
                      app.state == .runningForeground, app.frame == appFrame,
                      measuredSummary?.exists == true, measuredSummary?.frame == measuredSummaryFrame,
                      freshSummaries[0].frame == measuredSummaryFrame, freshSummaries[0].isEnabled,
                      freshSummaries[0].identifier == summaryIdentifier, freshSummaries[0].label == summaryLabel,
                      freshSummaries[0].elementType == summaryType,
                      freshTargets[0].isEnabled, freshTargets[0].identifier == targetIdentifier,
                      freshTargets[0].label == targetLabel, freshTargets[0].elementType == targetType,
                      freshTargets[0].frame == frame else {
                    XCTFail("Fresh native dock/target identity or geometry changed before gesture: " + name); return nil
                }
                if freshTargets[0].isHittable { return freshTargets[0] }
                start.press(forDuration: 0.05, thenDragTo: end)
            } else if direction == "up" { app.swipeUp() } else { app.swipeDown() }
            installCheckpoint("Reveal." + direction + ".after")
            let after = query.allElementsBoundByIndex.filter { $0.exists }
            guard after.count == 1 else { XCTFail("Reveal target changed ownership/uniqueness: " + name); return nil }
            let next = after[0].frame
            let progressed = direction == "up" ? next.minY < frame.minY : next.minY > frame.minY
            guard after[0].isHittable || progressed else {
                XCTFail("No observed target-frame progress after native gesture: " + name); return nil
            }
        }
        return nil
    }
    private func closeDeclaredNavigationIfOpen() {
        let back = host.buttons.matching(identifier: "Browser Back")
        if back.firstMatch.exists {
            let evidence = host.buttons.matching(identifier: "Evidence export").firstMatch.exists
                || host.otherElements.matching(identifier: "Evidence export").firstMatch.exists
            if evidence { nativeSummaryTap("V16 verification controls", in: host) }
            nativeSummaryTap("Declared browser navigation", in: host)
            XCTAssertFalse(back.firstMatch.exists, "Actual history child must disappear before Evidence Menu lookup")
        }
    }
    private func reviewedMenuCenterGeometry(app: CGRect, heading: CGRect, dock: CGRect,
                                            link: CGRect, center: CGPoint) -> Bool {
        let rectangles = [app, heading, dock, link]
        guard rectangles.allSatisfy({ rect in
            [rect.minX, rect.minY, rect.width, rect.height].allSatisfy { $0.isFinite }
                && rect.width > 0 && rect.height > 0
        }), center.x.isFinite, center.y.isFinite else { return false }
        guard app.contains(heading), app.contains(dock), app.contains(link),
              heading.maxY < dock.minY,
              link.minY > heading.maxY, link.maxY < dock.minY else { return false }
        return center.x == link.midX && center.y == link.midY
            && center.x > link.minX && center.x < link.maxX
            && center.y > link.minY && center.y < link.maxY
            && center.y > heading.maxY && center.y < dock.minY
    }
    private func nativeReviewedMenuCenterTap(_ label: String, query: XCUIElementQuery) throws {
        func refusal(_ why: String) -> CIWireError {
            attachment("v16-menu-center-refused", why)
            return CIWireError.refused("Reviewed menu center input refused: " + why)
        }
        guard host.state == .runningForeground, reviewedCurrentMenu() else {
            throw refusal("Same current frontmost reviewed Menu required")
        }
        let headings = host.staticTexts.matching(NSPredicate(format: "label == %@", "Current V16 checks"))
        let docks = host.otherElements.matching(identifier: "V16 verification controls")
        guard headings.count == 1, headings.element.exists, headings.element.isHittable,
              docks.count == 1, docks.element.exists,
              docks.element.elementType == .other,
              docks.element.identifier == "V16 verification controls",
              query.count == 1, query.element.exists, query.element.isEnabled,
              query.element.isHittable, query.element.elementType == .link,
              query.element.label == label else {
            throw refusal("Fresh unique visible Site38 heading/outer dock and unique enabled hittable reviewed Link required")
        }
        let heading = headings.element, dock = docks.element, target = query.element
        let appFrame = host.frame, headingFrame = heading.frame, dockFrame = dock.frame, linkFrame = target.frame
        let coordinate = target.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
        let point = coordinate.screenPoint
        let facts: [String: Any] = ["label": label, "attempt": 2,
            "appFrame": String(describing: appFrame), "headingFrame": String(describing: headingFrame),
            "outerDockFrame": String(describing: dockFrame), "linkFrame": String(describing: linkFrame),
            "centerScreenPoint": String(describing: point),
            "scope": "Sole second native input: current element normalized center, never absolute historical coordinates. Full Link must lie strictly below current heading and above outer dock."]
        attachment("v16-menu-center-geometry", String(decoding: try JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys]), as: UTF8.self))
        guard reviewedMenuCenterGeometry(app: appFrame, heading: headingFrame, dock: dockFrame,
                                        link: linkFrame, center: point) else {
            throw refusal("Unknown/nonpositive/nonfinite/outside/overlapping body geometry or noncenter dynamic coordinate")
        }
        // Re-resolve all ownership, visibility and geometry after recording; no stale-frame retry.
        guard host.state == .runningForeground, reviewedCurrentMenu(),
              headings.count == 1, headings.element.exists, headings.element.isHittable,
              docks.count == 1, docks.element.exists,
              docks.element.identifier == "V16 verification controls",
              query.count == 1, query.element.exists, query.element.isEnabled,
              query.element.isHittable, query.element.elementType == .link, query.element.label == label,
              host.frame == appFrame, headings.element.frame == headingFrame,
              docks.element.frame == dockFrame, query.element.frame == linkFrame,
              coordinate.screenPoint == point else {
            throw refusal("Native source/menu/element/frame changed before second input")
        }
        coordinate.tap()
    }
    private func nativeTapReviewedMenuLink(_ label: String) throws {
        let allowed = ["V16 silent OS audio comparison", "V16 URL/state controls",
            "V16 referrals alias controls", "V16 natural EOF 20-second request",
            "Native MediaError and ordinary Play /nf"]
        guard allowed.contains(label) else { throw CIWireError.refused("Unreviewed menu destination") }
        let query = host.links.matching(NSPredicate(format: "label == %@", label))
        var departed = false
        for attempt in 1...2 {
            let headings = host.staticTexts.matching(NSPredicate(format: "label == %@", "Current V16 checks"))
            guard host.state == .runningForeground, reviewedCurrentMenu() else {
                throw CIWireError.refused("Current source/menu and installed foreground host required before menu input")
            }
            guard query.firstMatch.waitForExistence(timeout: 8) else {
                throw CIWireError.refused("Reviewed native menu Link missing")
            }
            let hits = query.allElementsBoundByIndex.filter { $0.exists }
            guard hits.count == 1, hits[0].isEnabled, hits[0].elementType == .link else {
                throw CIWireError.refused("Unique enabled reviewed native menu Link required")
            }
            let target = hits[0]
            let before: [String: Any] = ["label": label, "attempt": attempt,
                "hittable": target.isHittable, "frame": String(describing: target.frame),
                "reviewedCurrentMenu": true, "hostStateRaw": host.state.rawValue,
                "headingStaticTextCount": headings.count,
                "headingAX": host.descendants(matching: .any).matching(NSPredicate(format: "label == %@", "Current V16 checks")).allElementsBoundByIndex.filter { $0.exists }.map {
                    ["type": $0.elementType.rawValue, "frame": String(describing: $0.frame), "hittable": $0.isHittable] as [String: Any]
                },
                "scope": "First input is native AX tap on the current reviewed menu; heading AX is diagnostic only. Sole second input still requires fresh Site38 safe-body center proof. Maximum two; no force/manual swipe/URL command."]
            attachment("v16-menu-before-input", String(decoding: try JSONSerialization.data(withJSONObject: before, options: [.sortedKeys]), as: UTF8.self))
            if attempt == 1 { target.tap() }
            else { try nativeReviewedMenuCenterTap(label, query: query) }
            let changed = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in !self.reviewedCurrentMenu() }, object: nil)
            departed = XCTWaiter.wait(for: [changed], timeout: 8) == .completed
            let stillMenu = reviewedCurrentMenu(), foreground = host.state == .runningForeground
            attachment("v16-menu-after-input", "attempt=\(attempt); departed=\(departed); sameReviewedMenu=\(stillMenu); foreground=\(foreground)")
            if departed { break }
            // Retry only this reversible, known same-frontmost lab navigation. Other inputs never retry here.
            guard attempt == 1 && stillMenu && foreground else { break }
        }
        guard departed, !reviewedCurrentMenu(), host.state == .runningForeground else {
            throw CIWireError.refused("Actual current menu must be left in installed host before destination controls/input")
        }
        let badge = host.staticTexts.matching(NSPredicate(format: "label MATCHES %@", ".*V16.*e7ab13f79d01.*"))
        guard badge.firstMatch.waitForExistence(timeout: 30) else {
            throw CIWireError.refused("Current V16 destination source badge required before destination input")
        }
        func requireDestinationText(_ pattern: String) throws {
            let matches = host.staticTexts.matching(NSPredicate(format: "label MATCHES %@", pattern))
            guard matches.firstMatch.waitForExistence(timeout: 15), matches.count == 1,
                  matches.element.exists else {
                throw CIWireError.refused("Unique actual destination context required: " + pattern)
            }
        }
        switch label {
        case "V16 silent OS audio comparison":
            ensureQuickControls(in: host)
            let pin = host.buttons.matching(identifier: "Pin actual playlist")
            guard pin.count == 1, pin.element.exists, pin.element.isHittable else {
                throw CIWireError.refused("Unique actual destination Pin control required before audio measurement")
            }
        case "V16 URL/state controls": try requireDestinationText("Device settings")
        case "V16 referrals alias controls": try requireNativeReferralsHeading()
        default:
            nativeEnsureMainOpen(in: host)
            let nativeSummary = host.buttons.matching(identifier: "Native failure input controls")
            let nativeOther = host.otherElements.matching(identifier: "Native failure input controls")
            let ready = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
                nativeSummary.firstMatch.exists || nativeOther.firstMatch.exists
            }, object: nil)
            guard XCTWaiter.wait(for: [ready], timeout: 8) == .completed else {
                throw CIWireError.refused("Actual NF/NG controls must exist in destination before measurement")
            }
            let controls = nativeSummary.firstMatch.exists ? nativeSummary : nativeOther
            guard controls.count == 1, controls.element.exists else {
                throw CIWireError.refused("Unique actual NF/NG control owner required before measurement")
            }
        }
    }
    private func requireNativeReferralsHeading() throws {
        let mains = host.otherElements.matching(NSPredicate(format: "label == %@", "main"))
        guard mains.firstMatch.waitForExistence(timeout: 15), mains.count == 1 else {
            throw CIWireError.refused("Unique actual referrals main owner required")
        }
        let main = mains.element
        let headings = main.otherElements.matching(NSPredicate(format: "label == %@", "Refer a friend,\nGet $50."))
        guard headings.count == 1, headings.element.exists else {
            throw CIWireError.refused("Unique actual referrals Other heading required")
        }
        let heading = headings.element
        let first = heading.staticTexts.matching(NSPredicate(format: "label == %@", "Refer a friend,"))
        let second = heading.staticTexts.matching(NSPredicate(format: "label == %@", "Get $50."))
        guard heading.staticTexts.count == 2, first.count == 1, second.count == 1,
              first.element.exists, second.element.exists else {
            throw CIWireError.refused("Exact two actual referrals heading children required")
        }
        let mainFrame = main.frame, headingFrame = heading.frame
        let firstFrame = first.element.frame, secondFrame = second.element.frame
        func finitePositive(_ frame: CGRect) -> Bool {
            frame.origin.x.isFinite && frame.origin.y.isFinite && frame.width.isFinite && frame.height.isFinite
                && frame.width > 0 && frame.height > 0
        }
        guard [mainFrame, headingFrame, firstFrame, secondFrame].allSatisfy(finitePositive),
              mainFrame.contains(headingFrame), headingFrame.contains(firstFrame), headingFrame.contains(secondFrame),
              secondFrame.minY > firstFrame.minY else {
            throw CIWireError.refused("Actual referrals heading owner/child geometry required")
        }
    }

    private func nativeMenuEntry() throws {
        if reviewedCurrentMenu() { return }
        revealEvidenceMenu()
        let menu = host.links.matching(NSPredicate(format: "label == %@", "Menu"))
        let target = try XCTUnwrap(nativeReveal(menu, name: "Evidence Menu", in: host, insideDock: true))
        target.tap()
        let ready = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in self.reviewedCurrentMenu() }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [ready], timeout: 12), .completed,
                       "Real same-WebClip entry must reach reviewed current V16 menu")
    }
    private func nativeSummaryTap(_ name: String, in app: XCUIApplication) {
        let buttons = app.buttons.matching(identifier: name)
        let query = buttons.firstMatch.exists ? buttons : app.otherElements.matching(identifier: name)
        guard let target = nativeReveal(query, name: name, in: app,
            insideDock: name != "V16 verification controls" && name != "Declared browser navigation") else { return }
        target.tap()
    }

    private func openEvidenceExport() {
        closeDeclaredNavigationIfOpen()
        nativeEnsureMainOpen(in: host)
        let menu = host.links.matching(NSPredicate(format: "label == %@", "Menu"))
        nativeEnsureDisclosureOpen("Evidence export", in: host, childExists: { menu.firstMatch.exists })
        XCTAssertTrue(menu.firstMatch.waitForExistence(timeout: 8), "Actual Evidence Menu child required")
        XCTAssertEqual(menu.count, 1, "Unique Evidence Menu child required after collapsing history owner")
    }

    private func revealEvidenceMenu() {
        openEvidenceExport()
        let menu = host.links.matching(NSPredicate(format: "label == %@", "Menu"))
        _ = nativeReveal(menu, name: "Evidence Menu", in: host, insideDock: true)
    }

    private func revealQuickResult(_ name: String, in app: XCUIApplication) {
        _ = nativeReveal(app.buttons.matching(identifier: name), name: name, in: app, insideDock: true)
    }

    private func ensureQuickControls(in app: XCUIApplication) {
        _ = text(".*V16.*e7ab13f79d01.*", in: app, timeout: 30)
        nativeEnsureMainOpen(in: app)
        let pin = app.buttons.matching(identifier: "Pin actual playlist")
        XCTAssertTrue(pin.firstMatch.waitForExistence(timeout: 8), "Actual original Pin child required")
        _ = nativeReveal(pin, name: "Pin actual playlist", in: app, insideDock: true)
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
            _ = text(".*V16.*e7ab13f79d01.*", in: host, timeout: 60)
            ensureQuickControls(in: host)
        } else {
            XCTAssertTrue(host.wait(for: .runningForeground, timeout: 8), "Installed WebClip did not become foreground")
            _ = text(".*V16.*e7ab13f79d01.*", in: host, timeout: 60)
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
        XCTAssertTrue(actions.waitForExistence(timeout: 60))
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
    private func audioRevealAndTap(_ name: String) throws {
        guard ["Prepare playback", "Start pilot and run", "Start bare native"].contains(name) else {
            throw CIWireError.refused("Unreviewed audio action visibility request")
        }
        guard let target = nativeReveal(host.buttons.matching(identifier: name),
            name: name, in: host, insideDock: true),
            target.exists, target.isEnabled, target.isHittable else {
            throw CIWireError.refused("Actual audio action must be revealed inside the current dock before input: " + name)
        }
        uniqueTap(name, in: host)
    }

    private func audioFreshEntryFromCurrentMenu() throws {
        XCTAssertEqual(host.state, .runningForeground)
        try nativeMenuEntry()
        try nativeTapReviewedMenuLink("V16 silent OS audio comparison")
        XCTAssertTrue(host.wait(for: .runningForeground, timeout: 8), "Audio link left actual installed WebClip")
    }

    private func audioEnsureStatusOpen() {
        let status = host.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "playlist="))
        nativeEnsureDisclosureOpen("V16 OS audio test", in: host,
            childExists: { status.count == 1 && status.element.exists })
    }

    func testV16InstalledAudioProtocol() throws {
        launchHomeIcon(requireAudioControls: false)
        try audioFreshEntryFromCurrentMenu()
        ensureQuickControls(in: host)
        uniqueTap("Pin actual playlist", in: host)
        // Reveal the existing original status; no helper/source changes. Fail if summary AX differs.
        audioEnsureStatusOpen()
        let pinAX = text("playlist=PINNED assets=6 .*", in: host, timeout: 20).label
        try audioRevealAndTap("Prepare playback")
        let preparedAX = text("READY: native playing and unmuted\\..*", in: host, timeout: 12).label
        screen("v16-prepared-unmuted")
        // Keep the original status detail open through phases. Reopening it after the
        // 19-second baseline can miss LIVE while native AX scrolling is still running.
        // Actual DOM is <a role="button" aria-label="Close">. Bind observed XCUI semantics.
        let closeCandidates = host.buttons.matching(identifier: "Close").allElementsBoundByIndex + host.links.matching(identifier: "Close").allElementsBoundByIndex
        let actualClose = closeCandidates.filter { $0.exists }
        XCTAssertEqual(actualClose.count, 1, "Must observe unique actual Close before phases")
        let close = try XCTUnwrap(actualClose.first)
        attachment("v16-actual-close-AX", "type=\(close.elementType.rawValue); label=\(close.label)")
        // Xcode bootstrap is outside capture. Host ACK must precede this real pilot/run tap.
        try waitForOwnedCapture(pin: pinAX, prepared: preparedAX)
        try audioRevealAndTap("Start pilot and run")
        _ = text("RUNNING: original pilot and product phases armed once\\.", in: host, timeout: 8)
        screen("v16-original-protocol-running")
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate { _,_ in !close.exists }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [gone], timeout: 48), .completed, "Actual Close not observed")
        screen("v16-after-actual-product-close")
        try audioRevealAndTap("Start bare native")
        // The original status remains open; query LIVE before doing more layout work.
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
        openEvidenceExport()
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
