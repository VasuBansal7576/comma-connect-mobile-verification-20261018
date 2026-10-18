// CI fixture only. Real accessibility taps, not a Safari wrapper or injected standalone flag.
import XCTest

@MainActor final class InstallProbeUITests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = false }

    override func tearDownWithError() throws {
        retain("final-safari-state", app: XCUIApplication(bundleIdentifier: "com.apple.mobilesafari"))
        retain("final-home-state", app: XCUIApplication(bundleIdentifier: "com.apple.springboard"))
    }

    private func retain(_ label: String, app: XCUIApplication) {
        let screen = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        screen.name = label; screen.lifetime = .keepAlways; add(screen)
        let hierarchy = XCTAttachment(string: app.debugDescription)
        hierarchy.name = label + "-hierarchy"; hierarchy.lifetime = .keepAlways; add(hierarchy)
    }

    private func tap(_ label: String, in app: XCUIApplication) {
        let button = app.buttons[label]
        XCTAssertTrue(button.waitForExistence(timeout: 8), "Missing button: " + label)
        XCTAssertTrue(button.isHittable, "Nonhittable button: " + label)
        button.tap()
    }

    private func launchInstalled() -> XCUIApplication {
        let home = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        // Add may already reveal the newly installed icon. A second Home press
        // resets the selected page, so press only when Springboard is not foreground.
        if home.state != .runningForeground { XCUIDevice.shared.press(.home) }
        XCTAssertTrue(home.wait(for: .runningForeground, timeout: 5), "Springboard not foreground")
        let icon = home.icons["CI Audio Probe"]
        XCTAssertTrue(icon.waitForExistence(timeout: 8), "No installed Home icon")
        for _ in 0..<4 {
            if icon.isHittable { break }
            let indicators = home.pageIndicators.matching(identifier: "Page control")
            guard indicators.count == 1, let value = indicators.element.value as? String else {
                retain("home-page-indicator-unavailable", app: home)
                XCTFail("Unique actual Home-page indicator required"); break
            }
            let words = value.split(separator: " ")
            guard words.count == 4, words[0] == "Page", words[2] == "of",
                  let page = Int(words[1]), let total = Int(words[3]),
                  page >= 1, total >= page, total <= 5, page < total else {
                retain("home-page-boundary-refused", app: home)
                XCTFail("Refuse unknown/last Home page; never swipe into App Library: " + value); break
            }
            let expected = "Page \(page + 1) of \(total)"
            retain("home-before-next-page-\(page)", app: home)
            home.swipeLeft()
            let changed = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == %@", expected), object: indicators.element)
            guard XCTWaiter.wait(for: [changed], timeout: 3) == .completed else {
                retain("home-page-transition-refused", app: home)
                XCTFail("Actual Home page did not advance exactly to " + expected); break
            }
        }
        retain("home-before-installed-icon-tap", app: home)
        XCTAssertTrue(icon.isHittable, "Installed icon not visible on verified Home pages")
        icon.tap()
        // Apple/WebKit identify the iOS Web Clip host as com.apple.webapp.
        // Query only; never activate this host to fake a Home-icon launch.
        let foreground = XCUIApplication(bundleIdentifier: "com.apple.webapp")
        let context = foreground.staticTexts["PWA standalone true"]
        if !context.waitForExistence(timeout: 8) {
            retain("standalone-context-not-established", app: foreground)
        }
        XCTAssertTrue(context.exists, "Actual page must report both standalone flags true")
        return foreground
    }

    func testInstallFromSafari() throws {
        let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
        safari.activate()
        // Shell opens the owned localhost fixture before this test. No address-bar
        // automation or private URL commands are used to create the installed shell.
        XCTAssertTrue(safari.staticTexts["CI-owned output calibration"].waitForExistence(timeout: 15))
        retain("safari-before-add-home", app: safari)
        tap("Share", in: safari)
        // Retained iOS 18.6 AX identifies this action as a Cell in the
        // share sheet collection, rather than a Button.
        let actions = safari.collectionViews["activityCollectionView"]
        XCTAssertTrue(actions.waitForExistence(timeout: 5), "Safari share sheet not present")
        let addHome = actions.cells["Add to Home Screen"]
        for _ in 0..<4 {
            if addHome.exists && addHome.isHittable { break }
            actions.swipeUp()
        }
        retain("share-sheet-before-add-home", app: safari)
        XCTAssertTrue(addHome.waitForExistence(timeout: 5) && addHome.isHittable, "Add to Home Screen cell not visible")
        addHome.tap()
        tap("Add", in: safari)
        let installed = launchInstalled()
        retain("installed-standalone", app: installed)
    }

    func testInstalledOutputControls() throws {
        let installed = launchInstalled()
        tap("Play 440 Hz", in: installed)
        XCTAssertTrue(installed.staticTexts["Audio playing unmuted"].waitForExistence(timeout: 8))
        Thread.sleep(forTimeInterval: 4)
        tap("Pause audio", in: installed)
        XCTAssertTrue(installed.staticTexts["Audio paused unmuted"].waitForExistence(timeout: 5))
        Thread.sleep(forTimeInterval: 2)
        tap("Resume audio", in: installed)
        XCTAssertTrue(installed.staticTexts["Audio playing unmuted"].waitForExistence(timeout: 5))
        Thread.sleep(forTimeInterval: 4)
        tap("Mute audio", in: installed)
        XCTAssertTrue(installed.staticTexts["Audio playing muted"].waitForExistence(timeout: 5))
        Thread.sleep(forTimeInterval: 2)
        tap("Unmute audio", in: installed)
        Thread.sleep(forTimeInterval: 4)
        tap("Pause audio", in: installed)
        retain("installed-output-phases", app: installed)
    }
}
