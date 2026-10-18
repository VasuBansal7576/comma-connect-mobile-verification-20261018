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
        XCUIDevice.shared.press(.home)
        let home = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let icon = home.icons["CI Audio Probe"]
        XCTAssertTrue(icon.waitForExistence(timeout: 8), "No installed Home icon")
        XCTAssertTrue(icon.isHittable, "Installed icon not visible")
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
        let addHome = safari.buttons["Add to Home Screen"]
        for _ in 0..<4 where !addHome.isHittable { safari.swipeUp() }
        XCTAssertTrue(addHome.waitForExistence(timeout: 5) && addHome.isHittable, "Add to Home Screen not supported/visible")
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
