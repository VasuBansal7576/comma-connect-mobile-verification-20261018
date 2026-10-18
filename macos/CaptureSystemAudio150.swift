// New CI-only helper. No microphone, permission request, audio rendering, or product graph changes.
import Foundation
import AppKit
import AVFoundation
import CoreMedia
import ScreenCaptureKit
import CoreGraphics

struct ProbeFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

final class AudioCollector: NSObject, SCStreamOutput, SCStreamDelegate {
    let queue = DispatchQueue(label: "ci.audio.collector")
    private let handle: FileHandle
    private var format: AVAudioFormat?
    private var frames = 0
    private var callbacks: [[String: Any]] = []
    private var failures: [String] = []
    private var finished = false
    private var stream: SCStream?

    init(output: URL) throws {
        guard FileManager.default.createFile(atPath: output.path, contents: nil) else {
            throw ProbeFailure("Cannot create new PCM output")
        }
        handle = try FileHandle(forWritingTo: output)
    }

    func start() async throws {
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        guard let display = content.displays.first else { throw ProbeFailure("No display") }
        let filter = SCContentFilter(display: display, excludingApplications: [], exceptingWindows: [])
        let configuration = SCStreamConfiguration()
        configuration.width = 2
        configuration.height = 2
        configuration.capturesAudio = true
        configuration.captureMicrophone = false
        configuration.excludesCurrentProcessAudio = true
        configuration.sampleRate = 48_000
        configuration.channelCount = 2
        // Only audio is registered; no screen images are retained.
        let active = SCStream(filter: filter, configuration: configuration, delegate: self)
        try active.addStreamOutput(self, type: .audio, sampleHandlerQueue: queue)
        stream = active
        try await active.startCapture()
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        queue.async { self.failures.append("SCStream stopped: \(error.localizedDescription)") }
    }

    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer, of outputType: SCStreamOutputType) {
        guard outputType == .audio, !finished else { return }
        guard sampleBuffer.isValid, let description = sampleBuffer.formatDescription else {
            failures.append("Invalid audio sample buffer"); return
        }
        let currentFormat = AVAudioFormat(cmAudioFormatDescription: description)
        let count = CMSampleBufferGetNumSamples(sampleBuffer)
        guard count > 0, currentFormat.commonFormat == .pcmFormatFloat32,
              currentFormat.sampleRate == 48_000, currentFormat.channelCount == 2 else {
            failures.append("Unexpected or empty PCM format"); return
        }
        if let format, format != currentFormat {
            failures.append("PCM format changed"); return
        }
        format = currentFormat
        guard let pcm = AVAudioPCMBuffer(pcmFormat: currentFormat, frameCapacity: AVAudioFrameCount(count)) else {
            failures.append("PCM allocation failed"); return
        }
        pcm.frameLength = AVAudioFrameCount(count)
        let status = CMSampleBufferCopyPCMDataIntoAudioBufferList(sampleBuffer, at: 0, frameCount: Int32(count), into: pcm.mutableAudioBufferList)
        guard status == noErr, let samples = pcm.floatChannelData else {
            failures.append("PCM copy failed: \(status)"); return
        }
        var interleaved = [Float](repeating: 0, count: count * 2)
        for index in 0..<count {
            for channel in 0..<2 {
                interleaved[index * 2 + channel] = currentFormat.isInterleaved
                    ? samples[0][index * 2 + channel] : samples[channel][index]
            }
        }
        do {
            try interleaved.withUnsafeBytes { try handle.write(contentsOf: $0) }
            callbacks.append([
                "sequence": callbacks.count,
                "frameOffset": frames,
                "frames": count,
                "presentationTimeSeconds": CMTimeGetSeconds(CMSampleBufferGetPresentationTimeStamp(sampleBuffer)),
                "hostUptimeSeconds": ProcessInfo.processInfo.systemUptime
            ])
            frames += count
        } catch { failures.append("PCM file write failed") }
    }

    func stop() async throws -> [String: Any] {
        if let stream { try await stream.stopCapture() }
        return try queue.sync {
            finished = true
            try handle.close()
            return [
                "schema": "ci-system-audio-v1",
                "captureAPI": "ScreenCaptureKit.SCStream.audio",
                "screenImagesRetained": false,
                "capturesMicrophone": false,
                "excludesCurrentProcessAudio": true,
                "sampleFormat": "float32-le-interleaved",
                "sampleRate": format?.sampleRate ?? 0,
                "channels": format?.channelCount ?? 0,
                "frames": frames,
                "callbacks": callbacks,
                "errors": failures,
                "continuityRequiresPTSCheck": true,
                "hardwareEquivalenceClaim": false
            ]
        }
    }
}

@main struct CaptureSystemAudio {
    static func main() async {
        let processDeadline = Task {
            try await Task.sleep(for: .seconds(170))
            fputs("Independent170s collector deadline\n", stderr); exit(124)
        }
        defer { processDeadline.cancel() }
        do {
            let arguments = CommandLine.arguments
            if arguments.count == 2, arguments[1] == "preflight" {
                print("{\"screenCapturePreflight\":\(CGPreflightScreenCaptureAccess()),\"permissionRequested\":false}")
                exit(CGPreflightScreenCaptureAccess() ? 0 : 77)
            }
            guard arguments.count == 5, arguments[1] == "capture",
                  let duration = Double(arguments[3]), duration > 0, duration <= 150 else {
                throw ProbeFailure("Usage: capture-system-audio preflight | capture OUTPUT.f32 SECONDS RECEIPT.json (max 150s)")
            }
            guard CGPreflightScreenCaptureAccess() else { throw ProbeFailure("Screen capture permission absent; refusing to prompt or bypass") }
            let output = URL(fileURLWithPath: arguments[2])
            let receipt = URL(fileURLWithPath: arguments[4])
            guard !FileManager.default.fileExists(atPath: output.path),
                  !FileManager.default.fileExists(atPath: receipt.path) else { throw ProbeFailure("Refusing to overwrite evidence") }
            let collector = try AudioCollector(output: output)
            let hostStartUptime = ProcessInfo.processInfo.systemUptime
            try await collector.start()
            print("CAPTURE_STARTED")
            fflush(stdout)
            try await Task.sleep(for: .seconds(duration))
            let stopDeadline = Task {
                try await Task.sleep(for: .seconds(5))
                fputs("Owned SCStream cleanup exceeded5s\n", stderr); exit(125)
            }
            var result = try await collector.stop()
            stopDeadline.cancel()
            result["hostStartUptimeSeconds"] = hostStartUptime
            result["hostStopUptimeSeconds"] = ProcessInfo.processInfo.systemUptime
            result["streamStopCompleted"] = true
            result["pcmHandleClosed"] = true
            result["independentProcessDeadlineSeconds"] = 170
            result["cleanupDeadlineSeconds"] = 5
            result["requestedDurationSeconds"] = duration
            result["permissionRequested"] = false
            result["output"] = output.lastPathComponent
            let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: receipt, options: .withoutOverwriting)
            if (result["frames"] as? Int ?? 0) == 0 || !(result["errors"] as? [String] ?? []).isEmpty { exit(2) }
        } catch {
            fputs("Capture failed: \(error)\n", stderr)
            exit(1)
        }
    }
}
