import Foundation
import Network

// This native XCTest-only loopback channel never reaches the product page or external network.
// Network.framework TCP avoids assuming URLSession ATS inheritance in Apple's test runner.
enum CIWireError: Error { case refused(String) }
final class CIWireBox: @unchecked Sendable {
    let lock = NSLock(), semaphore = DispatchSemaphore(value: 0)
    var data = Data(), error: Error?, done = false
    func finish(_ failure: Error? = nil) {
        lock.lock(); guard !done else { lock.unlock(); return }; done = true; error = failure; lock.unlock(); semaphore.signal()
    }
    func append(_ part: Data?) -> Bool {
        lock.lock(); defer { lock.unlock() }; guard !done else { return false }
        if let part { data.append(part) }; return data.count <= 65536
    }
}
func ciWire(_ path: String, body: [String: Any]? = nil) throws -> [String: Any] {
    guard ["/session", "/ready", "/ack", "/done", "/abort"].contains(path) else { throw CIWireError.refused("Own loopback path only") }
    let bytes = try body.map { try JSONSerialization.data(withJSONObject: $0) } ?? Data()
    guard bytes.count <= 8192 else { throw CIWireError.refused("Own handshake body cap") }
    let header = "\(body == nil ? "GET" : "POST") \(path) HTTP/1.1\r\nHost: 127.0.0.1:5831\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: \(bytes.count)\r\n\r\n"
    var request = Data(header.utf8); request.append(bytes)
    let box = CIWireBox(), connection = NWConnection(host: "127.0.0.1", port: 5831, using: .tcp)
    let queue = DispatchQueue(label: "owned.ci.v15.loopback")
    func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { part, _, complete, error in
            guard box.append(part) else { box.finish(CIWireError.refused("Own response cap/disposed")); return }
            if let error { box.finish(error) } else if complete { box.finish() } else { receive() }
        }
    }
    connection.stateUpdateHandler = { state in
        switch state {
        case .ready: connection.send(content: request, completion: .contentProcessed { error in if let error { box.finish(error) } else { receive() } })
        case .failed(let error): box.finish(error)
        default: break
        }
    }
    connection.start(queue: queue)
    let ready = box.semaphore.wait(timeout: .now() + 3)
    if ready == .timedOut { box.finish(CIWireError.refused("Own loopback request exceeded3s")) }
    connection.cancel(); connection.stateUpdateHandler = nil
    box.lock.lock(); let result = box.data, error = box.error; box.lock.unlock()
    if let error { throw error }
    guard let text = String(data: result, encoding: .utf8), let split = text.range(of: "\r\n\r\n"), text.hasPrefix("HTTP/1.1 200 ") else { throw CIWireError.refused("Own loopback HTTP refused") }
    let value = Data(text[split.upperBound...].utf8)
    guard let object = try JSONSerialization.jsonObject(with: value) as? [String: Any] else { throw CIWireError.refused("Own JSON response required") }
    return object
}


