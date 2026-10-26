import Citadel
import Crypto
import NIO
import NIOSSH
import XCTest

/// A server that answers the first user authentication request only after `delay`,
/// like sshd with `UseDNS yes` waiting on a slow reverse lookup of the client.
private final class SlowPasswordDelegate: NIOSSHServerUserAuthenticationDelegate, @unchecked Sendable {
    let delay: TimeAmount

    init(delay: TimeAmount) {
        self.delay = delay
    }

    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods { .password }

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        responsePromise.futureResult.eventLoop.scheduleTask(in: delay) {
            responsePromise.succeed(.success)
        }
    }
}

private final class AcceptedChannels: @unchecked Sendable {
    private let lock = NSLock()
    private var channels: [Channel] = []

    func append(_ channel: Channel) {
        lock.withLock { channels.append(channel) }
    }

    var all: [Channel] {
        lock.withLock { channels }
    }
}

final class LoginTimeoutTests: XCTestCase {
    private func startServer(authDelay: TimeAmount, accepted: AcceptedChannels) async throws -> Channel {
        let hostKey = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey())
        let delegate = SlowPasswordDelegate(delay: authDelay)
        return try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                accepted.append(channel)
                return channel.pipeline.addHandler(
                    NIOSSHHandler(
                        role: .server(.init(hostKeys: [hostKey], userAuthDelegate: delegate)),
                        allocator: channel.allocator,
                        inboundChildChannelInitializer: nil
                    )
                )
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
    }

    private func settings(port: Int) -> SSHClientSettings {
        SSHClientSettings(
            host: "127.0.0.1",
            port: port,
            authenticationMethod: { .passwordBased(username: "root", password: "x") },
            hostKeyValidator: .acceptAnything()
        )
    }

    /// A handshake that times out must not leave its TCP connection open: the caller only gets an error back.
    func testTimedOutHandshakeClosesConnection() async throws {
        let accepted = AcceptedChannels()
        let server = try await startServer(authDelay: .seconds(60), accepted: accepted)
        defer { server.close(promise: nil) }
        let port = try XCTUnwrap(server.localAddress?.port)

        do {
            _ = try await SSHClient.connect(to: settings(port: port))
            XCTFail("authentication never completes in time, connect must fail")
        } catch {}

        let child = try XCTUnwrap(accepted.all.first)
        let closed = expectation(description: "server side of the connection is closed")
        child.closeFuture.whenComplete { _ in closed.fulfill() }
        await fulfillment(of: [closed], timeout: 3)
    }

    /// A server that takes longer than the old hard-coded 10 seconds to answer authentication is still reachable.
    func testSlowAuthenticationWithinLoginTimeoutConnects() async throws {
        let accepted = AcceptedChannels()
        let server = try await startServer(authDelay: .seconds(12), accepted: accepted)
        defer { server.close(promise: nil) }
        let port = try XCTUnwrap(server.localAddress?.port)

        var settings = settings(port: port)
        settings.loginTimeout = .seconds(20)
        let client = try await SSHClient.connect(to: settings)
        try await client.close()
    }

    func testLoginTimeoutReportsItsOwnError() async throws {
        let accepted = AcceptedChannels()
        let server = try await startServer(authDelay: .seconds(60), accepted: accepted)
        defer { server.close(promise: nil) }
        let port = try XCTUnwrap(server.localAddress?.port)

        var settings = settings(port: port)
        settings.loginTimeout = .seconds(2)
        let started = Date()
        do {
            _ = try await SSHClient.connect(to: settings)
            XCTFail("authentication never completes in time, connect must fail")
        } catch let error as SSHLoginTimeoutError {
            XCTAssertEqual(error.timeout, .seconds(2))
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }
}
