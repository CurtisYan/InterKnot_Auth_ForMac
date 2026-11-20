import XCTest
@testable import InterKnotAuth

@MainActor
private final class FakePathObserver: NetworkPathObserving {
    var handler: ((NetworkPathSnapshot) -> Void)?
    var starts = 0
    var stops = 0
    func start(_ handler: @escaping (NetworkPathSnapshot) -> Void) { starts += 1; self.handler = handler }
    func stop() { stops += 1; handler = nil }
    func emit(_ available: Bool, _ identity: String = "en0:10.0.0.2") {
        handler?(NetworkPathSnapshot(available: available, identity: identity))
    }
}

final class WatchdogTests: XCTestCase {
    @MainActor
    private func eventually(_ condition: () -> Bool, file: StaticString = #filePath, line: UInt = #line) async {
        for _ in 0..<100 {
            if condition() { return }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("Expected state was not reached", file: file, line: line)
    }

    @MainActor
    func testInactiveWatchdogDoesNotRecoverFirstFailedLogin() async {
        let observer = FakePathObserver()
        var attempts = 0
        let service = WatchdogService(observer: observer, probe: { false }, reconnect: { attempts += 1 },
                                      stateChanged: { _ in }, networkChanged: { _ in }, reachabilityChanged: { _ in })
        service.authenticationFinished(success: false)
        service.reportReachability(false)
        service.checkNow()
        observer.emit(true)
        XCTAssertEqual(service.phase, .stopped)
        XCTAssertEqual(observer.starts, 0)
        XCTAssertEqual(attempts, 0)
    }

    @MainActor
    func testDisconnectWaitsWithoutRequestsAndReconnectsAfterRecovery() async {
        let observer = FakePathObserver()
        var probes = 0
        var attempts = 0
        var paths: [Bool] = []
        let service = WatchdogService(observer: observer, timing: .init(fallback: 0.02, debounce: 0.01),
            probe: { probes += 1; return false }, reconnect: { attempts += 1 }, stateChanged: { _ in },
            networkChanged: { paths.append($0) }, reachabilityChanged: { XCTAssertFalse($0) })
        service.start()
        observer.emit(true)
        observer.emit(false)
        XCTAssertEqual(service.phase, .waitingForNetwork)
        try? await Task.sleep(nanoseconds: 60_000_000)
        XCTAssertEqual(probes, 0)
        XCTAssertEqual(attempts, 0)
        observer.emit(true)
        await eventually { attempts == 1 }
        XCTAssertEqual(paths, [false, true])
        XCTAssertEqual(service.phase, .authenticating)
        service.checkNow()
        XCTAssertEqual(attempts, 1)
        service.stop()
    }

    @MainActor
    func testNetworkSwitchIsDebouncedAndDuplicateEventsAreIgnored() async {
        let observer = FakePathObserver()
        var probes = 0
        var pathChanges = 0
        let service = WatchdogService(observer: observer, timing: .init(fallback: 100, debounce: 0.02),
            probe: { probes += 1; return true }, reconnect: { XCTFail("Reachable path needs no login") },
            stateChanged: { _ in }, networkChanged: { _ in pathChanges += 1 }, reachabilityChanged: { XCTAssertTrue($0) })
        service.start()
        observer.emit(true, "old")
        observer.emit(true, "new")
        observer.emit(true, "new")
        observer.emit(true, "final")
        XCTAssertEqual(probes, 0)
        await eventually { probes == 1 }
        XCTAssertEqual(pathChanges, 2)
        XCTAssertEqual(service.phase, .monitoring)
        service.stop()
    }

    @MainActor
    func testTransientLoginFailureKeepsRetryingAndSuccessResetsBackoff() async {
        let observer = FakePathObserver()
        var attempts = 0
        var phases: [WatchdogPhase] = []
        var service: WatchdogService!
        service = WatchdogService(observer: observer, timing: .init(fallback: 100, debounce: 0.01, retryDelays: [0.02, 0.04]),
            probe: { false }, reconnect: {
                attempts += 1
                service.authenticationStarted()
                service.authenticationFinished(success: attempts >= 3)
            }, stateChanged: { phases.append($0) }, networkChanged: { _ in }, reachabilityChanged: { XCTAssertFalse($0) })
        service.start()
        observer.emit(true)
        service.checkNow()
        await eventually { attempts == 3 }
        XCTAssertTrue(service.isRunning)
        XCTAssertEqual(service.phase, .monitoring)
        XCTAssertEqual(phases.filter { if case .waitingToRetry = $0 { return true }; return false }.count, 2)
        service.stop()
    }

    @MainActor
    func testManualFailedProbeRetainsRecoveryWithoutSecondProbe() async {
        let observer = FakePathObserver()
        var attempts = 0
        let service = WatchdogService(observer: observer, probe: { XCTFail("Already probed by user"); return false },
            reconnect: { attempts += 1 }, stateChanged: { _ in }, networkChanged: { _ in }, reachabilityChanged: { XCTAssertFalse($0) })
        service.start()
        observer.emit(true)
        service.reportReachability(false)
        XCTAssertEqual(attempts, 1)
        XCTAssertTrue(service.isRunning)
        XCTAssertEqual(service.phase, .authenticating)
        service.stop()
    }

    @MainActor
    func testStopPreventsRetryAndLateNetworkCallbacks() async {
        let observer = FakePathObserver()
        var attempts = 0
        let service = WatchdogService(observer: observer, timing: .init(fallback: 0.01, debounce: 0.01, retryDelays: [0.02]),
            probe: { false }, reconnect: { attempts += 1 }, stateChanged: { _ in }, networkChanged: { _ in }, reachabilityChanged: { _ in })
        service.start()
        observer.emit(true)
        let staleHandler = observer.handler
        service.authenticationStarted()
        service.authenticationFinished(success: false)
        service.stop()
        staleHandler?(NetworkPathSnapshot(available: true, identity: "new"))
        try? await Task.sleep(nanoseconds: 60_000_000)
        XCTAssertEqual(attempts, 0)
        XCTAssertEqual(service.phase, .stopped)
    }

    @MainActor
    func testStaleSuccessfulProbeCannotRestoreConnectedAfterDisconnect() async {
        let observer = FakePathObserver()
        var continuation: CheckedContinuation<Bool, Never>?
        var reachableEvents: [Bool] = []
        let service = WatchdogService(observer: observer, probe: {
            await withCheckedContinuation { continuation = $0 }
        }, reconnect: { XCTFail("Old task must be ignored") }, stateChanged: { _ in }, networkChanged: { _ in },
           reachabilityChanged: { reachableEvents.append($0) })
        service.start()
        observer.emit(true)
        service.checkNow()
        service.checkNow()
        await eventually { continuation != nil }
        observer.emit(false)
        continuation?.resume(returning: true)
        try? await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertTrue(reachableEvents.isEmpty)
        XCTAssertEqual(service.phase, .waitingForNetwork)
        service.stop()
    }

    @MainActor
    func testFallbackDetectsExpiredAuthenticationWithoutPathChange() async {
        let observer = FakePathObserver()
        var attempts = 0
        let service = WatchdogService(observer: observer, timing: .init(fallback: 0.02), probe: { false },
            reconnect: { attempts += 1 }, stateChanged: { _ in }, networkChanged: { _ in }, reachabilityChanged: { _ in })
        service.start()
        observer.emit(true)
        await eventually { attempts == 1 }
        XCTAssertEqual(service.phase, .authenticating)
        service.stop()
    }

    func testOnlyExplicitAccountOrUserActionErrorsPauseRecovery() {
        for message in ["密码错误", "账号不存在", "操作过于频繁", "验证码未填写", "Invalid credentials"] {
            XCTAssertTrue(AuthenticationFailurePolicy.shouldPause(message), message)
        }
        for message in ["请求超时", "自动更新认证参数失败", "网络不可达", "未返回 keep-url", "连接验证失败"] {
            XCTAssertFalse(AuthenticationFailurePolicy.shouldPause(message), message)
        }
        XCTAssertEqual(ConnectionState.recovering("等待网络").title, "等待恢复")
        XCTAssertNotEqual(ConnectionState.recovering("等待网络").title, "已连接")
    }
}

extension WatchdogTests {
    @MainActor
    func testBackoffResetsAfterVerifiedSuccess() {
        let observer = FakePathObserver()
        let service = WatchdogService(observer: observer, timing: .init(fallback: 100, retryDelays: [15, 30, 60]),
            probe: { false }, reconnect: {}, stateChanged: { _ in }, networkChanged: { _ in }, reachabilityChanged: { _ in })
        service.start()
        observer.emit(true)
        service.authenticationStarted()
        service.authenticationFinished(success: false)
        XCTAssertEqual(service.phase, .waitingToRetry(15))
        service.authenticationStarted()
        service.authenticationFinished(success: false)
        XCTAssertEqual(service.phase, .waitingToRetry(30))
        service.authenticationStarted()
        service.authenticationFinished(success: true)
        XCTAssertEqual(service.phase, .monitoring)
        service.authenticationStarted()
        service.authenticationFinished(success: false)
        XCTAssertEqual(service.phase, .waitingToRetry(15))
        service.stop()
    }

    @MainActor
    func testManualFailureDuringCooldownPreservesScheduledRetry() async {
        let observer = FakePathObserver()
        var attempts = 0
        let service = WatchdogService(observer: observer, timing: .init(fallback: 100, retryDelays: [0.03]),
            probe: { false }, reconnect: { attempts += 1 }, stateChanged: { _ in }, networkChanged: { _ in }, reachabilityChanged: { _ in })
        service.start()
        observer.emit(true)
        service.authenticationStarted()
        service.authenticationFinished(success: false)
        service.reportReachability(false)
        XCTAssertEqual(attempts, 0)
        await eventually { attempts == 1 }
        XCTAssertTrue(service.isRunning)
        service.stop()
    }
}
