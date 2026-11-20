import Foundation
import Network

struct NetworkPathSnapshot: Equatable {
    let available: Bool
    let identity: String
}

@MainActor
protocol NetworkPathObserving: AnyObject {
    func start(_ handler: @escaping (NetworkPathSnapshot) -> Void)
    func stop()
}

/// One system event subscription; no SSID scanning or network requests.
@MainActor
final class SystemNetworkPathObserver: NetworkPathObserving {
    private var monitor: NWPathMonitor?
    private var generation = 0

    deinit { monitor?.cancel() }

    func start(_ handler: @escaping (NetworkPathSnapshot) -> Void) {
        stop()
        let epoch = generation
        let monitor = NWPathMonitor()
        self.monitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            let interfaces = path.availableInterfaces
                .filter { path.usesInterfaceType($0.type) }.map(\.name).sorted().joined(separator: ",")
            let snapshot = NetworkPathSnapshot(
                available: path.status == .satisfied,
                identity: interfaces + ":" + (NetworkInterfaceService.localIPv4Address() ?? ""))
            Task { @MainActor [weak self] in
                guard let self, self.generation == epoch else { return }
                handler(snapshot)
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.interknot.network-path", qos: .utility))
    }

    func stop() {
        generation += 1
        monitor?.cancel()
        monitor = nil
    }
}

enum WatchdogPhase: Equatable {
    case stopped
    case monitoring
    case waitingForNetwork
    case checking
    case authenticating
    case waitingToRetry(Int)

    var title: String {
        switch self {
        case .stopped: return "未启动"
        case .monitoring: return "监测中"
        case .waitingForNetwork: return "等待网络"
        case .checking: return "检测中"
        case .authenticating: return "正在重连"
        case .waitingToRetry(let seconds): return "等待重试（\(seconds) 秒）"
        }
    }
}

/// Armed only after a verified login. Transport failures never disarm recovery.
@MainActor
final class WatchdogService {
    struct Timing {
        var fallback: Double = 30
        var debounce: Double = 2
        var retryDelays: [Double] = [15, 30, 60, 120, 300]
    }

    private let observer: NetworkPathObserving
    private let timing: Timing
    private let probe: () async -> Bool
    private let reconnect: () -> Void
    private let stateChanged: (WatchdogPhase) -> Void
    private let networkChanged: (Bool) -> Void
    private let reachabilityChanged: (Bool) -> Void
    private var ticker: Task<Void, Never>?
    private var scheduledCheck: Task<Void, Never>?
    private var probeTask: Task<Void, Never>?
    private var snapshot: NetworkPathSnapshot?
    private var epoch = 0
    private var retryIndex = 0
    private var retryAt: Date?
    private var authenticating = false
    private(set) var isRunning = false
    private(set) var phase: WatchdogPhase = .stopped {
        didSet { if oldValue != phase { stateChanged(phase) } }
    }

    init(observer: NetworkPathObserving? = nil, timing: Timing = Timing(),
         probe: @escaping () async -> Bool, reconnect: @escaping () -> Void,
         stateChanged: @escaping (WatchdogPhase) -> Void,
         networkChanged: @escaping (Bool) -> Void,
         reachabilityChanged: @escaping (Bool) -> Void) {
        self.observer = observer ?? SystemNetworkPathObserver()
        self.timing = timing
        self.probe = probe
        self.reconnect = reconnect
        self.stateChanged = stateChanged
        self.networkChanged = networkChanged
        self.reachabilityChanged = reachabilityChanged
    }

    deinit {
        ticker?.cancel()
        scheduledCheck?.cancel()
        probeTask?.cancel()
    }

    func start() {
        guard !isRunning else { return }
        isRunning = true
        phase = .monitoring
        observer.start { [weak self] path in self?.pathChanged(path) }
        ticker = Task { [weak self, interval = timing.fallback] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: Self.nanoseconds(interval)) }
                catch { return }
                guard let self else { return }
                self.checkNow()
            }
        }
    }

    func stop() {
        isRunning = false
        invalidateChecks()
        ticker?.cancel()
        ticker = nil
        observer.stop()
        snapshot = nil
        retryAt = nil
        retryIndex = 0
        authenticating = false
        phase = .stopped
    }

    func authenticationStarted() {
        guard isRunning else { return }
        invalidateChecks()
        authenticating = true
        phase = .authenticating
    }

    func authenticationFinished(success: Bool) {
        guard isRunning else { return }
        authenticating = false
        if success {
            invalidateChecks()
            retryAt = nil
            retryIndex = 0
            phase = .monitoring
        } else if snapshot?.available == false {
            phase = .waitingForNetwork
        } else {
            scheduleRetry()
        }
    }

    /// Used by manual connectivity checks too. An offline result retains the monitor.
    func reportReachability(_ reachable: Bool) {
        guard isRunning, !authenticating else { return }
        invalidateChecks()
        if reachable {
            retryIndex = 0
            retryAt = nil
            phase = .monitoring
            reachabilityChanged(true)
        } else {
            reachabilityChanged(false)
            guard snapshot?.available != false else { phase = .waitingForNetwork; return }
            if let retryAt, retryAt > Date() {
                scheduleCheck(after: retryAt.timeIntervalSinceNow)
                return
            }
            requestReconnect()
        }
    }

    func checkNow() {
        guard isRunning, !authenticating, probeTask == nil, scheduledCheck == nil else { return }
        guard snapshot?.available != false else { phase = .waitingForNetwork; return }
        if let retryAt, retryAt > Date() { return }
        phase = .checking
        let currentEpoch = epoch
        probeTask = Task { [weak self, probe] in
            let reachable = await probe()
            guard let self, self.isRunning, !Task.isCancelled, self.epoch == currentEpoch else { return }
            self.probeTask = nil
            if reachable {
                self.retryIndex = 0
                self.retryAt = nil
                self.phase = .monitoring
                self.reachabilityChanged(true)
            } else {
                self.reachabilityChanged(false)
                self.requestReconnect()
            }
        }
    }

    private func requestReconnect() {
        guard isRunning, !authenticating else { return }
        // Set this before invoking the callback to prevent overlapping logins.
        authenticating = true
        phase = .authenticating
        reconnect()
    }

    private func pathChanged(_ path: NetworkPathSnapshot) {
        guard isRunning, path != snapshot else { return }
        let first = snapshot == nil
        snapshot = path
        if first && path.available { return } // Login was just verified on this path.
        invalidateChecks()
        authenticating = false
        retryAt = nil
        retryIndex = 0
        networkChanged(path.available)
        if !path.available {
            phase = .waitingForNetwork
        } else {
            phase = .checking
            scheduleCheck(after: timing.debounce)
        }
    }

    private func scheduleRetry() {
        let delays = timing.retryDelays.isEmpty ? [15.0] : timing.retryDelays
        let delay = delays[min(retryIndex, delays.count - 1)]
        retryIndex = min(retryIndex + 1, delays.count - 1)
        retryAt = Date().addingTimeInterval(delay)
        phase = .waitingToRetry(Int(delay.rounded(.up)))
        scheduleCheck(after: delay)
    }

    private func scheduleCheck(after seconds: Double) {
        scheduledCheck?.cancel()
        let currentEpoch = epoch
        scheduledCheck = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: Self.nanoseconds(seconds)) }
            catch { return }
            guard let self, self.isRunning, self.epoch == currentEpoch else { return }
            self.scheduledCheck = nil
            self.checkNow()
        }
    }

    private func invalidateChecks() {
        epoch += 1
        probeTask?.cancel()
        probeTask = nil
        scheduledCheck?.cancel()
        scheduledCheck = nil
    }

    private static func nanoseconds(_ seconds: Double) -> UInt64 {
        UInt64(max(0.001, seconds) * 1_000_000_000)
    }
}
