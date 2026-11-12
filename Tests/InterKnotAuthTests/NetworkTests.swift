import XCTest
@testable import InterKnotAuth

private final class StubProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let url = request.url!
        if url.host == "silent.test" { return }
        let code: Int
        let body: String
        var headers: [String: String] = [:]
        switch url.path {
        case "/redirect":
            code = 302; body = ""
            headers["Location"] = "http://unreachable.test/portal?wlanuserip=10.1.2.3&wlanacip=10.0.0.1"
        case "/portal": code = 200; body = "<html>请登录校园网</html>"
        case "/html":
            code = 200
            body = "<script>location.href='/portal?wlanuserip=10.1.2.3&amp;foo=1&amp;wlanacip=10.0.0.1'</script>"
        case "/xml":
            code = 200
            body = "<ticket-url>http://campus.test/ticket?wlanacip=10.0.0.1&amp;wlanuserip=10.1.2.3</ticket-url>"
        case "/generate_204": code = 204; body = ""
        case "/connecttest.txt": code = 200; body = "Microsoft Connect Test"
        default: code = 404; body = "Not Found"
        }
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: url, statusCode: code, httpVersion: nil, headerFields: headers)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class NetworkTests: XCTestCase {
    private func client() -> DirectHTTPClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return DirectHTTPClient(configuration: config)
    }

    func testRedirectParametersAreReadWithoutFetchingDestination() async throws {
        let auth = AuthenticationService(discoveryClient: client())
        let params = try await auth.detectParameters(targets: ["http://campus.test/redirect"])
        XCTAssertEqual(params.wlanUserIP, "10.1.2.3")
        XCTAssertEqual(params.wlanACIP, "10.0.0.1")
        XCTAssertEqual(params.esurfingURL, "unreachable.test")
    }

    func testHTMLAndClientXMLParameters() async throws {
        let auth = AuthenticationService(discoveryClient: client())
        for path in ["html", "xml"] {
            let params = try await auth.detectParameters(targets: ["http://campus.test/\(path)"])
            XCTAssertEqual(params.wlanUserIP, "10.1.2.3")
            XCTAssertEqual(params.wlanACIP, "10.0.0.1")
            XCTAssertEqual(params.esurfingURL, "campus.test")
        }
    }

    func testHTTPSAndInvalidIPs() throws {
        let auth = AuthenticationService(discoveryClient: client())
        let params = try auth.parseParameters(from: "https://campus.test:8443/login?wlanuserip=10.1.2.3&wlanacip=10.0.0.1")
        XCTAssertEqual(params.esurfingURL, "https://campus.test:8443")
        XCTAssertThrowsError(try auth.parseParameters(from: "http://campus.test/?wlanuserip=0.0.0.0&wlanacip=10.0.0.1"))
        XCTAssertThrowsError(try auth.parseParameters(from: "http://campus.test/?wlanuserip=invalid&wlanacip=10.0.0.1"))
    }

    func testNoParametersIsFailure() async {
        do {
            _ = try await AuthenticationService(discoveryClient: client()).detectParameters(targets: ["http://campus.test/portal"])
            XCTFail("Login HTML must not imply discovered parameters")
        } catch {}
    }

    func testCaptivePagesRedirectsAnd404AreNotInternetSuccess() async {
        let probe = ConnectivityProbeService(client: client())
        let results = await probe.measure(urlStrings: [
            "http://campus.test/redirect", "http://www.msftconnecttest.com/portal",
            "http://captive.apple.com/portal", "http://campus.test/missing"
        ])
        XCTAssertEqual(results.count, 4)
        XCTAssertTrue(results.allSatisfy { !$0.success })
    }

    func testExpectedResponsesSucceed() async {
        let results = await ConnectivityProbeService(client: client()).measure(urlStrings: [
            "http://campus.test/generate_204", "http://www.msftconnecttest.com/connecttest.txt"
        ])
        XCTAssertEqual(results.count, 2)
        XCTAssertTrue(results.allSatisfy(\.success))
    }

    func testSilentTargetsShareFiveSecondDeadline() async {
        let start = Date()
        let results = await ConnectivityProbeService(client: client()).measure(urlStrings: (1...6).map { "http://silent.test/\($0)" })
        XCTAssertEqual(results.count, 6)
        XCTAssertTrue(results.allSatisfy { !$0.success })
        XCTAssertLessThan(Date().timeIntervalSince(start), 6.5, "Timeouts must run concurrently")
    }

    func testFirstSuccessDoesNotWaitForSilentTarget() async {
        let start = Date()
        let results = await ConnectivityProbeService(client: client()).measure(
            urlStrings: ["http://silent.test/wait", "http://campus.test/generate_204"], stopOnFirstSuccess: true)
        XCTAssertTrue(results.contains(where: \.success))
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.5)
    }
}

private final class CaptiveStudentProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: [:])!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data("<html>请登录校园网</html>".utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

extension NetworkTests {
    func testStudentHTMLWithoutConfigIsNotLoginSuccess() async {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [CaptiveStudentProtocol.self]
        let dialer = StudentDialerService(configuration: config)
        do {
            _ = try await dialer.login(request: LoginRequest(username: "student", password: "test", userIP: "10.1.2.3", mode: .automatic), logger: { _ in })
            XCTFail("An HTML response without client config must never mean login success")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("不能判定登录成功"))
        }
    }

    func testParameterDiscoveryHasOverallDeadline() async {
        let start = Date()
        do {
            _ = try await AuthenticationService(discoveryClient: client()).detectParameters(
                targets: (1...5).map { "http://silent.test/\($0)" })
            XCTFail("Silent targets must fail")
        } catch {
            XCTAssertLessThan(Date().timeIntervalSince(start), 6.5)
        }
    }
}
