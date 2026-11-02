/// Where the cloud lives.
///
/// Overridden at build time with `--dart-define=FLORA_API=https://…`, so a
/// release build points at the deployment and a debug build can point at a
/// laptop without editing code.
class AppConfig {
  AppConfig._();

  /// Compile-time override.
  static const String _override = String.fromEnvironment('FLORA_API');

  /// Base URL of the cloud API.
  ///
  /// The default is deliberately a local address: pointing a debug build at a
  /// production deployment by accident is worse than pointing it at nothing.
  static String get apiBaseUrl {
    if (_override.isNotEmpty) return _override;
    // Android emulators reach the host through 10.0.2.2 rather than localhost.
    // `defaultTargetPlatform` is not imported here to keep this file free of
    // Flutter dependencies, so the caller supplies the value if it cares.
    return 'http://127.0.0.1:8080';
  }

  /// WebSocket base derived from the API base, since the streams live on the
  /// same host.
  static String get streamBaseUrl {
    final base = apiBaseUrl;
    if (base.startsWith('https://')) {
      return 'wss://${base.substring('https://'.length)}';
    }
    if (base.startsWith('http://')) {
      return 'ws://${base.substring('http://'.length)}';
    }
    return base;
  }

  /// Whether the configured endpoint is encrypted.
  ///
  /// Accessed tokens and signed commands travel over this connection, so a
  /// plaintext endpoint is only acceptable for local development.
  static bool get isEncrypted => apiBaseUrl.startsWith('https://');

  /// How long to wait for a request before treating it as failed.
  static const Duration requestTimeout = Duration(seconds: 20);

  /// How long to try reconnecting a stream before giving up.
  static const Duration streamReconnectWindow = Duration(minutes: 5);

  /// Longest label the server accepts, mirrored so the field can cap input
  /// rather than letting the user type something that will be refused.
  static const int maxLabelLength = 64;
}
