import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../models/models.dart';

/// One event from the server.
sealed class StreamEvent {
  const StreamEvent();
}

/// New readings arrived for a gateway.
class TelemetryEvent extends StreamEvent {
  const TelemetryEvent({required this.gatewayId, required this.readings});

  final String gatewayId;
  final List<Reading> readings;
}

/// A command changed state.
class CommandEvent extends StreamEvent {
  const CommandEvent({
    required this.gatewayId,
    required this.commandId,
    required this.status,
  });

  final String gatewayId;
  final String commandId;
  final String status;

  bool get isSettled => status != 'pending' && status != 'dispatched';
  bool get isFailure => status == 'refused' || status == 'expired';
}

/// The connection is up and authenticated.
class ReadyEvent extends StreamEvent {
  const ReadyEvent();
}

/// The client fell behind and missed events, so local state may be stale.
class LaggedEvent extends StreamEvent {
  const LaggedEvent(this.missed);

  final int missed;
}

/// State of the connection, so the UI can say whether data is live.
enum StreamStatus { connecting, live, reconnecting, stopped }

/// A live connection to one of the server's event streams.
///
/// Render's free plan spins a service down after fifteen minutes without
/// *inbound* traffic, and that includes WebSocket messages. The server pings,
/// and this client answers by virtue of `web_socket_channel` handling pongs at
/// the protocol level; the client also sends a periodic frame of its own so the
/// service stays warm even if a pong is lost.
class EventStream {
  EventStream({
    required this.url,
    required this.accessToken,
  });

  final String url;
  final String accessToken;

  final _events = StreamController<StreamEvent>.broadcast();
  final _status = StreamController<StreamStatus>.broadcast();
  final _random = Random();

  WebSocketChannel? _channel;
  StreamSubscription<dynamic>? _subscription;
  Timer? _keepalive;
  Timer? _reconnect;
  int _attempt = 0;
  bool _closed = false;
  StreamStatus _current = StreamStatus.stopped;

  /// Events, broadcast so several screens can listen.
  Stream<StreamEvent> get events => _events.stream;

  /// Connection state, for a "live" indicator.
  Stream<StreamStatus> get status => _status.stream;

  StreamStatus get currentStatus => _current;

  /// Open the connection and start reconnecting on failure.
  void connect() {
    _closed = false;
    _open();
  }

  /// Close permanently. No further reconnects.
  Future<void> dispose() async {
    _closed = true;
    _keepalive?.cancel();
    _reconnect?.cancel();
    await _subscription?.cancel();
    await _channel?.sink.close();
    _channel = null;
    _setStatus(StreamStatus.stopped);
    await _events.close();
    await _status.close();
  }

  void _open() {
    if (_closed) return;
    _setStatus(_attempt == 0 ? StreamStatus.connecting : StreamStatus.reconnecting);

    try {
      final channel = WebSocketChannel.connect(Uri.parse(url));
      _channel = channel;

      _subscription = channel.stream.listen(
        _onFrame,
        onError: (_) => _scheduleReconnect(),
        onDone: _scheduleReconnect,
        cancelOnError: true,
      );

      // The token is the first frame: a token in a URL reaches access logs, and
      // this one reads a farm's data.
      channel.sink.add(jsonEncode({'token': accessToken}));

      _keepalive?.cancel();
      _keepalive = Timer.periodic(const Duration(seconds: 45), (_) {
        // Any inbound frame counts as activity for the platform, so a small
        // periodic send is what keeps the service from spinning down.
        _channel?.sink.add(jsonEncode({'type': 'ping'}));
      });
    } catch (_) {
      _scheduleReconnect();
    }
  }

  void _onFrame(dynamic frame) {
    if (frame is! String || frame.isEmpty) return;
    Object? decoded;
    try {
      decoded = jsonDecode(frame);
    } on FormatException {
      return;
    }
    if (decoded is! Map<String, dynamic>) return;

    switch (decoded['type']) {
      case 'ready':
        _attempt = 0;
        _setStatus(StreamStatus.live);
        _events.add(const ReadyEvent());
      case 'telemetry':
        final gatewayId = decoded['gateway_id'];
        final readings = decoded['readings'];
        if (gatewayId is! String || readings is! List) return;
        _events.add(
          TelemetryEvent(
            gatewayId: gatewayId,
            readings: readings
                .whereType<Map<String, dynamic>>()
                .map(Reading.fromJson)
                .toList(growable: false),
          ),
        );
      case 'command':
        final gatewayId = decoded['gateway_id'];
        final commandId = decoded['command_id'];
        final status = decoded['status'];
        if (gatewayId is! String || commandId is! String || status is! String) return;
        _events.add(
          CommandEvent(
            gatewayId: gatewayId,
            commandId: commandId,
            status: status,
          ),
        );
      case 'lagged':
        // Local state may be stale; the listener should refetch.
        _events.add(LaggedEvent((decoded['missed'] as num?)?.toInt() ?? 0));
      default:
        // An unknown type is ignored rather than treated as an error, so a
        // server that starts sending something new does not break the app.
        break;
    }
  }

  void _scheduleReconnect() {
    if (_closed) return;
    _keepalive?.cancel();
    _subscription?.cancel();
    _channel = null;

    _attempt = (_attempt + 1).clamp(1, 10);
    // Exponential backoff with jitter, so a server restart does not meet a
    // synchronised stampede from every app at once.
    final base = min(30, 1 << min(_attempt, 5));
    final delay = Duration(milliseconds: base * 1000 + _random.nextInt(1000));
    _setStatus(StreamStatus.reconnecting);

    _reconnect?.cancel();
    _reconnect = Timer(delay, _open);
  }

  void _setStatus(StreamStatus status) {
    _current = status;
    if (!_status.isClosed) _status.add(status);
  }
}
