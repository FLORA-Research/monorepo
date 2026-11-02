import 'dart:typed_data';

import '../../core/protocol.dart';
import '../protocol/canonical.dart';

/// A gateway: a Pico W that owns one plot's bus.
class Gateway {
  const Gateway({
    required this.id,
    required this.status,
    this.label,
    this.firmwareVersion,
    this.lastSeen,
    this.claimedAt,
  });

  /// The 32-character hex device id.
  final String id;

  /// `unclaimed`, `claimed`, or `retired`.
  final String status;

  final String? label;
  final String? firmwareVersion;
  final DateTime? lastSeen;
  final DateTime? claimedAt;

  bool get isClaimed => status == 'claimed';
  bool get isRetired => status == 'retired';

  /// Raw 16-byte id, for the canonical command encoding.
  Uint8List get idBytes {
    final bytes = Canonical.hexDecode(id);
    if (bytes == null || bytes.length != Protocol.gatewayIdLength) {
      throw StateError('gateway id $id is not ${Protocol.gatewayIdLength} bytes of hex');
    }
    return bytes;
  }

  /// Name to show, falling back to a short form of the id.
  String get displayName =>
      (label != null && label!.trim().isNotEmpty) ? label!.trim() : 'Plot ${id.substring(0, 4)}';

  factory Gateway.fromJson(Map<String, dynamic> json) {
    return Gateway(
      id: json['id'] as String,
      status: json['status'] as String? ?? 'unclaimed',
      label: json['label'] as String?,
      firmwareVersion: json['fw_version'] as String?,
      lastSeen: _parseTime(json['last_seen']),
      claimedAt: _parseTime(json['claimed_at']),
    );
  }
}

/// A field node discovered on a gateway's bus.
class Node {
  const Node({
    required this.uuid,
    required this.addr,
    required this.online,
    this.label,
    this.firmwareVersion,
    this.lastSeen,
  });

  /// 16-character hex node uuid.
  final String uuid;

  /// RS-485 address. `1` is the aggregator's own plot.
  final int addr;

  final bool online;
  final String? label;
  final String? firmwareVersion;
  final DateTime? lastSeen;

  /// Whether this node is the aggregator watering its own plot.
  ///
  /// Address 1 is the aggregator itself; anything else is on the bus.
  bool get isSelf => addr == 1;

  String get displayName {
    final trimmed = label?.trim();
    if (trimmed != null && trimmed.isNotEmpty) return trimmed;
    return isSelf ? 'This plot' : 'Node $addr';
  }

  factory Node.fromJson(Map<String, dynamic> json) {
    return Node(
      uuid: json['node_uuid'] as String,
      addr: (json['addr'] as num).toInt(),
      online: json['online'] as bool? ?? false,
      label: json['label'] as String?,
      firmwareVersion: json['fw_version'] as String?,
      lastSeen: _parseTime(json['last_seen']),
    );
  }
}

/// One sensor reading.
///
/// Metrics are nullable because the firmware reports `unavailable` for a
/// sentinel or an uncalibrated probe, and the cloud stores that as SQL `NULL`.
/// A null means "not measured", never zero, so the UI must not render it as a
/// number or let it trigger an alert.
class Reading {
  const Reading({
    required this.timestamp,
    required this.nodeUuid,
    this.moisture,
    this.temperature,
    this.humidity,
    this.valveState,
    this.seq,
  });

  final DateTime timestamp;
  final String nodeUuid;

  /// Percent, `0..100`, or null when unavailable.
  final double? moisture;

  /// Degrees Celsius, or null when unavailable.
  final double? temperature;

  /// Percent, `0..100`, or null when unavailable.
  final double? humidity;

  /// `0` closed, `1` open, or null when not reported.
  final int? valveState;

  final int? seq;

  bool get valveOpen => valveState == 1;

  /// Whether this reading carries nothing usable, so the UI can say so once
  /// instead of showing three dashes.
  bool get isEmpty =>
      moisture == null && temperature == null && humidity == null;

  factory Reading.fromJson(Map<String, dynamic> json) {
    return Reading(
      timestamp: _parseTime(json['ts']) ?? DateTime.now().toUtc(),
      nodeUuid: json['node_uuid'] as String,
      moisture: _parseDouble(json['moisture']),
      temperature: _parseDouble(json['temperature']),
      humidity: _parseDouble(json['humidity']),
      valveState: (json['valve_state'] as num?)?.toInt(),
      seq: (json['seq'] as num?)?.toInt(),
    );
  }
}

/// An account, which exists only once a gateway has been claimed.
class Account {
  const Account({
    required this.id,
    required this.createdAt,
    required this.gateways,
  });

  final String id;
  final DateTime createdAt;
  final List<Gateway> gateways;

  factory Account.fromJson(Map<String, dynamic> json) {
    final gateways = (json['gateways'] as List<dynamic>? ?? const [])
        .map((entry) => Gateway.fromJson(entry as Map<String, dynamic>))
        .toList(growable: false);
    return Account(
      id: json['account_id'] as String,
      createdAt: _parseTime(json['created_at']) ?? DateTime.now().toUtc(),
      gateways: gateways,
    );
  }
}

/// A manual command's state, as the audit trail reports it.
class CommandStatus {
  const CommandStatus({
    required this.id,
    required this.kind,
    required this.nodeAddr,
    required this.status,
    required this.expiresAt,
  });

  final String id;
  final String kind;
  final int nodeAddr;

  /// `pending`, `dispatched`, `applied`, `refused`, or `expired`.
  final String status;

  final DateTime expiresAt;

  /// Whether the command reached a conclusion, so the UI can stop showing it as
  /// in flight.
  bool get isSettled => status != 'pending' && status != 'dispatched';

  /// A refusal or an expiry is a failure the farmer should see.
  bool get isFailure => status == 'refused' || status == 'expired';

  factory CommandStatus.fromJson(Map<String, dynamic> json) {
    return CommandStatus(
      id: json['id'] as String,
      kind: json['kind'] as String,
      nodeAddr: (json['node_addr'] as num).toInt(),
      status: json['status'] as String,
      expiresAt: _parseTime(json['expires_at']) ?? DateTime.now().toUtc(),
    );
  }
}

/// Parse an RFC 3339 timestamp, tolerating a value the server omitted.
DateTime? _parseTime(Object? value) {
  if (value is! String || value.isEmpty) return null;
  return DateTime.tryParse(value)?.toUtc();
}

/// Parse a JSON number that may be null.
double? _parseDouble(Object? value) {
  if (value == null) return null;
  if (value is num) return value.toDouble();
  return null;
}
