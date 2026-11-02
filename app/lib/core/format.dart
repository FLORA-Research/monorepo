import 'package:intl/intl.dart';

/// Formatting for display.
///
/// Centralised so a reading never renders as a bare number where a unit is
/// needed, and so the unavailable case is handled once rather than per screen.
abstract final class Fmt {
  /// A moisture or humidity percentage, or a dash when unavailable.
  ///
  /// The firmware reports "unavailable" for an uncalibrated probe, and the
  /// cloud stores that as null. Rendering it as `0%` would read as bone dry and
  /// could prompt watering that is not needed.
  static String percent(double? value, {int decimals = 0}) {
    if (value == null) return '--';
    return '${value.toStringAsFixed(decimals)}%';
  }

  /// A temperature in degrees Celsius, or a dash when unavailable.
  static String celsius(double? value, {int decimals = 1}) {
    if (value == null) return '--';
    return '${value.toStringAsFixed(decimals)}°C';
  }

  /// Relative time, which is what a farmer cares about: how long ago.
  static String ago(DateTime? when) {
    if (when == null) return 'never';
    final delta = DateTime.now().toUtc().difference(when.toUtc());
    if (delta.isNegative) return 'just now';
    if (delta.inSeconds < 60) return 'just now';
    if (delta.inMinutes < 60) return '${delta.inMinutes} min ago';
    if (delta.inHours < 24) return '${delta.inHours} h ago';
    if (delta.inDays < 30) return '${delta.inDays} d ago';
    return DateFormat.yMMMd().format(when.toLocal());
  }

  /// An absolute timestamp for a history row.
  static String stamp(DateTime when) {
    final local = when.toLocal();
    final today = DateTime.now();
    final isToday = local.year == today.year &&
        local.month == today.month &&
        local.day == today.day;
    return isToday
        ? DateFormat.Hm().format(local)
        : DateFormat('d MMM, HH:mm').format(local);
  }

  /// A valve-open duration in seconds, as a person would say it.
  static String duration(int seconds) {
    if (seconds <= 0) return 'off';
    if (seconds < 60) return '${seconds}s';
    final minutes = seconds ~/ 60;
    final remainder = seconds % 60;
    if (remainder == 0) return '$minutes min';
    return '$minutes min ${remainder}s';
  }

  /// A label or a generated fallback.
  static String label(String? value, String fallback) {
    final trimmed = value?.trim();
    return (trimmed == null || trimmed.isEmpty) ? fallback : trimmed;
  }
}

/// Thresholds that decide what a moisture reading means.
///
/// These are presentation defaults only. The device holds the real thresholds
/// and the cloud never decides, so this exists to colour a gauge, not to
/// irrigate.
abstract final class MoistureScale {
  /// Below this, the soil is dry enough that the device would water.
  static const double dry = 30;

  /// Above this, the device would stop watering.
  static const double wet = 60;

  /// A band for the gauge, 0 to 100 percent.
  static const double min = 0;
  static const double max = 100;
}
