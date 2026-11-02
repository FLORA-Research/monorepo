import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/format.dart';
import '../../core/protocol.dart';
import '../../core/theme.dart';
import '../../data/api/api_client.dart';
import '../../data/models/models.dart';
import '../../data/protocol/canonical.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';
import '../home/rename_dialog.dart';

/// One node: its live reading, history, and manual controls.
class NodeScreen extends ConsumerStatefulWidget {
  const NodeScreen({super.key, required this.gateway, required this.node});

  final Gateway gateway;
  final Node node;

  @override
  ConsumerState<NodeScreen> createState() => _NodeScreenState();
}

class _NodeScreenState extends ConsumerState<NodeScreen> {
  /// The selected history window.
  Duration _window = const Duration(hours: 24);

  List<Reading>? _history;
  String? _historyError;
  bool _loadingHistory = true;

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  Future<void> _loadHistory() async {
    setState(() {
      _loadingHistory = true;
      _historyError = null;
    });
    try {
      final readings = await ref.read(cloudProvider).history(
            widget.gateway.id,
            since: DateTime.now().toUtc().subtract(_window),
            nodeUuid: widget.node.uuid,
          );
      if (!mounted) return;
      setState(() {
        // Oldest first, which is the order a chart wants.
        _history = readings.reversed.toList(growable: false);
        _loadingHistory = false;
      });
    } on ApiFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _historyError = failure.message;
        _loadingHistory = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    ref.watch(accountStreamProvider);
    final telemetry = ref.watch(telemetryProvider(widget.gateway.id));
    final reading = telemetry.readingFor(widget.node.uuid);
    final node = telemetry.nodes
            .where((candidate) => candidate.uuid == widget.node.uuid)
            .firstOrNull ??
        widget.node;

    return Scaffold(
      appBar: AppBar(
        title: Text(node.displayName),
        actions: [
          IconButton(
            tooltip: 'Rename this node',
            onPressed: () => renameNode(context, ref, widget.gateway, node),
            icon: const Icon(Icons.drive_file_rename_outline),
          ),
        ],
      ),
      body: SafeArea(
        child: RefreshIndicator(
          color: FloraColors.soil,
          onRefresh: () async {
            await ref.read(telemetryProvider(widget.gateway.id).notifier).refresh();
            await _loadHistory();
          },
          child: ListView(
            padding: const EdgeInsets.fromLTRB(Gap.lg, Gap.md, Gap.lg, Gap.xxl),
            children: [
              _LiveCard(node: node, reading: reading),
              const SizedBox(height: Gap.xl),
              SectionHeading(
                'HISTORY',
                trailing: _WindowPicker(
                  value: _window,
                  onChanged: (value) {
                    setState(() => _window = value);
                    _loadHistory();
                  },
                ),
              ),
              _HistoryChart(
                loading: _loadingHistory,
                error: _historyError,
                readings: _history ?? const [],
                window: _window,
              ),
              const SizedBox(height: Gap.xl),
              const SectionHeading('MANUAL CONTROL'),
              _ManualControl(
                gateway: widget.gateway,
                node: node,
                reading: reading,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// The current reading, or a clear statement that there is not one.
class _LiveCard extends StatelessWidget {
  const _LiveCard({required this.node, required this.reading});

  final Node node;
  final Reading? reading;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(Gap.lg),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                StatusPill(
                  text: node.online ? 'Online' : 'Offline',
                  colour: node.online ? FloraColors.leaf : FloraColors.muted,
                  icon: node.online ? Icons.check_circle_outline : Icons.cloud_off,
                ),
                const Spacer(),
                Text(
                  reading == null ? 'No reading' : Fmt.stamp(reading!.timestamp),
                  style: const TextStyle(fontSize: 12, color: FloraColors.muted),
                ),
              ],
            ),
            const SizedBox(height: Gap.lg),
            if (reading == null)
              const Text(
                'This node has not reported since it was found.',
                style: TextStyle(fontSize: 14, color: FloraColors.muted),
              )
            else ...[
              MetricTile(
                label: 'Soil moisture',
                value: Fmt.percent(reading!.moisture),
                icon: Icons.grass,
                hint: reading!.moisture == null ? 'probe not calibrated' : null,
              ),
              MetricTile(
                label: 'Temperature',
                value: Fmt.celsius(reading!.temperature),
                icon: Icons.thermostat,
              ),
              MetricTile(
                label: 'Humidity',
                value: Fmt.percent(reading!.humidity),
                icon: Icons.water_drop_outlined,
              ),
              MetricTile(
                label: 'Valve',
                value: reading!.valveState == null
                    ? '--'
                    : (reading!.valveOpen ? 'Open' : 'Closed'),
                icon: Icons.water_drop,
                tint: reading!.valveOpen ? FloraColors.water : null,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// 24 hours, 7 days, or 45 days.
class _WindowPicker extends StatelessWidget {
  const _WindowPicker({required this.value, required this.onChanged});

  final Duration value;
  final ValueChanged<Duration> onChanged;

  static const _options = <(String, Duration)>[
    ('24 h', Duration(hours: 24)),
    ('7 d', Duration(days: 7)),
    ('45 d', Duration(days: 45)),
  ];

  @override
  Widget build(BuildContext context) {
    return SegmentedButton<Duration>(
      segments: [
        for (final (label, duration) in _options)
          ButtonSegment(value: duration, label: Text(label)),
      ],
      selected: {value},
      onSelectionChanged: (selection) => onChanged(selection.first),
      style: ButtonStyle(
        visualDensity: VisualDensity.compact,
        textStyle: WidgetStatePropertyAll(
          const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
        ),
      ),
      showSelectedIcon: false,
    );
  }
}

/// A moisture trend.
class _HistoryChart extends StatelessWidget {
  const _HistoryChart({
    required this.loading,
    required this.error,
    required this.readings,
    required this.window,
  });

  final bool loading;
  final String? error;
  final List<Reading> readings;
  final Duration window;

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const SizedBox(
        height: 200,
        child: Center(child: CircularProgressIndicator()),
      );
    }
    if (error != null) {
      return SizedBox(
        height: 200,
        child: ErrorState(message: error!),
      );
    }

    // Only points that exist are plotted: a null reading is a gap, not a zero,
    // and drawing it as zero would invent a drought.
    final points = <FlSpot>[];
    for (final reading in readings) {
      if (reading.moisture == null) continue;
      points.add(
        FlSpot(
          reading.timestamp.millisecondsSinceEpoch.toDouble(),
          reading.moisture!,
        ),
      );
    }

    if (points.isEmpty) {
      return const SizedBox(
        height: 200,
        child: EmptyState(
          icon: Icons.show_chart,
          title: 'No history yet',
          body: 'Readings appear here once the plot has been reporting for a while.',
        ),
      );
    }

    final minX = points.first.x;
    final maxX = points.last.x;

    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(Gap.md, Gap.lg, Gap.lg, Gap.md),
        child: SizedBox(
          height: 200,
          child: LineChart(
            LineChartData(
              minY: 0,
              maxY: 100,
              minX: minX,
              maxX: maxX == minX ? minX + 1 : maxX,
              gridData: FlGridData(
                show: true,
                drawVerticalLine: false,
                horizontalInterval: 25,
                getDrawingHorizontalLine: (_) => const FlLine(
                  color: FloraColors.line,
                  strokeWidth: 1,
                ),
              ),
              borderData: FlBorderData(show: false),
              titlesData: FlTitlesData(
                topTitles: const AxisTitles(),
                rightTitles: const AxisTitles(),
                leftTitles: AxisTitles(
                  sideTitles: SideTitles(
                    showTitles: true,
                    reservedSize: 36,
                    interval: 25,
                    getTitlesWidget: (value, meta) => Text(
                      '${value.toInt()}%',
                      style: const TextStyle(fontSize: 10, color: FloraColors.muted),
                    ),
                  ),
                ),
                bottomTitles: AxisTitles(
                  sideTitles: SideTitles(
                    showTitles: true,
                    reservedSize: 28,
                    interval: (maxX - minX) / 3 == 0 ? 1 : (maxX - minX) / 3,
                    getTitlesWidget: (value, meta) {
                      final at = DateTime.fromMillisecondsSinceEpoch(value.toInt()).toUtc();
                      final label = window.inDays >= 7
                          ? '${at.day}/${at.month}'
                          : '${at.hour}:00';
                      return Padding(
                        padding: const EdgeInsets.only(top: Gap.xs),
                        child: Text(
                          label,
                          style: const TextStyle(fontSize: 10, color: FloraColors.muted),
                        ),
                      );
                    },
                  ),
                ),
              ),
              lineTouchData: LineTouchData(
                touchTooltipData: LineTouchTooltipData(
                  getTooltipColor: (_) => FloraColors.ink,
                  getTooltipItems: (spots) => [
                    for (final spot in spots)
                      LineTooltipItem(
                        '${spot.y.toStringAsFixed(1)}%\n'
                        '${Fmt.stamp(DateTime.fromMillisecondsSinceEpoch(spot.x.toInt()).toUtc())}',
                        const TextStyle(color: Colors.white, fontSize: 12),
                      ),
                  ],
                ),
              ),
              lineBarsData: [
                LineChartBarData(
                  spots: points,
                  isCurved: false,
                  color: FloraColors.water,
                  barWidth: 2,
                  dotData: FlDotData(
                    // Individual dots would be noise once there are hundreds.
                    show: points.length < 24,
                  ),
                  belowBarData: BarAreaData(
                    show: true,
                    color: FloraColors.water.withValues(alpha: 0.12),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Explicit valve control, with the real duration cap stated.
class _ManualControl extends ConsumerStatefulWidget {
  const _ManualControl({
    required this.gateway,
    required this.node,
    required this.reading,
  });

  final Gateway gateway;
  final Node node;
  final Reading? reading;

  @override
  ConsumerState<_ManualControl> createState() => _ManualControlState();
}

class _ManualControlState extends ConsumerState<_ManualControl> {
  bool _busy = false;

  Future<void> _send({required bool open}) async {
    final keypair = await ref.read(keypairProvider.future);
    if (keypair == null) {
      _snack('This phone has no account key. Pair again.');
      return;
    }

    setState(() => _busy = true);
    try {
      final command = await ref.read(cloudProvider).sendCommand(
            gatewayId: widget.gateway.id,
            nodeAddr: widget.node.addr,
            kind: Protocol.kindSetValve,
            payload: Canonical.valvePayload(
              open: open,
              durationSeconds: open ? 300 : 0,
            ),
            keypair: keypair,
          );
      if (!mounted) return;
      _snack(
        'Request sent. The device checks it before acting. (${command.status})',
      );
    } on ApiFailure catch (failure) {
      if (mounted) _snack(failure.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _snack(String message) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(Gap.lg),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'The device makes its own decisions and can refuse a request. '
              'A command that arrives too late to be useful expires instead of running.',
              style: TextStyle(fontSize: 13, color: FloraColors.muted),
            ),
            const SizedBox(height: Gap.lg),
            Row(
              children: [
                Expanded(
                  child: FilledButton.icon(
                    onPressed: _busy ? null : () => _send(open: true),
                    icon: const Icon(Icons.water_drop, size: 18),
                    label: const Text('Water now'),
                  ),
                ),
                const SizedBox(width: Gap.md),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _busy ? null : () => _send(open: false),
                    icon: const Icon(Icons.block, size: 18),
                    label: const Text('Close'),
                  ),
                ),
              ],
            ),
            if (_busy) ...[
              const SizedBox(height: Gap.md),
              const LinearProgressIndicator(minHeight: 3),
            ],
          ],
        ),
      ),
    );
  }
}
