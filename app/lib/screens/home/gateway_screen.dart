import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/format.dart';
import '../../core/protocol.dart';
import '../../core/theme.dart';
import '../../data/api/api_client.dart';
import '../../data/protocol/canonical.dart';
import '../../data/models/models.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';
import '../devices/node_screen.dart';
import 'rename_dialog.dart';

/// One plot: its nodes, their readings, and manual controls.
class GatewayScreen extends ConsumerStatefulWidget {
  const GatewayScreen({super.key, required this.gateway});

  final Gateway gateway;

  @override
  ConsumerState<GatewayScreen> createState() => _GatewayScreenState();
}

class _GatewayScreenState extends ConsumerState<GatewayScreen> {
  /// Commands sent but not yet settled, so a control can show it is in flight
  /// instead of silently snapping back.
  final _pending = <String, String>{};

  @override
  Widget build(BuildContext context) {
    final telemetry = ref.watch(telemetryProvider(widget.gateway.id));
    // Keep the label current if it was renamed from another screen.
    final gateway = ref
            .watch(gatewaysProvider)
            .where((candidate) => candidate.id == widget.gateway.id)
            .firstOrNull ??
        widget.gateway;

    return Scaffold(
      appBar: AppBar(
        title: Text(gateway.displayName),
        actions: [
          IconButton(
            tooltip: 'Rename this plot',
            onPressed: () => renameGateway(context, ref, gateway),
            icon: const Icon(Icons.drive_file_rename_outline),
          ),
          IconButton(
            tooltip: 'Refresh',
            onPressed: () => ref.read(telemetryProvider(gateway.id).notifier).refresh(),
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: SafeArea(
        child: RefreshIndicator(
          color: FloraColors.soil,
          onRefresh: () => ref.read(telemetryProvider(gateway.id).notifier).refresh(),
          child: _body(gateway, telemetry),
        ),
      ),
    );
  }

  Widget _body(Gateway gateway, GatewayTelemetry telemetry) {
    if (telemetry.error != null && telemetry.nodes.isEmpty) {
      return ListView(
        children: [
          SizedBox(height: MediaQuery.sizeOf(context).height * 0.2),
          ErrorState(
            message: telemetry.error!,
            onRetry: () => ref.read(telemetryProvider(gateway.id).notifier).refresh(),
          ),
        ],
      );
    }

    if (telemetry.loading && telemetry.nodes.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (telemetry.nodes.isEmpty) {
      return ListView(
        children: const [
          SizedBox(height: 120),
          EmptyState(
            icon: Icons.sensors_off,
            title: 'No nodes yet',
            body: 'This plot has not reported any nodes. It discovers them over its own cable '
                'as they come online.',
          ),
        ],
      );
    }

    return ListView(
      padding: const EdgeInsets.fromLTRB(Gap.lg, Gap.md, Gap.lg, Gap.xxl),
      children: [
        _GatewayHeader(gateway: gateway, telemetry: telemetry),
        const SizedBox(height: Gap.xl),
        const SectionHeading('NODES'),
        for (final node in telemetry.nodes) ...[
          _NodeTile(
            gateway: gateway,
            node: node,
            reading: telemetry.readingFor(node.uuid),
            pendingStatus: _pending[node.uuid],
            onOpen: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => NodeScreen(gateway: gateway, node: node),
              ),
            ),
            onValve: (open) => _setValve(gateway, node, open),
          ),
          const SizedBox(height: Gap.md),
        ],
      ],
    );
  }

  /// Open or close a node's valve.
  ///
  /// The command is signed here and verified by the aggregator, so the UI
  /// reflects the request rather than the outcome. A refusal arrives over the
  /// stream and the control reverts, which is why the pending map exists.
  Future<void> _setValve(Gateway gateway, Node node, bool open) async {
    final keypair = await ref.read(keypairProvider.future);
    if (keypair == null) {
      _snack('This phone has no account key. Pair again.');
      return;
    }

    setState(() => _pending[node.uuid] = open ? 'opening' : 'closing');

    try {
      final command = await ref.read(cloudProvider).sendCommand(
            gatewayId: gateway.id,
            nodeAddr: node.addr,
            keypair: keypair,
            kind: Protocol.kindSetValve,
            payload: Canonical.valvePayload(
              open: open,
              // Five minutes is a starting point; the device caps it at its own
              // maximum runtime and refuses anything longer.
              durationSeconds: open ? const Duration(minutes: 5).inSeconds : 0,
            ),
          );
      if (!mounted) return;
      setState(() => _pending[node.uuid] = command.status);
      _snack(
        open
            ? 'Asked ${node.displayName} to water. The device decides whether to.'
            : 'Asked ${node.displayName} to close.',
      );
    } on ApiFailure catch (failure) {
      if (!mounted) return;
      setState(() => _pending.remove(node.uuid));
      _snack(failure.message);
    }
  }

  void _snack(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }
}

/// The plot's own summary: identity, uptime, and firmware.
class _GatewayHeader extends StatelessWidget {
  const _GatewayHeader({required this.gateway, required this.telemetry});

  final Gateway gateway;
  final GatewayTelemetry telemetry;

  @override
  Widget build(BuildContext context) {
    final online = gateway.lastSeen != null &&
        DateTime.now().toUtc().difference(gateway.lastSeen!).inMinutes <= 15;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(Gap.lg),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                StatusPill(
                  text: online ? 'Reporting' : 'Not reporting',
                  colour: online ? FloraColors.leaf : FloraColors.muted,
                  icon: online ? Icons.wifi_tethering : Icons.wifi_off_outlined,
                ),
                const Spacer(),
                if (gateway.firmwareVersion != null)
                  Text(
                    'v${gateway.firmwareVersion}',
                    style: const TextStyle(fontSize: 12, color: FloraColors.muted),
                  ),
              ],
            ),
            const SizedBox(height: Gap.md),
            MetricTile(
              label: 'Last heard from',
              value: Fmt.ago(gateway.lastSeen),
              icon: Icons.schedule,
            ),
            MetricTile(
              label: 'Nodes found',
              value: '${telemetry.nodes.length}',
              icon: Icons.hub_outlined,
            ),
          ],
        ),
      ),
    );
  }
}

/// One node row, with its reading and a valve control.
class _NodeTile extends StatelessWidget {
  const _NodeTile({
    required this.gateway,
    required this.node,
    required this.reading,
    required this.onOpen,
    required this.onValve,
    this.pendingStatus,
  });

  final Gateway gateway;
  final Node node;
  final Reading? reading;
  final VoidCallback onOpen;
  final ValueChanged<bool> onValve;
  final String? pendingStatus;

  @override
  Widget build(BuildContext context) {
    final pending = pendingStatus == 'opening' || pendingStatus == 'closing';
    final open = reading?.valveOpen ?? false;

    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(Corners.card),
        onTap: onOpen,
        child: Padding(
          padding: const EdgeInsets.all(Gap.lg),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          node.displayName,
                          style: const TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w700,
                            color: FloraColors.ink,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          node.isSelf
                              ? 'This plot’s sensor'
                              : 'Address ${node.addr} · ${node.online ? "online" : "offline"}',
                          style: const TextStyle(fontSize: 12, color: FloraColors.muted),
                        ),
                      ],
                    ),
                  ),
                  if (pending)
                    const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  else
                    _ValveButton(
                      open: open,
                      enabled: pendingStatus == null || reading != null,
                      onChanged: onValve,
                    ),
                ],
              ),
              const SizedBox(height: Gap.md),
              if (reading == null)
                const Text(
                  'No reading yet.',
                  style: TextStyle(fontSize: 13, color: FloraColors.muted),
                )
              else ...[
                MoistureGauge(value: reading!.moisture),
                const SizedBox(height: Gap.md),
                Row(
                  children: [
                    _MiniMetric(label: 'Soil', value: Fmt.percent(reading!.moisture)),
                    _MiniMetric(label: 'Temp', value: Fmt.celsius(reading!.temperature)),
                    _MiniMetric(label: 'Humidity', value: Fmt.percent(reading!.humidity)),
                  ],
                ),
                if (reading!.isEmpty)
                  const Padding(
                    padding: EdgeInsets.only(top: Gap.sm),
                    child: Text(
                      'This node reported no sensor values. Its probe may not be calibrated yet.',
                      style: TextStyle(fontSize: 12, color: FloraColors.clay),
                    ),
                  ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

/// A small labelled value.
class _MiniMetric extends StatelessWidget {
  const _MiniMetric({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(fontSize: 11, color: FloraColors.muted)),
          Text(
            value,
            style: const TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w700,
              color: FloraColors.ink,
            ),
          ),
        ],
      ),
    );
  }
}

/// A valve control that shows its own pending state.
class _ValveButton extends StatelessWidget {
  const _ValveButton({
    required this.open,
    required this.enabled,
    required this.onChanged,
  });

  final bool open;
  final bool enabled;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    final colour = open ? FloraColors.water : FloraColors.soil;
    return Semantics(
      button: true,
      label: open ? 'Close the valve' : 'Open the valve',
      child: Material(
        color: colour.withValues(alpha: 0.12),
        shape: const CircleBorder(),
        child: InkWell(
          customBorder: const CircleBorder(),
          onTap: enabled ? () => onChanged(!open) : null,
          child: Padding(
            padding: const EdgeInsets.all(Gap.md),
            child: Icon(
              open ? Icons.water_drop : Icons.water_drop_outlined,
              color: enabled ? colour : FloraColors.muted,
              size: 22,
            ),
          ),
        ),
      ),
    );
  }
}

