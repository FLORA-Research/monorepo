import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/format.dart';
import '../../core/theme.dart';
import '../../data/models/models.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';
import '../home/gateway_screen.dart';

/// Alerts: the conditions worth interrupting a farmer for.
///
/// Derived on the device from what the app already knows, rather than pushed
/// from the cloud. A farm with poor signal still gets a warning, and the cloud
/// never has to decide what matters.
class AlertsScreen extends ConsumerWidget {
  const AlertsScreen({super.key});

  /// A plot silent for this long is treated as offline.
  static const offlineAfter = Duration(minutes: 30);

  /// Below this, the soil is dry enough to be worth mentioning.
  static const dryBelow = 30.0;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final account = ref.watch(accountProvider);

    if (!account.restored) {
      return const PageBody(
        title: 'Alerts',
        child: SizedBox(height: 240, child: Center(child: CircularProgressIndicator())),
      );
    }

    final alerts = _collect(ref);
    if (alerts.isEmpty) {
      return PageBody(
        title: 'Alerts',
        onRefresh: () => ref.read(accountProvider.notifier).refresh(),
        child: const EmptyState(
          icon: Icons.check_circle_outline,
          title: 'Nothing needs attention',
          body: 'Dry soil, a silent plot, or a low battery will appear here.',
        ),
      );
    }

    return PageBody(
      title: 'Alerts',
      onRefresh: () => ref.read(accountProvider.notifier).refresh(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          for (final alert in alerts) ...[
            _AlertCard(alert: alert),
            const SizedBox(height: Gap.md),
          ],
        ],
      ),
    );
  }

  /// Build the alert list from the current state.
  List<_Alert> _collect(WidgetRef ref) {
    final gateways = ref.watch(gatewaysProvider);
    final now = DateTime.now().toUtc();
    final alerts = <_Alert>[];

    for (final gateway in gateways) {
      if (gateway.isRetired) continue;

      final telemetry = ref.watch(telemetryProvider(gateway.id));

      // A plot that has gone quiet is the most important thing to say, because
      // irrigation decisions are still being made locally and the farmer
      // cannot see them.
      final lastSeen = gateway.lastSeen;
      if (lastSeen == null || now.difference(lastSeen) > offlineAfter) {
        alerts.add(_Alert(
          severity: AlertSeverity.warning,
          title: '${gateway.displayName} is not reporting',
          body: lastSeen == null
              ? 'This plot has never reported since it was added.'
              : 'Last heard from ${Fmt.ago(lastSeen)}. Its irrigation continues on its own.',
          gateway: gateway,
        ));
        continue;
      }

      for (final node in telemetry.nodes) {
        final reading = telemetry.readingFor(node.uuid);
        if (reading == null) continue;

        // A null moisture is "unknown", not "dry". Alerting on it would cry
        // wolf on every uncalibrated node.
        final moisture = reading.moisture;
        if (moisture != null && moisture < dryBelow) {
          alerts.add(_Alert(
            severity: AlertSeverity.warning,
            title: '${node.displayName} is dry',
            body: 'Soil is at ${Fmt.percent(moisture)}. The device waters on its own '
                'threshold; open the node to water now.',
            gateway: gateway,
            node: node,
          ));
        }

        if (!node.online) {
          alerts.add(_Alert(
            severity: AlertSeverity.info,
            title: '${node.displayName} stopped answering',
            body: 'Last seen ${Fmt.ago(node.lastSeen)}. Check the cable and its power.',
            gateway: gateway,
            node: node,
          ));
        }
      }
    }

    // Warnings before information, so the important thing is on top.
    alerts.sort((a, b) => a.severity.index.compareTo(b.severity.index));
    return alerts;
  }
}

enum AlertSeverity { warning, info }

class _Alert {
  const _Alert({
    required this.severity,
    required this.title,
    required this.body,
    required this.gateway,
    this.node,
  });

  final AlertSeverity severity;
  final String title;
  final String body;
  final Gateway gateway;
  final Node? node;
}

class _AlertCard extends StatelessWidget {
  const _AlertCard({required this.alert});

  final _Alert alert;

  @override
  Widget build(BuildContext context) {
    final colour = switch (alert.severity) {
      AlertSeverity.warning => FloraColors.clay,
      AlertSeverity.info => FloraColors.water,
    };
    final icon = switch (alert.severity) {
      AlertSeverity.warning => Icons.warning_amber_rounded,
      AlertSeverity.info => Icons.info_outline,
    };

    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(Corners.card),
        onTap: () => Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => GatewayScreen(gateway: alert.gateway)),
        ),
        child: Padding(
          padding: const EdgeInsets.all(Gap.lg),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                padding: const EdgeInsets.all(Gap.sm),
                decoration: BoxDecoration(
                  color: colour.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(Corners.field),
                ),
                child: Icon(icon, color: colour, size: 20),
              ),
              const SizedBox(width: Gap.md),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      alert.title,
                      style: const TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                        color: FloraColors.ink,
                      ),
                    ),
                    const SizedBox(height: Gap.xs),
                    Text(
                      alert.body,
                      style: const TextStyle(
                        fontSize: 13,
                        color: FloraColors.muted,
                        height: 1.35,
                      ),
                    ),
                  ],
                ),
              ),
              const Icon(Icons.chevron_right, color: FloraColors.muted),
            ],
          ),
        ),
      ),
    );
  }
}
