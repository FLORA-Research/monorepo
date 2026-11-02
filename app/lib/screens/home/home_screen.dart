import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/format.dart';
import '../../core/theme.dart';
import '../../data/models/models.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';
import '../pairing/pair_screen.dart';
import 'gateway_screen.dart';

/// The farm overview: every gateway, and a summary of the whole farm.
///
/// With no account this is an empty state that explains what to do, not a
/// sign-in screen. That distinction is the point of the design.
class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final account = ref.watch(accountProvider);

    // Before the first restore finishes, show a spinner rather than the empty
    // state, so a returning user is not told they have no devices.
    if (!account.restored) {
      return const PageBody(
        title: 'Farm',
        child: SizedBox(
          height: 240,
          child: Center(child: CircularProgressIndicator()),
        ),
      );
    }

    if (!account.isSignedIn) {
      return PageBody(
        title: 'Farm',
        child: EmptyState(
          icon: Icons.eco_outlined,
          title: 'No devices yet',
          body: 'Scan the code that came with your FLORA box to add your first plot.',
          action: SizedBox(
            width: 220,
            child: FilledButton.icon(
              onPressed: () => openPairing(context, ref),
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Scan the code'),
            ),
          ),
        ),
      );
    }

    final gateways = ref.watch(gatewaysProvider);
    if (gateways.isEmpty) {
      return PageBody(
        title: 'Farm',
        onRefresh: () => ref.read(accountProvider.notifier).refresh(),
        child: EmptyState(
          icon: Icons.add_link,
          title: 'No plots on this account',
          body: 'Add another aggregator by scanning its code.',
          action: SizedBox(
            width: 220,
            child: FilledButton.icon(
              onPressed: () => openPairing(context, ref),
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Add a plot'),
            ),
          ),
        ),
      );
    }

    return PageBody(
      title: 'Farm',
      onRefresh: () => ref.read(accountProvider.notifier).refresh(),
      actions: [
        IconButton(
          tooltip: 'Add a plot',
          onPressed: () => openPairing(context, ref),
          icon: const Icon(Icons.add),
        ),
      ],
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _FarmSummary(gateways: gateways),
          const SizedBox(height: Gap.xl),
          const SectionHeading('PLOTS'),
          for (final gateway in gateways) ...[
            _GatewayCard(gateway: gateway),
            const SizedBox(height: Gap.md),
          ],
        ],
      ),
    );
  }
}

/// Opens the pairing screen and refreshes on success.
Future<void> openPairing(BuildContext context, WidgetRef ref) async {
  final paired = await Navigator.of(context).push<bool>(
    MaterialPageRoute(builder: (_) => const PairScreen()),
  );
  if (paired == true) {
    await ref.read(accountProvider.notifier).refresh();
  }
}

/// Counts across the whole farm.
class _FarmSummary extends ConsumerWidget {
  const _FarmSummary({required this.gateways});

  final List<Gateway> gateways;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final claimed = gateways.where((gateway) => gateway.isClaimed).length;
    final online = gateways
        .where((gateway) =>
            gateway.lastSeen != null &&
            DateTime.now().toUtc().difference(gateway.lastSeen!).inMinutes <= 15)
        .length;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(Gap.lg),
        child: Row(
          children: [
            _SummaryStat(label: 'Plots', value: '$claimed', icon: Icons.landscape_outlined),
            _SummaryStat(label: 'Reporting', value: '$online', icon: Icons.wifi_tethering),
            _SummaryStat(
              label: 'Not now',
              value: '${claimed - online}',
              icon: Icons.wifi_off_outlined,
              muted: true,
            ),
          ],
        ),
      ),
    );
  }
}

class _SummaryStat extends StatelessWidget {
  const _SummaryStat({
    required this.label,
    required this.value,
    required this.icon,
    this.muted = false,
  });

  final String label;
  final String value;
  final IconData icon;
  final bool muted;

  @override
  Widget build(BuildContext context) {
    final colour = muted ? FloraColors.muted : FloraColors.soil;
    return Expanded(
      child: Column(
        children: [
          Icon(icon, size: 20, color: colour),
          const SizedBox(height: Gap.xs),
          Text(
            value,
            style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800, color: colour),
          ),
          Text(
            label,
            style: const TextStyle(fontSize: 12, color: FloraColors.muted),
          ),
        ],
      ),
    );
  }
}

/// One plot, with a live reading from its own node.
class _GatewayCard extends ConsumerWidget {
  const _GatewayCard({required this.gateway});

  final Gateway gateway;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // The stream keeps this current without the card doing any work.
    ref.watch(accountStreamProvider);
    final telemetry = ref.watch(telemetryProvider(gateway.id));
    final self = telemetry.nodes.where((node) => node.isSelf).firstOrNull;
    final reading = self == null ? null : telemetry.readingFor(self.uuid);

    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(Corners.card),
        onTap: () => Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => GatewayScreen(gateway: gateway)),
        ),
        child: Padding(
          padding: const EdgeInsets.all(Gap.lg),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      gateway.displayName,
                      style: const TextStyle(
                        fontSize: 17,
                        fontWeight: FontWeight.w700,
                        color: FloraColors.ink,
                      ),
                    ),
                  ),
                  if (reading?.valveState != null) ValveChip(open: reading!.valveOpen, compact: true),
                ],
              ),
              const SizedBox(height: Gap.xs),
              Row(
                children: [
                  Text(
                    '${telemetry.nodes.length} node${telemetry.nodes.length == 1 ? "" : "s"}',
                    style: const TextStyle(fontSize: 12, color: FloraColors.muted),
                  ),
                  const SizedBox(width: Gap.md),
                  Text(
                    'Seen ${Fmt.ago(gateway.lastSeen)}',
                    style: const TextStyle(fontSize: 12, color: FloraColors.muted),
                  ),
                ],
              ),
              const SizedBox(height: Gap.md),
              if (telemetry.loading && telemetry.readings.isEmpty)
                const SizedBox(
                  height: 4,
                  child: LinearProgressIndicator(minHeight: 4),
                )
              else if (reading == null || reading.isEmpty)
                const Text(
                  'No readings yet. This plot has not reported since it was added.',
                  style: TextStyle(fontSize: 13, color: FloraColors.muted),
                )
              else ...[
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        'Soil ${Fmt.percent(reading.moisture)}',
                        style: const TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                          color: FloraColors.ink,
                        ),
                      ),
                    ),
                    Text(
                      Fmt.celsius(reading.temperature),
                      style: const TextStyle(fontSize: 13, color: FloraColors.muted),
                    ),
                  ],
                ),
                const SizedBox(height: Gap.sm),
                MoistureGauge(value: reading.moisture),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
