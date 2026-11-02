import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/format.dart';
import '../../core/theme.dart';
import '../../data/models/models.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';
import '../home/gateway_screen.dart';
import '../home/home_screen.dart';

/// The devices tab: every plot and the nodes under it, in one list.
class DevicesScreen extends ConsumerWidget {
  const DevicesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final account = ref.watch(accountProvider);

    if (!account.restored) {
      return const PageBody(
        title: 'Devices',
        child: SizedBox(height: 240, child: Center(child: CircularProgressIndicator())),
      );
    }

    if (!account.isSignedIn) {
      return PageBody(
        title: 'Devices',
        child: EmptyState(
          icon: Icons.sensors_outlined,
          title: 'No devices yet',
          body: 'Add your first plot by scanning the code that came with it.',
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
        title: 'Devices',
        child: EmptyState(
          icon: Icons.add_link,
          title: 'Nothing paired yet',
          body: 'Scan a code to add a plot to this account.',
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
      title: 'Devices',
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
          for (final gateway in gateways) ...[
            _GatewaySection(gateway: gateway),
            const SizedBox(height: Gap.xl),
          ],
        ],
      ),
    );
  }
}

/// One plot and the nodes beneath it.
class _GatewaySection extends ConsumerWidget {
  const _GatewaySection({required this.gateway});

  final Gateway gateway;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Subscribing here keeps the list live without polling.
    ref.watch(accountStreamProvider);
    final telemetry = ref.watch(telemetryProvider(gateway.id));

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SectionHeading(
          gateway.displayName.toUpperCase(),
          trailing: TextButton(
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => GatewayScreen(gateway: gateway)),
            ),
            child: const Text('Open'),
          ),
        ),
        Card(
          child: Column(
            children: [
              if (telemetry.nodes.isEmpty)
                const Padding(
                  padding: EdgeInsets.all(Gap.lg),
                  child: Row(
                    children: [
                      Icon(Icons.sensors_off, size: 20, color: FloraColors.muted),
                      SizedBox(width: Gap.md),
                      Expanded(
                        child: Text(
                          'No nodes found yet.',
                          style: TextStyle(fontSize: 14, color: FloraColors.muted),
                        ),
                      ),
                    ],
                  ),
                )
              else
                for (var index = 0; index < telemetry.nodes.length; index++) ...[
                  if (index > 0) const Divider(height: 1),
                  _NodeRow(
                    gateway: gateway,
                    node: telemetry.nodes[index],
                    reading: telemetry.readingFor(telemetry.nodes[index].uuid),
                  ),
                ],
            ],
          ),
        ),
      ],
    );
  }
}

/// One node, compact.
class _NodeRow extends StatelessWidget {
  const _NodeRow({
    required this.gateway,
    required this.node,
    required this.reading,
  });

  final Gateway gateway;
  final Node node;
  final Reading? reading;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: Gap.lg, vertical: Gap.xs),
      leading: Container(
        width: 40,
        height: 40,
        decoration: BoxDecoration(
          color: (node.online ? FloraColors.leaf : FloraColors.muted).withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(Corners.field),
        ),
        child: Icon(
          node.isSelf ? Icons.eco : Icons.sensors,
          size: 20,
          color: node.online ? FloraColors.leaf : FloraColors.muted,
        ),
      ),
      title: Text(
        node.displayName,
        style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15),
      ),
      subtitle: Text(
        reading == null
            ? 'No reading yet'
            : '${Fmt.percent(reading!.moisture)} soil · ${Fmt.celsius(reading!.temperature)} · ${Fmt.ago(reading!.timestamp)}',
        style: const TextStyle(fontSize: 12, color: FloraColors.muted),
      ),
      trailing: reading?.valveState == null
          ? null
          : ValveChip(open: reading!.valveOpen, compact: true),
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => GatewayScreen(gateway: gateway)),
      ),
    );
  }
}
