import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/theme.dart';
import '../data/ws/event_stream.dart';
import '../providers/providers.dart';
import 'alerts/alerts_screen.dart';
import 'devices/devices_screen.dart';
import 'home/home_screen.dart';
import 'settings/settings_screen.dart';

/// The main shell: Home, Devices, Alerts, Settings.
///
/// The shell renders before anything is known about the account, so the app is
/// usable with no devices and no sign-in. That is the point of the design: a
/// farmer who has not scanned a code yet still gets settings and help, not a
/// login wall.
class ShellScreen extends ConsumerStatefulWidget {
  const ShellScreen({super.key});

  @override
  ConsumerState<ShellScreen> createState() => _ShellScreenState();
}

class _ShellScreenState extends ConsumerState<ShellScreen> {
  int _index = 0;

  static const _destinations = [
    NavigationDestination(
      icon: Icon(Icons.eco_outlined),
      selectedIcon: Icon(Icons.eco),
      label: 'Farm',
    ),
    NavigationDestination(
      icon: Icon(Icons.sensors_outlined),
      selectedIcon: Icon(Icons.sensors),
      label: 'Devices',
    ),
    NavigationDestination(
      icon: Icon(Icons.notifications_none),
      selectedIcon: Icon(Icons.notifications),
      label: 'Alerts',
    ),
    NavigationDestination(
      icon: Icon(Icons.settings_outlined),
      selectedIcon: Icon(Icons.settings),
      label: 'Settings',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final streamStatus = ref.watch(streamStatusProvider);

    return Scaffold(
      body: SafeArea(
        bottom: false,
        child: IndexedStack(
          index: _index,
          children: const [
            HomeScreen(),
            DevicesScreen(),
            AlertsScreen(),
            SettingsScreen(),
          ],
        ),
      ),
      bottomNavigationBar: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // A thin live indicator, so a farmer can tell at a glance whether the
          // numbers on screen are current. Only shown when signed in, because
          // there is nothing to be live about otherwise.
          if (ref.watch(accountProvider).isSignedIn)
            _LiveBar(status: streamStatus.value),
          NavigationBar(
            selectedIndex: _index,
            onDestinationSelected: (index) => setState(() => _index = index),
            destinations: _destinations,
          ),
        ],
      ),
    );
  }
}

/// A one-line connection indicator.
class _LiveBar extends StatelessWidget {
  const _LiveBar({this.status});

  final StreamStatus? status;

  @override
  Widget build(BuildContext context) {
    final (colour, text) = switch (status) {
      StreamStatus.live => (FloraColors.leaf, 'Live'),
      StreamStatus.connecting => (FloraColors.muted, 'Connecting'),
      StreamStatus.reconnecting => (FloraColors.clay, 'Reconnecting'),
      StreamStatus.stopped => (FloraColors.muted, 'Not connected'),
      null => (FloraColors.muted, 'Connecting'),
    };

    return Container(
      width: double.infinity,
      color: colour.withValues(alpha: 0.10),
      padding: const EdgeInsets.symmetric(horizontal: Gap.lg, vertical: 3),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(color: colour, shape: BoxShape.circle),
          ),
          const SizedBox(width: Gap.sm),
          Text(
            text,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: colour,
            ),
          ),
        ],
      ),
    );
  }
}
