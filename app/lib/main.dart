import 'package:flutter/material.dart';

void main() {
  runApp(const FloraApp());
}

/// FLORA app shell. Hello world for now: a single home screen that will
/// grow into gateway and plot views.
class FloraApp extends StatelessWidget {
  const FloraApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FLORA',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.green),
      ),
      home: const HomeScreen(),
    );
  }
}

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('FLORA')),
      body: const Center(child: Text('No gateways yet')),
    );
  }
}
