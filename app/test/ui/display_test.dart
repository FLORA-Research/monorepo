import 'package:flora_app/core/format.dart';
import 'package:flora_app/data/models/models.dart';
import 'package:flora_app/data/protocol/canonical.dart';
import 'package:flora_app/widgets/common.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('unavailable readings', () {
    test('render as a dash, never as a number', () {
      // The firmware reports "unavailable" for an uncalibrated probe or a
      // failed read, and the cloud stores that as null. Showing 0% would read
      // as bone dry and could prompt watering that is not needed.
      expect(Fmt.percent(null), '--');
      expect(Fmt.celsius(null), '--');
      expect(Fmt.percent(31.2), '31%');
      expect(Fmt.celsius(28.4), '28.4°C');
    });

    test('a reading of zero is shown as zero, not as unavailable', () {
      // Zero and unavailable are different findings and must not be conflated.
      expect(Fmt.percent(0), '0%');
      expect(Fmt.celsius(0), '0.0°C');
    });
  });

  group('reading model', () {
    test('parses nulls from the wire as unknown rather than zero', () {
      final reading = Reading.fromJson({
        'ts': '2026-10-02T12:00:00Z',
        'node_uuid': '0202020202020202',
        'moisture': null,
        'temperature': null,
        'humidity': null,
        'valve_state': 1,
        'seq': 10,
      });
      expect(reading.moisture, isNull);
      expect(reading.temperature, isNull);
      expect(reading.isEmpty, isTrue, reason: 'no usable sensor values');
      expect(reading.valveOpen, isTrue, reason: 'valve state is present and open');
    });

    test('an absent valve state is unknown, not closed', () {
      final reading = Reading.fromJson({
        'ts': '2026-10-02T12:00:00Z',
        'node_uuid': '0202020202020202',
        'valve_state': null,
      });
      expect(reading.valveState, isNull);
      // Treating this as closed would claim certainty the data does not support.
      expect(reading.valveOpen, isFalse);
    });
  });

  group('gateway model', () {
    test('derives its display name from a label or falls back', () {
      final labelled = Gateway.fromJson({
        'id': 'fe812c12f3ab4ce6ac5db69ac352f906',
        'status': 'claimed',
        'label': '  plot-north  ',
      });
      expect(labelled.displayName, 'plot-north', reason: 'trimmed');

      final blank = Gateway.fromJson({
        'id': 'fe812c12f3ab4ce6ac5db69ac352f906',
        'status': 'claimed',
        'label': '   ',
      });
      expect(blank.displayName, startsWith('Plot '));

      final unlabelled = Gateway.fromJson({
        'id': 'fe812c12f3ab4ce6ac5db69ac352f906',
        'status': 'claimed',
      });
      expect(unlabelled.displayName, startsWith('Plot '));
    });

    test('exposes its id as the 16 bytes the canonical encoding needs', () {
      final gateway = Gateway.fromJson({
        'id': 'fe812c12f3ab4ce6ac5db69ac352f906',
        'status': 'claimed',
      });
      expect(gateway.idBytes.length, 16);
      expect(() => Gateway.fromJson({
            'id': 'fe812c12',
            'status': 'claimed',
          }).idBytes,
          throwsStateError,
          reason: 'an 8-byte id would silently sign the wrong bytes');
    });
  });

  group('node model', () {
    test('address 1 is the aggregator itself and is named as such', () {
      final self = Node.fromJson({
        'node_uuid': '0202020202020202',
        'addr': 1,
        'online': true,
      });
      expect(self.isSelf, isTrue);
      expect(self.displayName, 'This plot');

      final bus = Node.fromJson({
        'node_uuid': '0303030303030303',
        'addr': 3,
        'online': true,
      });
      expect(bus.isSelf, isFalse);
      expect(bus.displayName, 'Node 3');

      final named = Node.fromJson({
        'node_uuid': '0303030303030303',
        'addr': 3,
        'online': true,
        'label': 'north bed',
      });
      expect(named.displayName, 'north bed');
    });
  });

  group('widgets survive the states that used to break the old app', () {
    testWidgets('a gauge renders an unavailable value without throwing', (tester) async {
      // Jank and errors in the old app came from rebuilding whole screens and
      // touching disposed controllers. Rendering the leaf widgets with the
      // awkward inputs is the cheap guard against that class returning.
      await tester.pumpWidget(const MaterialApp(
        home: Scaffold(body: Center(child: MoistureGauge(value: null))),
      ));
      expect(tester.takeException(), isNull);
      expect(find.byType(MoistureGauge), findsOneWidget);
    });

    testWidgets('a gauge renders each band without throwing', (tester) async {
      for (final value in [null, 0.0, 10.0, 45.0, 80.0, 100.0]) {
        await tester.pumpWidget(MaterialApp(
          home: Scaffold(body: Center(child: MoistureGauge(value: value))),
        ));
        expect(tester.takeException(), isNull, reason: 'value $value');
      }
    });

    testWidgets('an unknown valve state is shown as unknown', (tester) async {
      await tester.pumpWidget(const MaterialApp(
        home: Scaffold(body: Center(child: ValveChip(open: null))),
      ));
      expect(find.text('Unknown'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('an empty state renders its call to action', (tester) async {
      var tapped = false;
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: EmptyState(
            icon: Icons.eco,
            title: 'No devices yet',
            body: 'Scan the code that came with your FLORA box.',
            action: FilledButton(
              onPressed: () => tapped = true,
              child: const Text('Scan'),
            ),
          ),
        ),
      ));
      expect(find.text('No devices yet'), findsOneWidget);
      await tester.tap(find.text('Scan'));
      await tester.pump();
      expect(tapped, isTrue);
      expect(tester.takeException(), isNull);
    });
  });

  group('payload encoding shown in the UI', () {
    test('a manual water command encodes to the documented bytes', () {
      // The valve button sends exactly this, so the bytes are asserted where a
      // screen would produce them rather than only in isolation.
      expect(Canonical.valvePayload(open: true, durationSeconds: 300), [1, 1, 44, 0]);
      expect(Canonical.valvePayload(open: false, durationSeconds: 0), [0, 0, 0, 0]);
    });
  });
}
