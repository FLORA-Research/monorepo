import 'package:flutter_test/flutter_test.dart';
import 'package:flora_app/main.dart';

void main() {
  testWidgets('home screen renders', (tester) async {
    await tester.pumpWidget(const FloraApp());

    expect(find.text('FLORA'), findsOneWidget);
    expect(find.text('No gateways yet'), findsOneWidget);
  });
}
