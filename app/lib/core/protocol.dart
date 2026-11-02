/// Wire constants shared with the Rust crates.
///
/// Every value here is a contract. A mismatch does not raise an error, it
/// produces a signature the device rejects or a field the cloud misreads, so
/// each constant cites the Rust source it must match and a test pins the byte
/// layout.
///
/// Sources:
/// - `cloud/crates/flora-protocol/src/lib.rs`
/// - `cloud/docs/commands.md`
/// - `cloud/crates/flora-auth/src/pairing.rs`
class Protocol {
  Protocol._();

  /// Version byte of the canonical command encoding.
  ///
  /// From `CANONICAL_VERSION` in `flora-protocol`.
  static const int canonicalVersion = 0x01;

  /// Length of the canonical command message.
  ///
  /// `version(1) kind(1) gateway_id(16) node_addr(1) nonce(4) timestamp(4)
  /// payload(4)` from `CANONICAL_MESSAGE_LEN`.
  static const int canonicalMessageLength = 31;

  /// Bytes in a gateway id: the 16-byte `device_id`, hex-encoded on the wire.
  static const int gatewayIdLength = 16;

  /// Hex characters in a gateway id.
  static const int gatewayIdHexLength = gatewayIdLength * 2;

  /// Bytes in an Ed25519 public key and signature.
  static const int publicKeyLength = 32;
  static const int signatureLength = 64;

  /// Bytes in a node uuid, which is narrower than a gateway id.
  static const int nodeUuidLength = 8;

  /// Bytes in every opaque token (device, claim, refresh, nonce).
  static const int tokenLength = 32;

  /// Bytes in a pairing nonce.
  static const int nonceLength = 16;

  /// Command kinds, from `flora-protocol`.
  static const int kindSetValve = 1;
  static const int kindSetThreshold = 2;
  static const int kindCalibrate = 3;

  /// Command kind names as the API accepts them.
  static String kindName(int kind) => switch (kind) {
        kindSetValve => 'set_valve',
        kindSetThreshold => 'set_threshold',
        kindCalibrate => 'calibrate',
        _ => throw ArgumentError('unknown command kind $kind'),
      };

  /// Byte length of a command payload. Every kind currently uses four bytes.
  static int payloadLength(int kind) => switch (kind) {
        kindSetValve || kindSetThreshold || kindCalibrate => 4,
        _ => throw ArgumentError('unknown command kind $kind'),
      };

  /// Domain separators.
  ///
  /// Pairing and authentication sign different prefixes so a signature made for
  /// one flow cannot be replayed into the other.
  static const String pairingPrefix = 'flora-pair-v1';
  static const String authPrefix = 'flora-auth-v1';

  /// QR scheme for a claim.
  static const String pairScheme = 'flora';
  static const String pairHost = 'pair';
  static const int pairVersion = 1;

  /// Per-mille sentinel meaning "unavailable", from the firmware.
  ///
  /// The cloud converts this to `null` on ingest, so a client should never see
  /// it. It is kept because a cached or mocked response might carry it.
  static const int unavailableU16 = 0xFFFF;

  /// Temperature sentinel meaning "unavailable", from the firmware.
  static const int unavailableI16 = -32768;
}
