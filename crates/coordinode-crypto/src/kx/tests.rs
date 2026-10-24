use getrandom::rand_core::{TryCryptoRng, TryRng};
use rustls::crypto::SupportedKxGroup;

struct FailedEntropy;

impl TryRng for FailedEntropy {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }
}

impl TryCryptoRng for FailedEntropy {}

/// An uncompressed share of `group` completes; its compressed form of the same
/// point, and a share one byte short, are refused.
fn only_uncompressed_shares_complete(group: &dyn SupportedKxGroup, coordinate: usize) {
    let peer = group
        .start()
        .expect("the system entropy source works in tests");
    let uncompressed = peer.pub_key();
    assert_eq!(uncompressed.len(), 1 + 2 * coordinate);
    assert_eq!(uncompressed[0], 0x04);
    assert!(group.start_and_complete(uncompressed).is_ok());

    let mut compressed = alloc::vec![0x02 | (uncompressed[2 * coordinate] & 1)];
    compressed.extend_from_slice(&uncompressed[1..=coordinate]);
    let truncated = &uncompressed[..2 * coordinate];
    for share in [compressed.as_slice(), truncated] {
        assert!(matches!(
            group.start_and_complete(share).map(|_| ()),
            Err(rustls::Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare
            ))
        ));
    }
}

// TLS 1.3 key shares and TLS 1.2 ECDHE points are uncompressed only
// (RFC 8446 section 4.2.8.2, RFC 8422 section 5.1.2), although SEC1 decoders
// accept the compressed form of the same point.
#[test]
fn p256_key_share_is_uncompressed_only() {
    only_uncompressed_shares_complete(&super::SecP256R1, 32);
}

#[test]
fn p384_key_share_is_uncompressed_only() {
    only_uncompressed_shares_complete(&super::SecP384R1, 48);
}

// Entropy failure must return a TLS error before an exchange is constructed.
#[test]
fn entropy_failure_does_not_panic_or_create_an_exchange() {
    assert!(matches!(
        super::X25519::start_with_rng(&mut FailedEntropy),
        Err(rustls::Error::General(_))
    ));
}
