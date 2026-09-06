//! Webhook delivery signing and SSRF validation. See `docs/DESIGN.md` §11.
//!
//! The HTTP delivery worker itself (retry/backoff against a real `reqwest` client)
//! is not implemented in this pass - these are the two pieces of logic worth getting
//! right and testing in isolation first: how a delivery is authenticated, and how a
//! merchant-supplied URL is checked before this server ever makes a request to it.

use std::net::IpAddr;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes the `X-MoneroPay-Signature` header value for a webhook delivery body.
/// Hex-encoded HMAC-SHA256 of the raw payload bytes, keyed by the webhook's
/// `signing_secret`. Documented with a fixed test vector so a merchant implementing
/// verification can cross-check their own computation against the same input.
pub fn sign_payload(secret: &str, payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Verifies a presented `X-MoneroPay-Signature` against a freshly-computed one.
///
/// The comparison is constant-time, which is the entire reason this goes through
/// `Mac::verify_slice` (backed by `subtle`'s `ct_eq`) rather than the obvious
/// `sign_payload(..) == presented`. `String`/`&str` equality short-circuits at the
/// first differing byte, so the time it takes to reject a forgery is a direct
/// readout of how many leading bytes were right - the standard byte-at-a-time
/// signature-forgery oracle, and a real one here because this is the helper a
/// merchant integrating against this service calls on *their* HTTP endpoint, with an
/// attacker choosing both the payload and the candidate signature and able to
/// re-measure as many times as they like.
///
/// The signature is decoded from hex and compared as raw tag bytes rather than as
/// hex text: comparing the hex *rendering* would work too, but only by accident of
/// both sides using lowercase. Anything that isn't exactly 32 bytes of valid hex is
/// rejected outright, before any comparison happens - the length/encoding of a
/// presented signature is attacker-supplied public data and reveals nothing.
pub fn verify_signature(secret: &str, payload: &[u8], presented_signature_hex: &str) -> bool {
    let Ok(presented) = hex::decode(presented_signature_hex) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.verify_slice(&presented).is_ok()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebhookUrlError {
    #[error("only http/https URLs are allowed")]
    UnsupportedScheme,
    #[error("URL has no host")]
    NoHost,
    #[error("URL resolves to a private, loopback, or link-local address")]
    PrivateAddress,
    #[error("URL could not be parsed: {0}")]
    Unparseable(String),
}

/// Checks a webhook URL isn't pointed at loopback/private/link-local address space,
/// given a resolved IP for its host. This function deliberately takes the resolved
/// IP as a parameter rather than doing DNS resolution itself: the real delivery
/// worker must re-run this check *at connect time* against whatever the resolver
/// currently returns (DNS can change between webhook registration and delivery), not
/// just once at registration - see `docs/DESIGN.md` §11. This split also makes the
/// check trivially testable without a real resolver.
pub fn validate_webhook_url(url: &str, resolved_ip: IpAddr) -> Result<(), WebhookUrlError> {
    let parsed = url::Url::parse(url).map_err(|e| WebhookUrlError::Unparseable(e.to_string()))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(WebhookUrlError::UnsupportedScheme);
    }
    if parsed.host().is_none() {
        return Err(WebhookUrlError::NoHost);
    }
    if is_disallowed_address(resolved_ip) {
        return Err(WebhookUrlError::PrivateAddress);
    }
    Ok(())
}

pub fn is_disallowed_address(ip: IpAddr) -> bool {
    // An IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) is a completely ordinary way
    // to reach 127.0.0.1, but none of the `Ipv6Addr` predicates below recognize it -
    // classified as v6 it looks like an unremarkable global address. Unmap first so
    // exactly one set of rules applies to any given destination, regardless of which
    // family a resolver happened to express it in.
    //
    // `to_ipv4`, not `to_ipv4_mapped`: the deprecated IPv4-*compatible* form
    // (`::127.0.0.1`, i.e. `::/96` without the `ffff` marker) embeds a v4 address just
    // as literally, and unmapping only the `::ffff:` form left it classified as an
    // ordinary global v6 address - one character away from the same bypass, in the
    // fix meant to close it. The two v6 addresses this additionally folds into v4,
    // `::` and `::1`, land on 0.0.0.0 and 0.0.0.1, both of which the v4 arm rejects.
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                // "This network" (0.0.0.0/8), not merely the single unspecified
                // address `is_unspecified` covers. A destination of 0.0.0.0 is
                // routed to the local host by every mainstream stack - a
                // well-travelled way to say "localhost" without writing 127 - and
                // the rest of the /8 is unrouteable junk with no legitimate use as
                // a webhook target either way.
                || o[0] == 0
                // Carrier-grade NAT (100.64.0.0/10). Not "private" by
                // `Ipv4Addr::is_private`'s RFC 1918 definition, but just as much a
                // neighbouring-host address space on any deployment behind a
                // CGNAT'd connection - which a self-hosted router install very
                // plausibly is.
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
                // Cloud metadata endpoints (AWS/GCP/Azure all use 169.254.169.254,
                // already covered by is_link_local, but called out explicitly since
                // it's the single most consequential SSRF target for a hosted
                // deployment).
                || o == [169, 254, 169, 254]
                // Benchmarking (198.18.0.0/15, RFC 2544). Routed into real lab
                // networks often enough that treating it as public is a needless
                // gamble.
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                // Multicast (224.0.0.0/4) and the reserved class E space
                // (240.0.0.0/4, which `is_broadcast` only covers the last address
                // of). Neither is a meaningful destination for an outbound TCP
                // connection, so anything asking for one is probing, not
                // integrating.
                || o[0] >= 224
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00 // unique local (fc00::/7)
                || (first & 0xffc0) == 0xfe80 // link-local (fe80::/10) - the v6 counterpart of 169.254.0.0/16
                || (first & 0xff00) == 0xff00 // multicast (ff00::/8) - the v6 counterpart of 224.0.0.0/4
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn signature_matches_a_fixed_test_vector() {
        // Documented in merchant-facing docs so implementers can cross-check their
        // own HMAC computation against this exact input/output pair. The expected
        // hex below is this implementation's real output for this input (verified
        // independently against a standalone HMAC-SHA256 computation, not just
        // round-tripped through this same function) - a future change to the
        // signing scheme must change this test deliberately, not accidentally.
        let secret = "whsec_test_vector_secret";
        let payload = br#"{"event":"order.paid","payment_id":"pay_test123"}"#;
        let signature = sign_payload(secret, payload);
        // Cross-checked independently via Python's stdlib: hmac.new(secret.encode(),
        // payload, hashlib.sha256).hexdigest() with the exact secret/payload above.
        assert_eq!(signature, "ef04ee135feb4cf09569865b91e9bff4c323df1a88fbecc69da6da2d2ab4e84c");
        assert!(verify_signature(secret, payload, &signature));
    }

    #[test]
    fn signature_is_sensitive_to_the_secret_and_the_payload() {
        let payload = b"{\"event\":\"order.paid\"}";
        let sig_a = sign_payload("secret_a", payload);
        let sig_b = sign_payload("secret_b", payload);
        assert_ne!(sig_a, sig_b);

        let sig_diff_payload = sign_payload("secret_a", b"{\"event\":\"order.partial\"}");
        assert_ne!(sig_a, sig_diff_payload);
    }

    #[test]
    fn verify_rejects_a_tampered_payload() {
        let secret = "whsec_abc";
        let payload = b"original";
        let signature = sign_payload(secret, payload);
        assert!(!verify_signature(secret, b"tampered", &signature));
    }

    #[test]
    fn verify_compares_the_decoded_tag_in_constant_time_and_refuses_every_near_miss() {
        // The vulnerability this pins closed: `sign_payload(..) == presented` is a
        // `str` comparison, which stops at the first differing byte. That turns
        // rejection latency into a readout of how many leading bytes an attacker has
        // already guessed - the textbook byte-at-a-time forgery oracle, and a live
        // one here because this is the function a merchant runs on their own public
        // webhook endpoint against an attacker-chosen payload and signature.
        //
        // Timing itself isn't assertable in a unit test without flakiness, so what's
        // pinned here is the observable half: the switch to `Mac::verify_slice` must
        // not have loosened *what* verifies. Every one-byte-off neighbour of a valid
        // signature, every truncation, and every non-hex string must still be
        // rejected, and the genuine signature must still be accepted.
        let secret = "whsec_abc";
        let payload = b"{\"event\":\"order.paid\"}";
        let good = sign_payload(secret, payload);
        assert!(verify_signature(secret, payload, &good));

        // A signature sharing every byte but the last is exactly the input an
        // early-exit comparison would take longest to reject.
        let mut almost = good.clone();
        let last = almost.pop().unwrap();
        almost.push(if last == '0' { '1' } else { '0' });
        assert!(!verify_signature(secret, payload, &almost));

        // ...and one differing only in the *first* byte, the input it would reject
        // fastest. Both must be equally, unconditionally refused.
        let mut first_off = good.clone();
        let head = first_off.remove(0);
        first_off.insert(0, if head == '0' { '1' } else { '0' });
        assert!(!verify_signature(secret, payload, &first_off));

        for bad in [
            "",                        // empty
            &good[..2],                // a correct prefix, far too short
            &good[..good.len() - 2],   // a correct prefix one byte short of the tag
            &format!("{good}00"),      // correct tag with trailing junk
            "not hex at all",          // undecodable
            &good.to_uppercase(),      // valid hex, wrong case
        ] {
            let expected = bad == good.to_uppercase();
            assert_eq!(
                verify_signature(secret, payload, bad),
                expected,
                "{bad:?} verified as {}, expected {expected}",
                !expected
            );
        }
    }

    #[test]
    fn public_https_url_with_a_public_ip_is_allowed() {
        assert!(validate_webhook_url("https://merchant.example/hook", IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))).is_ok());
    }

    #[test]
    fn loopback_resolved_address_is_rejected() {
        let err = validate_webhook_url("http://looks-public.example/hook", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .unwrap_err();
        assert_eq!(err, WebhookUrlError::PrivateAddress);
    }

    #[test]
    fn private_lan_resolved_address_is_rejected() {
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(172, 16, 0, 1),
        ] {
            let err = validate_webhook_url("http://example.test/hook", IpAddr::V4(ip)).unwrap_err();
            assert_eq!(err, WebhookUrlError::PrivateAddress);
        }
    }

    #[test]
    fn cloud_metadata_address_is_rejected() {
        let err =
            validate_webhook_url("http://example.test/hook", IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))).unwrap_err();
        assert_eq!(err, WebhookUrlError::PrivateAddress);
    }

    #[test]
    fn ipv4_mapped_ipv6_loopback_is_rejected() {
        // `::ffff:127.0.0.1` reaches 127.0.0.1 exactly like the plain v4 literal
        // does, but none of the `Ipv6Addr` predicates recognize it - classified as a
        // v6 address it looks entirely global, so this was a one-character bypass of
        // every check in this function. Unmapping before classifying is what makes
        // the rules independent of which family the resolver happened to answer in.
        for mapped in [
            "::ffff:127.0.0.1",   // loopback
            "::ffff:10.0.0.1",    // RFC 1918
            "::ffff:169.254.169.254", // cloud metadata
        ] {
            let err = validate_webhook_url("http://looks-public.example/hook", mapped.parse().unwrap()).unwrap_err();
            assert_eq!(err, WebhookUrlError::PrivateAddress, "{mapped} must be rejected");
        }
    }

    #[test]
    fn ipv6_link_local_is_rejected() {
        // fe80::/10 - the v6 counterpart of 169.254.0.0/16, and the same
        // neighbouring-host reachability concern.
        for ip in ["fe80::1", "febf:ffff::1"] {
            let err = validate_webhook_url("http://example.test/hook", ip.parse().unwrap()).unwrap_err();
            assert_eq!(err, WebhookUrlError::PrivateAddress, "{ip} must be rejected");
        }
        // The neighbouring prefix is genuinely global and must still be allowed -
        // this is a /10, not a /16.
        assert!(validate_webhook_url("http://example.test/hook", "fec0::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn cgnat_shared_address_space_is_rejected() {
        // 100.64.0.0/10. Not "private" by RFC 1918's definition (so
        // `Ipv4Addr::is_private` says nothing about it) but just as much a
        // neighbouring-host range on any deployment behind a carrier-grade NAT,
        // which a self-hosted router install plausibly is.
        for ip in [Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 127, 255, 254)] {
            let err = validate_webhook_url("http://example.test/hook", IpAddr::V4(ip)).unwrap_err();
            assert_eq!(err, WebhookUrlError::PrivateAddress, "{ip} must be rejected");
        }
        // Immediately either side of the /10 is ordinary public space.
        for ip in [Ipv4Addr::new(100, 63, 255, 255), Ipv4Addr::new(100, 128, 0, 1)] {
            assert!(
                validate_webhook_url("http://example.test/hook", IpAddr::V4(ip)).is_ok(),
                "{ip} is outside 100.64.0.0/10 and must still be allowed"
            );
        }
    }

    #[test]
    fn the_whole_zero_network_is_rejected_not_just_the_unspecified_address() {
        // `0.0.0.0` is a well-travelled way of writing "localhost" without writing
        // 127 - every mainstream stack routes a connection to it at the local host -
        // and `Ipv4Addr::is_unspecified` covers only that single address, leaving the
        // rest of 0.0.0.0/8 classified as ordinary public space.
        for ip in [Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 1), Ipv4Addr::new(0, 255, 255, 254)] {
            let err = validate_webhook_url("http://looks-public.example/hook", IpAddr::V4(ip)).unwrap_err();
            assert_eq!(err, WebhookUrlError::PrivateAddress, "{ip} must be rejected");
        }
        // 1.0.0.0 is the first address outside the /8 and is genuinely routable.
        assert!(validate_webhook_url("http://example.test/hook", IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))).is_ok());
    }

    #[test]
    fn ipv4_compatible_ipv6_is_unmapped_exactly_like_the_ipv4_mapped_form() {
        // `::127.0.0.1` (the deprecated IPv4-*compatible* form, `::/96` with no
        // `ffff` marker) embeds a v4 address just as literally as `::ffff:127.0.0.1`
        // does, but `Ipv6Addr::to_ipv4_mapped` returns `None` for it - so unmapping
        // only the `ffff` form left this one classified as an unremarkable global v6
        // address, one character away from the same bypass the unmapping exists to
        // close.
        for compat in ["::127.0.0.1", "::10.0.0.1", "::169.254.169.254", "::0.0.0.1"] {
            let err = validate_webhook_url("http://looks-public.example/hook", compat.parse().unwrap()).unwrap_err();
            assert_eq!(err, WebhookUrlError::PrivateAddress, "{compat} must be rejected");
        }
    }

    #[test]
    fn multicast_and_reserved_ranges_are_rejected_in_both_families() {
        // Nothing legitimate ever registers a webhook here; anything that does is
        // probing the classifier rather than integrating with it.
        for ip in [
            "224.0.0.1",        // v4 multicast, 224.0.0.0/4
            "239.255.255.250",  // SSDP, the same /4
            "240.0.0.1",        // reserved class E, 240.0.0.0/4
            "255.255.255.255",  // broadcast
            "198.18.0.1",       // benchmarking, 198.18.0.0/15
            "198.19.255.255",   // ...and its far end
            "ff02::1",          // v6 multicast, ff00::/8
        ] {
            let err = validate_webhook_url("http://example.test/hook", ip.parse().unwrap()).unwrap_err();
            assert_eq!(err, WebhookUrlError::PrivateAddress, "{ip} must be rejected");
        }
        // Immediately either side of 198.18.0.0/15 is ordinary public space.
        for ip in ["198.17.255.255", "198.20.0.1", "223.255.255.255"] {
            assert!(
                validate_webhook_url("http://example.test/hook", ip.parse().unwrap()).is_ok(),
                "{ip} is outside every blocked range and must still be allowed"
            );
        }
    }

    #[test]
    fn non_http_scheme_is_rejected_even_with_a_public_ip() {
        let err = validate_webhook_url("file:///etc/passwd", IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))).unwrap_err();
        assert_eq!(err, WebhookUrlError::UnsupportedScheme);
    }
}
