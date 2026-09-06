use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::{Mutex, RwLock};

use monero::cryptonote::onetime_key::SubKeyChecker;
use monero::{Address, PrivateKey, PublicKey, Transaction, ViewPair};
use zeroize::Zeroize;

use super::{
    KeyCustody, KeyCustodyError, MatchedOutput, Network, SubaddressIndex, WalletHandle,
    WalletMaterial,
};

/// Ceiling on `major_range.len() * minor_range.len()` for one scan. Table
/// construction is one scalar multiplication per candidate index (see
/// [`SubKeyChecker::new`]), so an unbounded range isn't slow, it's a hang: a caller
/// that accidentally passed `0..u32::MAX` would wedge the scanner thread for the
/// rest of the process's life with no error and no progress, and every payment for
/// every tenant would stop being detected. Refusing loudly is the only safe
/// behaviour. 1M entries is already far past anything legitimate - the trait docs
/// ask callers to keep ranges tight around *active* orders - while still leaving
/// enormous headroom over the `0..next_minor_index` ranges the scanner actually
/// issues.
const MAX_SCAN_TABLE_ENTRIES: u64 = 1_000_000;

/// The output of [`SubKeyChecker::new`] worth keeping around: a table of every
/// derived spend key across some `(major_range, minor_range)`, built by doing one
/// scalar multiplication per candidate index. That construction cost is what makes
/// re-deriving it on every single mempool transaction wasteful - the table itself
/// has no lifetime tied to the view pair, so it can outlive the call that built it
/// and be reused as long as the caller keeps asking about the same range.
struct CachedTable {
    major_range: Range<u32>,
    minor_range: Range<u32>,
    table: HashMap<PublicKey, SubaddressIndex>,
}

struct WalletEntry {
    view_pair: ViewPair,
    /// Rebuilt only when a scan asks about a range that doesn't match what's
    /// cached. A tenant with a stable set of active orders - the common case,
    /// since the range only needs to widen when a new order is created and can
    /// shrink again as completed orders' indices are recycled - pays the
    /// scalar-multiplication cost once, not once per transaction scanned.
    cached_table: Mutex<Option<CachedTable>>,
    #[cfg(test)]
    rebuild_count: std::sync::atomic::AtomicU64,
}

impl WalletEntry {
    fn new(view_pair: ViewPair) -> Self {
        WalletEntry {
            view_pair,
            cached_table: Mutex::new(None),
            #[cfg(test)]
            rebuild_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Returns a lookup table covering exactly `major_range`/`minor_range`,
    /// rebuilding it only if the cached one (if any) covers a different range.
    fn table_for_range(
        &self,
        major_range: Range<u32>,
        minor_range: Range<u32>,
    ) -> HashMap<PublicKey, SubaddressIndex> {
        let mut cached = self.cached_table.lock().unwrap();
        let stale = match &*cached {
            Some(c) => c.major_range != major_range || c.minor_range != minor_range,
            None => true,
        };
        if stale {
            let checker =
                SubKeyChecker::new(&self.view_pair, major_range.clone(), minor_range.clone());
            #[cfg(test)]
            self.rebuild_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            *cached = Some(CachedTable {
                major_range,
                minor_range,
                table: checker.table,
            });
        }
        // SubKeyChecker owns its table by value (no lifetime tying it to the view
        // pair), so reusing the cache still costs one HashMap clone per call - but
        // that's a plain memory copy, nowhere near the cost of the scalar
        // multiplications it replaces.
        cached.as_ref().unwrap().table.clone()
    }
}

/// Best-effort scrub of the one *long-lived* copy of a tenant's view key: the one
/// this registry holds for the life of the process, and the one still sitting in
/// freed heap after a tenant offboards via `remove_wallet`.
///
/// Deliberately scoped, because `monero::PrivateKey` is `Copy` and so is
/// `ViewPair` - every `SubKeyChecker`/`KeyGenerator` call the crate makes takes its
/// own transient copy that nothing here can track or clear. Chasing those would
/// require the upstream crate to zeroize, not us. What this *does* buy is that
/// offboarding a tenant doesn't leave their view key readable in freed memory for
/// the remaining uptime of a long-running process, which is the difference between
/// "compromise the box now" and "compromise the box any time later".
///
/// The `compiler_fence` is the load-bearing part: without it this is a dead store
/// into a value about to be dropped, exactly the kind LLVM is free to delete. This
/// is `zeroize`'s own technique; `zeroize` itself can't be used directly because
/// `PrivateKey` exposes no mutable view of its scalar's bytes.
impl Drop for WalletEntry {
    fn drop(&mut self) {
        if let Ok(zero) = PrivateKey::from_slice(&[0u8; 32]) {
            self.view_pair.view = zero;
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Reference `KeyCustody` implementation: view pairs live in this process's ordinary
/// memory behind a lock, with no encryption at rest and no isolation from the host
/// process. See the module-level docs for why that's an acceptable default for a
/// self-hosted, single-tenant deployment and not for a multi-tenant hosted one.
#[derive(Default)]
pub struct PlainKeyCustody {
    wallets: RwLock<HashMap<WalletHandle, WalletEntry>>,
}

#[async_trait::async_trait]
impl KeyCustody for PlainKeyCustody {
    async fn register_wallet(
        &self,
        material: WalletMaterial,
    ) -> Result<WalletHandle, KeyCustodyError> {
        let view_pair = material.to_view_pair()?;
        let handle = WalletHandle::new();
        self.wallets
            .write()
            .unwrap()
            .insert(handle, WalletEntry::new(view_pair));
        Ok(handle)
    }

    async fn remove_wallet(&self, handle: WalletHandle) -> Result<(), KeyCustodyError> {
        self.wallets
            .write()
            .unwrap()
            .remove(&handle)
            .map(|_| ())
            .ok_or(KeyCustodyError::UnknownWallet)
    }

    async fn seal(&self, material: &WalletMaterial) -> Result<Vec<u8>, KeyCustodyError> {
        // "No encryption" is the entire point of this backend - sealing is a no-op
        // serialization, not a security boundary. A stolen database file is exactly
        // as sensitive as this wallet's key material, which is the expected
        // tradeoff for a self-hosted, single-tenant deployment.
        //
        // The returned `Vec` necessarily carries the view key (that's what the
        // caller persists), but the fixed-size staging buffer `to_raw_bytes` hands
        // back is a second copy with no reason to outlive this call - scrub it
        // rather than leaving it in the freed stack frame.
        let mut raw = material.to_raw_bytes();
        let sealed = raw.to_vec();
        raw.zeroize();
        Ok(sealed)
    }

    async fn unseal_and_register(&self, sealed: &[u8]) -> Result<WalletHandle, KeyCustodyError> {
        let material = WalletMaterial::from_raw_bytes(sealed)?;
        self.register_wallet(material).await
    }

    async fn derive_subaddress(
        &self,
        handle: WalletHandle,
        index: SubaddressIndex,
        network: Network,
    ) -> Result<Address, KeyCustodyError> {
        let wallets = self.wallets.read().unwrap();
        let entry = wallets.get(&handle).ok_or(KeyCustodyError::UnknownWallet)?;
        if index.is_zero() {
            // 0/0 is the account's *standard* address, not a subaddress - its keys
            // are the unmodified root pair `(v*G, S)`. `get_subaddress` returns
            // exactly those keys but still stamps the result with the *subaddress*
            // network byte, and that combination is not merely cosmetic: it is
            // unpayable. A sender seeing a subaddress-tagged address derives the tx
            // pubkey as `R = r*D` and the shared secret from `8*r*C`, while this
            // wallet looks for `8*v*R`. Those agree only when `C = v*D`, which holds
            // for every genuine subaddress and never for the root pair (there
            // `C = v*G` but `v*D = v*S`). So funds sent to that string would be
            // permanently undetectable by the very wallet it names - see
            // `admin::create_tenant`, which reports this address to the merchant as
            // their `primary_address`. Every non-zero index goes through the
            // subaddress path unchanged.
            return Ok(Address::standard(
                network,
                entry.view_pair.spend,
                PublicKey::from_private_key(&entry.view_pair.view),
            ));
        }
        Ok(monero::cryptonote::subaddress::get_subaddress(
            &entry.view_pair,
            index,
            Some(network),
        ))
    }

    async fn scan_tx_outputs(
        &self,
        handle: WalletHandle,
        tx: &Transaction,
        major_range: Range<u32>,
        minor_range: Range<u32>,
    ) -> Result<Vec<MatchedOutput>, KeyCustodyError> {
        let table_entries = (major_range.end.saturating_sub(major_range.start) as u64)
            .saturating_mul(minor_range.end.saturating_sub(minor_range.start) as u64);
        if table_entries > MAX_SCAN_TABLE_ENTRIES {
            return Err(KeyCustodyError::ScanFailed(format!(
                "requested subaddress range {}x{} exceeds the {MAX_SCAN_TABLE_ENTRIES}-entry scan limit",
                major_range.end.saturating_sub(major_range.start),
                minor_range.end.saturating_sub(minor_range.start),
            )));
        }

        let wallets = self.wallets.read().unwrap();
        let entry = wallets.get(&handle).ok_or(KeyCustodyError::UnknownWallet)?;

        let table = entry.table_for_range(major_range, minor_range);
        let checker = SubKeyChecker {
            table,
            keys: &entry.view_pair,
        };
        let owned = tx
            .check_outputs_with(&checker)
            .map_err(|e| KeyCustodyError::ScanFailed(e.to_string()))?;
        Ok(owned
            .into_iter()
            .map(|o| MatchedOutput {
                output_index: o.index(),
                subaddress_index: o.sub_index(),
                amount_piconero: o.amount().map(|a| a.as_pico()),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_custody::WalletMaterial;
    use monero::consensus::encode::deserialize;
    use monero::{Network, PrivateKey};
    use std::sync::atomic::Ordering;

    fn random_scalar_bytes(seed: u8) -> [u8; 32] {
        // Not cryptographically random - deterministic per-test fixture data only.
        let mut bytes = [seed; 32];
        bytes[31] &= 0x0f; // keep well under the group order so it's a valid scalar
        bytes
    }

    #[tokio::test]
    async fn register_then_derive_subaddress_roundtrip() {
        let view_key = PrivateKey::from_slice(&random_scalar_bytes(1)).unwrap();
        let spend_key = PrivateKey::from_slice(&random_scalar_bytes(2)).unwrap();
        let spend_pubkey = PublicKey::from_private_key(&spend_key);

        let custody = PlainKeyCustody::default();
        let handle = custody
            .register_wallet(WalletMaterial::new(
                view_key.to_bytes(),
                spend_pubkey.to_bytes(),
            ))
            .await
            .unwrap();

        let primary = custody
            .derive_subaddress(handle, SubaddressIndex::default(), Network::Mainnet)
            .await
            .unwrap();

        // 0/0 is the account's primary keyset, so the derived keys should equal the
        // root view pair directly - though `get_subaddress` still tags the address
        // as `AddressType::SubAddress` rather than `Standard` even at index zero,
        // which is a quirk of the underlying primitive, not something we need to
        // paper over here.
        assert_eq!(primary.public_spend, spend_pubkey);
        assert_eq!(primary.public_view, PublicKey::from_private_key(&view_key));

        custody.remove_wallet(handle).await.unwrap();
        let err = custody
            .derive_subaddress(handle, SubaddressIndex::default(), Network::Mainnet)
            .await
            .unwrap_err();
        assert!(matches!(err, KeyCustodyError::UnknownWallet));
    }

    #[tokio::test]
    async fn scan_tx_outputs_finds_output_paid_to_subaddress() {
        // Fixture transaction and key pair lifted byte-for-byte from monero-rs's own
        // `code_coverage_owned_tx_out` test in blockdata/transaction.rs, which is
        // known to contain one output paying subaddress 0/1 for this exact wallet -
        // it exercises the real RingCT amount-decryption path, not just key
        // matching. We only ever hand this boundary the *private view key* plus the
        // *public* spend key (derived here from the fixture's private spend key,
        // the same way a real caller would derive it from a tenant-submitted watch
        // key), matching the watch-only shape `KeyCustody` is built around.
        let raw_tx = hex::decode(include_str!("../../tests/fixtures/subaddress_tx.hex"))
            .expect("fixture is valid hex");
        let tx: Transaction = deserialize(&raw_tx).expect("fixture is a valid monero tx");

        let view_key = PrivateKey::from_slice(
            &hex::decode("bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07")
                .unwrap(),
        )
        .unwrap();
        let secret_spend = PrivateKey::from_slice(
            &hex::decode("e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907")
                .unwrap(),
        )
        .unwrap();
        let spend_pubkey = PublicKey::from_private_key(&secret_spend);

        let custody = PlainKeyCustody::default();
        let handle = custody
            .register_wallet(WalletMaterial::new(
                view_key.to_bytes(),
                spend_pubkey.to_bytes(),
            ))
            .await
            .unwrap();

        let matches = custody
            .scan_tx_outputs(handle, &tx, 0..2, 0..3)
            .await
            .unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].output_index, 1);
        assert_eq!(
            matches[0].subaddress_index,
            SubaddressIndex {
                major: 0,
                minor: 1
            }
        );
        assert!(matches[0].amount_piconero.unwrap() > 0);
    }

    #[tokio::test]
    async fn repeated_scans_over_same_range_reuse_the_cached_table() {
        let raw_tx = hex::decode(include_str!("../../tests/fixtures/subaddress_tx.hex")).unwrap();
        let tx: Transaction = deserialize(&raw_tx).unwrap();
        let view_key = PrivateKey::from_slice(
            &hex::decode("bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07")
                .unwrap(),
        )
        .unwrap();
        let secret_spend = PrivateKey::from_slice(
            &hex::decode("e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907")
                .unwrap(),
        )
        .unwrap();
        let spend_pubkey = PublicKey::from_private_key(&secret_spend);

        let custody = PlainKeyCustody::default();
        let handle = custody
            .register_wallet(WalletMaterial::new(
                view_key.to_bytes(),
                spend_pubkey.to_bytes(),
            ))
            .await
            .unwrap();

        // Three scans, same wallet, same range - as the chain scanner would issue
        // while polling the mempool for a tenant with a stable set of pending
        // orders. Only the first should pay the table-construction cost.
        for _ in 0..3 {
            custody
                .scan_tx_outputs(handle, &tx, 0..2, 0..3)
                .await
                .unwrap();
        }
        assert_eq!(
            rebuild_count(&custody, handle),
            1,
            "same range should rebuild the table once, not once per scan"
        );

        // A genuinely wider range (e.g. a new order just issued a fresh minor
        // index) must trigger exactly one more rebuild.
        custody
            .scan_tx_outputs(handle, &tx, 0..2, 0..4)
            .await
            .unwrap();
        assert_eq!(rebuild_count(&custody, handle), 2);
    }

    #[tokio::test]
    async fn seal_then_unseal_survives_a_simulated_restart() {
        let view_key = PrivateKey::from_slice(&random_scalar_bytes(3)).unwrap();
        let spend_key = PrivateKey::from_slice(&random_scalar_bytes(4)).unwrap();
        let spend_pubkey = PublicKey::from_private_key(&spend_key);
        let material = WalletMaterial::new(view_key.to_bytes(), spend_pubkey.to_bytes());

        // "Before restart": register, derive an address, seal what we'd persist.
        let custody_before = PlainKeyCustody::default();
        let handle_before = custody_before.register_wallet(material.clone()).await.unwrap();
        let address_before = custody_before
            .derive_subaddress(handle_before, SubaddressIndex { major: 0, minor: 7 }, Network::Mainnet)
            .await
            .unwrap();
        let sealed = custody_before.seal(&material).await.unwrap();

        // "After restart": a brand new backend instance, nothing in memory except
        // what came out of storage. The old handle is meaningless here - only the
        // sealed bytes and a fresh handle from unsealing them matter.
        let custody_after = PlainKeyCustody::default();
        let handle_after = custody_after.unseal_and_register(&sealed).await.unwrap();
        assert_ne!(handle_before, handle_after);

        let address_after = custody_after
            .derive_subaddress(handle_after, SubaddressIndex { major: 0, minor: 7 }, Network::Mainnet)
            .await
            .unwrap();
        assert_eq!(address_before, address_after);
    }

    #[tokio::test]
    async fn index_zero_derives_a_standard_address_not_an_unpayable_subaddress() {
        // Regression test for the worst shape of bug this boundary can produce: an
        // address the service hands out that no payment to it could ever be
        // detected at. `get_subaddress` at 0/0 returns the correct root keys under a
        // *subaddress* network byte, which makes a sender derive the shared secret
        // as `8*r*C` against `C = v*G` while this wallet looks for `8*v*r*D` against
        // `D = S` - they never agree, so the funds land somewhere this wallet cannot
        // see. `admin::create_tenant` reports exactly this address to a merchant as
        // their `primary_address`.
        let view_key = PrivateKey::from_slice(&random_scalar_bytes(5)).unwrap();
        let spend_key = PrivateKey::from_slice(&random_scalar_bytes(6)).unwrap();
        let spend_pubkey = PublicKey::from_private_key(&spend_key);

        let custody = PlainKeyCustody::default();
        let handle = custody
            .register_wallet(WalletMaterial::new(view_key.to_bytes(), spend_pubkey.to_bytes()))
            .await
            .unwrap();

        let primary = custody
            .derive_subaddress(handle, SubaddressIndex::default(), Network::Mainnet)
            .await
            .unwrap();
        assert_eq!(
            primary.addr_type,
            monero::AddressType::Standard,
            "0/0 must encode as a standard address; a subaddress-tagged root key pair is unpayable"
        );
        assert_eq!(primary, monero::Address::standard(
            Network::Mainnet,
            spend_pubkey,
            PublicKey::from_private_key(&view_key),
        ));
        // Mainnet standard addresses start with '4'; subaddresses start with '8'.
        // Asserting the rendered form too, since that string is what a merchant
        // actually copies out of the admin API.
        assert!(primary.to_string().starts_with('4'), "got {primary}");

        // Every non-zero index must still take the real subaddress path.
        let first_order_address = custody
            .derive_subaddress(handle, SubaddressIndex { major: 0, minor: 1 }, Network::Mainnet)
            .await
            .unwrap();
        assert_eq!(first_order_address.addr_type, monero::AddressType::SubAddress);
        assert_ne!(first_order_address.public_spend, spend_pubkey);
    }

    #[tokio::test]
    async fn an_index_at_the_top_of_the_u32_range_derives_without_overflowing() {
        // Subaddress derivation hashes the index rather than doing arithmetic on it,
        // so `u32::MAX` is not a special case - but nothing else proves that, and a
        // panic here would take down whichever request or scan tick hit it.
        let view_key = PrivateKey::from_slice(&random_scalar_bytes(7)).unwrap();
        let spend_key = PrivateKey::from_slice(&random_scalar_bytes(8)).unwrap();
        let custody = PlainKeyCustody::default();
        let handle = custody
            .register_wallet(WalletMaterial::new(
                view_key.to_bytes(),
                PublicKey::from_private_key(&spend_key).to_bytes(),
            ))
            .await
            .unwrap();

        let extreme = custody
            .derive_subaddress(
                handle,
                SubaddressIndex { major: u32::MAX, minor: u32::MAX },
                Network::Mainnet,
            )
            .await
            .unwrap();
        assert_eq!(extreme.addr_type, monero::AddressType::SubAddress);
        // Distinct from its neighbours - i.e. the index really is participating in
        // the derivation rather than saturating to something shared.
        let neighbour = custody
            .derive_subaddress(
                handle,
                SubaddressIndex { major: u32::MAX, minor: u32::MAX - 1 },
                Network::Mainnet,
            )
            .await
            .unwrap();
        assert_ne!(extreme, neighbour);
    }

    #[tokio::test]
    async fn an_absurdly_wide_scan_range_is_refused_rather_than_hanging_forever() {
        // Table construction is one scalar multiplication per candidate index, so a
        // range this size isn't slow, it never finishes - and it would take the
        // whole scanner loop (every tenant, every network) with it, silently.
        let raw_tx = hex::decode(include_str!("../../tests/fixtures/subaddress_tx.hex")).unwrap();
        let tx: Transaction = deserialize(&raw_tx).unwrap();
        let view_key = PrivateKey::from_slice(&random_scalar_bytes(9)).unwrap();
        let spend_key = PrivateKey::from_slice(&random_scalar_bytes(10)).unwrap();
        let custody = PlainKeyCustody::default();
        let handle = custody
            .register_wallet(WalletMaterial::new(
                view_key.to_bytes(),
                PublicKey::from_private_key(&spend_key).to_bytes(),
            ))
            .await
            .unwrap();

        let err = custody
            .scan_tx_outputs(handle, &tx, 0..1, 0..u32::MAX)
            .await
            .unwrap_err();
        assert!(matches!(err, KeyCustodyError::ScanFailed(_)), "got {err:?}");

        // A realistic range is of course still accepted.
        custody.scan_tx_outputs(handle, &tx, 0..1, 0..64).await.unwrap();
    }

    #[tokio::test]
    async fn removing_a_wallet_scrubs_its_view_key_rather_than_leaving_it_in_freed_memory() {
        // The registry holds the only long-lived copy of a tenant's view key.
        // Offboarding must not leave it readable for the remaining uptime of the
        // process; `WalletEntry`'s `Drop` is what guarantees that, and this pins the
        // observable half of it (that removal actually drops the entry, and that a
        // scrubbed entry can never answer a later scan).
        let view_key = PrivateKey::from_slice(&random_scalar_bytes(11)).unwrap();
        let spend_key = PrivateKey::from_slice(&random_scalar_bytes(12)).unwrap();
        let custody = PlainKeyCustody::default();
        let handle = custody
            .register_wallet(WalletMaterial::new(
                view_key.to_bytes(),
                PublicKey::from_private_key(&spend_key).to_bytes(),
            ))
            .await
            .unwrap();

        custody.remove_wallet(handle).await.unwrap();
        assert!(custody.wallets.read().unwrap().is_empty());
        assert!(matches!(
            custody.remove_wallet(handle).await.unwrap_err(),
            KeyCustodyError::UnknownWallet
        ));

        let raw_tx = hex::decode(include_str!("../../tests/fixtures/subaddress_tx.hex")).unwrap();
        let tx: Transaction = deserialize(&raw_tx).unwrap();
        assert!(matches!(
            custody.scan_tx_outputs(handle, &tx, 0..1, 0..2).await.unwrap_err(),
            KeyCustodyError::UnknownWallet
        ));
    }

    #[tokio::test]
    async fn registering_the_same_material_twice_yields_independent_handles_that_both_work() {
        // Reachable in production: `main::register_all_tenants` registers every
        // tenant at boot, and `http::resolve_wallet_handle` can register the same
        // tenant again if two requests race the cache. Both handles must derive
        // identical addresses, and removing one must not disturb the other - a
        // shared or recycled handle space would break exactly that.
        let view_key = PrivateKey::from_slice(&random_scalar_bytes(13)).unwrap();
        let spend_key = PrivateKey::from_slice(&random_scalar_bytes(14)).unwrap();
        let material =
            WalletMaterial::new(view_key.to_bytes(), PublicKey::from_private_key(&spend_key).to_bytes());

        let custody = PlainKeyCustody::default();
        let sealed = custody.seal(&material).await.unwrap();
        let first = custody.unseal_and_register(&sealed).await.unwrap();
        let second = custody.unseal_and_register(&sealed).await.unwrap();
        assert_ne!(first, second, "each registration must get its own handle");

        let index = SubaddressIndex { major: 0, minor: 3 };
        let from_first = custody.derive_subaddress(first, index, Network::Mainnet).await.unwrap();
        let from_second = custody.derive_subaddress(second, index, Network::Mainnet).await.unwrap();
        assert_eq!(from_first, from_second);

        custody.remove_wallet(first).await.unwrap();
        assert_eq!(
            custody.derive_subaddress(second, index, Network::Mainnet).await.unwrap(),
            from_second,
            "removing one registration must not invalidate an independent one"
        );
    }

    #[tokio::test]
    async fn seal_rejects_truncated_or_overlong_material_instead_of_silently_padding() {
        // `from_raw_bytes` is the only path back from at-rest bytes to a live key.
        // A short read that silently zero-padded (or a long one that silently
        // truncated) would register a wallet with the *wrong* view key - it would
        // scan cleanly and simply never match a real payment.
        for bad_len in [0usize, 31, 32, 63, 65, 128] {
            let custody = PlainKeyCustody::default();
            let err = custody.unseal_and_register(&vec![7u8; bad_len]).await.unwrap_err();
            assert!(
                matches!(err, KeyCustodyError::InvalidKeyMaterial(_)),
                "{bad_len} bytes should be rejected, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn seal_round_trips_every_byte_of_both_keys_including_high_bytes() {
        // Guards the `[..32]`/`[32..]` split in `to_raw_bytes`/`from_raw_bytes`
        // against an off-by-one that would swap or clip key bytes - the kind of
        // corruption that survives a restart and then silently sees no payments.
        let mut view_bytes = [0u8; 32];
        for (i, b) in view_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        view_bytes[31] &= 0x0f; // keep it a canonical scalar
        let spend_bytes = PublicKey::from_private_key(
            &PrivateKey::from_slice(&random_scalar_bytes(15)).unwrap(),
        )
        .to_bytes();

        let material = WalletMaterial::new(view_bytes, spend_bytes);
        let sealed = PlainKeyCustody::default().seal(&material).await.unwrap();
        assert_eq!(sealed.len(), 64);
        assert_eq!(&sealed[..32], &view_bytes[..]);
        assert_eq!(&sealed[32..], &spend_bytes[..]);

        let restored = WalletMaterial::from_raw_bytes(&sealed).unwrap();
        let original_pair = material.to_view_pair().unwrap();
        let restored_pair = restored.to_view_pair().unwrap();
        assert_eq!(original_pair.view.to_bytes(), restored_pair.view.to_bytes());
        assert_eq!(original_pair.spend, restored_pair.spend);
    }

    #[tokio::test]
    async fn concurrent_registrations_and_removals_never_cross_wires_between_wallets() {
        // Two tenants' wallets registered and scanned from many tasks at once: the
        // guarantee that matters is that a handle only ever resolves to *its own*
        // key material, never a neighbour's, no matter the interleaving. A
        // misattributed payment is the single worst outcome this module can produce.
        use std::sync::Arc;

        let custody = Arc::new(PlainKeyCustody::default());
        let mut expected = Vec::new();
        for seed in 20u8..24 {
            let view_key = PrivateKey::from_slice(&random_scalar_bytes(seed)).unwrap();
            let spend_key = PrivateKey::from_slice(&random_scalar_bytes(seed + 40)).unwrap();
            let spend_pubkey = PublicKey::from_private_key(&spend_key);
            let handle = custody
                .register_wallet(WalletMaterial::new(view_key.to_bytes(), spend_pubkey.to_bytes()))
                .await
                .unwrap();
            let index = SubaddressIndex { major: 0, minor: 1 };
            let address = custody.derive_subaddress(handle, index, Network::Mainnet).await.unwrap();
            expected.push((handle, address));
        }

        let mut tasks = Vec::new();
        for (handle, address) in expected.clone() {
            for _ in 0..8 {
                let custody = custody.clone();
                tasks.push(tokio::spawn(async move {
                    let index = SubaddressIndex { major: 0, minor: 1 };
                    assert_eq!(
                        custody.derive_subaddress(handle, index, Network::Mainnet).await.unwrap(),
                        address,
                        "a handle resolved to another wallet's key material"
                    );
                }));
            }
        }
        // Churn the map concurrently with those reads, so the reads are genuinely
        // racing writer acquisitions of the registry lock rather than a quiet map.
        for seed in 60u8..68 {
            let custody = custody.clone();
            tasks.push(tokio::spawn(async move {
                let view_key = PrivateKey::from_slice(&random_scalar_bytes(seed)).unwrap();
                let spend_key = PrivateKey::from_slice(&random_scalar_bytes(seed + 20)).unwrap();
                let handle = custody
                    .register_wallet(WalletMaterial::new(
                        view_key.to_bytes(),
                        PublicKey::from_private_key(&spend_key).to_bytes(),
                    ))
                    .await
                    .unwrap();
                custody.remove_wallet(handle).await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        // Every original wallet is still intact and still its own.
        for (handle, address) in expected {
            let index = SubaddressIndex { major: 0, minor: 1 };
            assert_eq!(
                custody.derive_subaddress(handle, index, Network::Mainnet).await.unwrap(),
                address
            );
        }
    }

    fn rebuild_count(custody: &PlainKeyCustody, handle: WalletHandle) -> u64 {
        custody
            .wallets
            .read()
            .unwrap()
            .get(&handle)
            .unwrap()
            .rebuild_count
            .load(Ordering::Relaxed)
    }
}
