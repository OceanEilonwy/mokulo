//! Operator commands that act directly on the local SQLite database rather than
//! through the HTTP admin API - `--rotate-secret`, `--show-tenant`, `--snippet`.
//! Deliberately need no network call and no existing secret token: having
//! filesystem access to the box this database lives on already implies the level
//! of trust the HTTP admin API's bearer-token check exists to establish remotely,
//! consistent with the self-hosted, single-operator deployment model this whole
//! CLI targets (`docs/DESIGN.md` §4). This is also the answer to "I lost my admin
//! secret": there is no way to recover it (only its hash is ever stored - see
//! `Store::create_tenant`), only to mint a new one, which is exactly what
//! `rotate_secret` does.

use crate::store::{Store, Tenant};

#[derive(Debug, thiserror::Error)]
pub enum LocalAdminError {
    #[error("no tenant is configured yet - run `moneropay-core --init`, then start the server once with `moneropay-core` to create it")]
    NoTenant,
    #[error("more than one tenant is configured ({0}) - name which one with --pk <pk_...>")]
    AmbiguousTenant(String),
    #[error("no tenant found with public key {0:?}")]
    UnknownTenant(String),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}

/// Resolves which tenant a local-admin command should act on: the one named by
/// `pk` if given, or the sole active tenant if there's exactly one, erroring
/// otherwise rather than guessing - a self-hosted deployment (this feature's whole
/// target) has exactly one, so the common case never needs `--pk` at all.
fn resolve_tenant(store: &Store, pk: Option<&str>) -> Result<Tenant, LocalAdminError> {
    if let Some(pk) = pk {
        return store.find_tenant_by_public_key(pk)?.ok_or_else(|| LocalAdminError::UnknownTenant(pk.to_string()));
    }
    let mut tenants = store.list_active_tenants()?;
    match tenants.len() {
        0 => Err(LocalAdminError::NoTenant),
        1 => Ok(tenants.remove(0)),
        _ => {
            let pks: Vec<String> = tenants.iter().map(|t| t.public_key.clone()).collect();
            Err(LocalAdminError::AmbiguousTenant(pks.join(", ")))
        }
    }
}

/// Mints a fresh admin secret for a tenant, invalidating whatever the old one
/// was. Returns `(public_key, new_secret)`. The only way back from a lost
/// secret - see the module doc.
pub fn rotate_secret(store: &Store, pk: Option<&str>) -> Result<(String, String), LocalAdminError> {
    let tenant = resolve_tenant(store, pk)?;
    let new_secret = store.rotate_tenant_secret(&tenant.id)?;
    Ok((tenant.public_key, new_secret))
}

/// A snapshot of a tenant's non-secret settings, for `--show-tenant`. Everything
/// here is either public by design (`public_key`) or was chosen by the operator
/// and is safe to print back to them (`allowed_origins`, thresholds). Deliberately
/// excludes `sealed_key_material`: even though `PlainKeyCustody` seals to plain
/// bytes today (see its own doc comment), a future sealed backend's raw bytes are
/// not something a "show me my settings" command should ever surface.
#[derive(Debug, PartialEq)]
pub struct TenantSummary {
    pub public_key: String,
    pub network: String,
    pub primary_address: String,
    pub allowed_origins: Vec<String>,
    pub confirmations_required: u64,
    pub zero_conf_max_piconero: Option<u64>,
    pub order_expiry_seconds: i64,
}

pub fn show_tenant(store: &Store, pk: Option<&str>) -> Result<TenantSummary, LocalAdminError> {
    let tenant = resolve_tenant(store, pk)?;
    Ok(TenantSummary {
        public_key: tenant.public_key,
        network: tenant.network,
        primary_address: tenant.primary_address,
        allowed_origins: tenant.allowed_origins,
        confirmations_required: tenant.confirmations_required,
        zero_conf_max_piconero: tenant.zero_conf_max_piconero,
        order_expiry_seconds: tenant.order_expiry_seconds,
    })
}

/// The embeddable-widget integration snippet (`docs/DESIGN.md` §14's documented
/// client API), pre-filled with a real tenant's public key and the endpoint URL
/// customers will actually reach this server at - the thing a self-hoster
/// currently has to reconstruct by hand from the design doc or `e2e/demo-shop/`.
///
/// `endpoint` is taken as given, not derived from `server.bind` - a bind address
/// like `0.0.0.0:8443` says nothing about the externally-reachable URL once a
/// reverse proxy, a domain name, or port forwarding sits in front of it, so
/// guessing would produce a plausible-looking snippet that's wrong exactly when
/// it matters. The caller is expected to ask.
pub fn snippet(store: &Store, pk: Option<&str>, endpoint: &str) -> Result<String, LocalAdminError> {
    let tenant = resolve_tenant(store, pk)?;
    let endpoint = endpoint.trim_end_matches('/');
    Ok(format!(
        r#"<!-- MoneroPay checkout widget - paste this where you want a "Pay with Monero" button. -->
<button id="moneropay-buy-button">Pay with Monero</button>
<div id="moneropay-checkout"></div>
<script>
(function () {{
  var script = document.createElement('script');
  script.src = {endpoint:?} + '/static/moneropay-client.js';
  script.onload = function () {{
    document.getElementById('moneropay-buy-button').addEventListener('click', function () {{
      MoneroPay.createOrder({{
        endpoint: {endpoint:?},
        publicKey: {pk:?},
        merchantOrderId: 'order-' + Date.now(),   // <- replace with your own order id
        fiatAmount: 9.99,                         // <- replace with the real amount
        fiatCurrency: 'USD',                      // <- must have an [exchange_rate.rates] entry
        description: 'What they are paying for',  // <- optional, shown on the checkout page
      }}).then(function (order) {{
        MoneroPay.mount('#moneropay-checkout', order, {{
          onPaid: function () {{
            // e.g. window.location = '/thank-you.html';
          }},
        }});
      }}).catch(function (err) {{
        alert('Could not start checkout: ' + err.message);
      }});
    }});
  }};
  document.head.appendChild(script);
}})();
</script>
<!-- If order creation fails with a CORS error in the browser console, double-check
     `allowed_origins` in your moneropay config exactly matches this page's origin
     (scheme + host + port, no trailing slash). -->
"#,
        endpoint = endpoint,
        pk = tenant.public_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_custody::{KeyCustody, PlainKeyCustody, WalletMaterial};
    use crate::store::NewTenant;

    async fn store_with_tenant(allowed_origins: Vec<String>) -> (Store, Tenant, String) {
        let store = Store::open_in_memory().unwrap();
        let key_custody = PlainKeyCustody::default();
        let material = WalletMaterial::new([7u8; 32], [8u8; 32]);
        let sealed = key_custody.seal(&material).await.unwrap();
        let created = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".to_string(),
                    sealed_key_material: sealed,
                    primary_address: "4abc".to_string(),
                    network: "mainnet".to_string(),
                    allowed_origins,
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let pk = created.tenant.public_key.clone();
        (store, created.tenant, pk)
    }

    #[tokio::test]
    async fn resolve_tenant_with_no_pk_and_exactly_one_tenant_finds_it() {
        let (store, tenant, _) = store_with_tenant(vec![]).await;
        let resolved = resolve_tenant(&store, None).unwrap();
        assert_eq!(resolved.id, tenant.id);
    }

    #[tokio::test]
    async fn resolve_tenant_with_no_tenants_at_all_is_a_clear_error() {
        let store = Store::open_in_memory().unwrap();
        assert!(matches!(resolve_tenant(&store, None), Err(LocalAdminError::NoTenant)));
    }

    #[tokio::test]
    async fn resolve_tenant_with_more_than_one_requires_naming_which_pk() {
        let key_custody = PlainKeyCustody::default();
        let store = Store::open_in_memory().unwrap();
        for seed in [1u8, 2u8] {
            let material = WalletMaterial::new([seed; 32], [seed.wrapping_add(1); 32]);
            let sealed = key_custody.seal(&material).await.unwrap();
            store
                .create_tenant(
                    NewTenant {
                        key_custody_backend: "plain".to_string(),
                        sealed_key_material: sealed,
                        primary_address: "4abc".to_string(),
                        network: "mainnet".to_string(),
                        allowed_origins: vec![],
                        confirmations_required: None,
                        zero_conf_max_piconero: None,
                        order_expiry_seconds: None,
                    },
                    1_700_000_000,
                )
                .unwrap();
        }
        let err = resolve_tenant(&store, None).unwrap_err();
        assert!(matches!(err, LocalAdminError::AmbiguousTenant(_)), "got {err}");

        // But naming one directly still works with two present.
        let (_, tenant, pk) = store_with_tenant(vec![]).await;
        let _ = tenant;
        let store2 = Store::open_in_memory().unwrap();
        let material = WalletMaterial::new([9u8; 32], [10u8; 32]);
        let sealed = key_custody.seal(&material).await.unwrap();
        let created = store2
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".to_string(),
                    sealed_key_material: sealed,
                    primary_address: "4abc".to_string(),
                    network: "mainnet".to_string(),
                    allowed_origins: vec![],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let resolved = resolve_tenant(&store2, Some(&created.tenant.public_key)).unwrap();
        assert_eq!(resolved.id, created.tenant.id);
        let _ = pk;
    }

    #[tokio::test]
    async fn resolve_tenant_with_an_unknown_pk_is_a_clear_error() {
        let (store, _, _) = store_with_tenant(vec![]).await;
        let err = resolve_tenant(&store, Some("pk_doesnotexist")).unwrap_err();
        assert!(matches!(err, LocalAdminError::UnknownTenant(pk) if pk == "pk_doesnotexist"));
    }

    #[tokio::test]
    async fn rotate_secret_invalidates_the_old_one_and_returns_a_usable_new_one() {
        let store = Store::open_in_memory().unwrap();
        let key_custody = PlainKeyCustody::default();
        let material = WalletMaterial::new([1u8; 32], [2u8; 32]);
        let sealed = key_custody.seal(&material).await.unwrap();
        let created = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".to_string(),
                    sealed_key_material: sealed,
                    primary_address: "4abc".to_string(),
                    network: "mainnet".to_string(),
                    allowed_origins: vec![],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1_700_000_000,
            )
            .unwrap();

        let (pk, new_secret) = rotate_secret(&store, None).unwrap();
        assert_eq!(pk, created.tenant.public_key);
        assert_ne!(new_secret, created.secret_token);
        assert!(store.find_tenant_by_secret_token(&created.secret_token).unwrap().is_none(), "old secret must stop working");
        assert!(store.find_tenant_by_secret_token(&new_secret).unwrap().is_some(), "new secret must work");
    }

    #[tokio::test]
    async fn show_tenant_reports_the_real_settings_and_never_the_key_material() {
        let (store, _, pk) = store_with_tenant(vec!["https://merchant.example".to_string()]).await;
        let summary = show_tenant(&store, None).unwrap();
        assert_eq!(summary.public_key, pk);
        assert_eq!(summary.network, "mainnet");
        assert_eq!(summary.allowed_origins, vec!["https://merchant.example".to_string()]);
    }

    #[tokio::test]
    async fn snippet_embeds_the_real_pk_and_endpoint_and_strips_a_trailing_slash() {
        let (store, _, pk) = store_with_tenant(vec![]).await;
        let html = snippet(&store, None, "https://pay.example.com/").unwrap();
        assert!(html.contains(&format!("{pk:?}")), "missing the real pk: {html}");
        assert!(html.contains("\"https://pay.example.com\""), "trailing slash should be stripped: {html}");
        assert!(!html.contains("https://pay.example.com/'"), "must not keep the trailing slash: {html}");
        assert!(html.contains("MoneroPay.createOrder"));
        assert!(html.contains("MoneroPay.mount"));
        assert!(html.contains("moneropay-client.js"));
    }

    #[tokio::test]
    async fn every_local_admin_command_gives_the_same_actionable_error_when_nothing_is_configured_yet() {
        let store = Store::open_in_memory().unwrap();
        for err in [
            rotate_secret(&store, None).unwrap_err(),
            show_tenant(&store, None).unwrap_err(),
            snippet(&store, None, "https://example.com").unwrap_err(),
        ] {
            assert!(matches!(err, LocalAdminError::NoTenant), "got {err}");
            assert!(err.to_string().contains("--init"), "should point at the fix: {err}");
        }
    }
}
