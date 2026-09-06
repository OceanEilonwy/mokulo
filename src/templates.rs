//! The payment page templating engine (`docs/DESIGN.md` §14): a folder of editable
//! HTML files a merchant can customize, loaded at runtime - not compiled in - so
//! editing a template never requires rebuilding the binary. Falls back to an
//! embedded default template when no custom directory is configured or a file is
//! missing from it, so a self-hoster who never touches templates still gets a
//! working checkout page.

use std::path::Path;

use handlebars::{Context, Handlebars, Helper, HelperResult, Output, RenderContext, RenderErrorReason};
use serde::Serialize;

const DEFAULT_CHECKOUT_TEMPLATE: &str = include_str!("../templates/default/checkout.html.hbs");

/// `{{{json some_value}}}` inside a `<script>` block - safely embeds a template
/// value as a JS literal (proper string quoting/escaping) rather than the raw
/// HTML-unescaped text `{{{...}}}` alone would produce, which breaks (or,
/// for attacker-controlled fields, injects into) the script.
fn json_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h
        .param(0)
        .ok_or_else(|| RenderErrorReason::ParamNotFoundForIndex("json", 0))?;
    let json = serde_json::to_string(param.value())
        .map_err(|e| RenderErrorReason::NestedError(Box::new(e)))?;
    out.write(&escape_for_script_element(&json))?;
    Ok(())
}

/// Makes `serde_json`'s output safe to paste *literally between `<script>` tags*,
/// which is not the same thing as valid JSON and is the whole reason this helper
/// exists.
///
/// `serde_json::to_string("</script>")` produces `"</script>"` - correctly escaped
/// JSON, and still fatal here, because an HTML parser ends a `<script>` element at
/// the first `</script` it sees regardless of JS string quoting. Everything after it
/// is reparsed as markup. On this particular page that means a customer-supplied
/// `description` or `merchant_order_id` (both free-form strings accepted by the
/// public order-creation API) could rewrite the displayed Monero address, which
/// makes this a payment-redirection bug rather than a generic XSS.
///
/// `<`, `>` and `&` can only ever occur inside a JSON *string literal* - JSON's own
/// structural characters are `{}[]:,` plus digits and the bare `true`/`false`/`null`
/// words - so replacing them unconditionally cannot corrupt the surrounding
/// structure. `\uXXXX` is a valid escape in both JSON and JS, so the value parses
/// back identically. U+2028/U+2029 get the same treatment: they are legal in JSON
/// strings but are line terminators to older JS parsers, which would truncate the
/// statement.
fn escape_for_script_element(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("failed to read template file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to register template: {0}")]
    Register(#[from] handlebars::TemplateError),
    #[error("failed to render template: {0}")]
    Render(#[from] handlebars::RenderError),
}

pub struct TemplateEngine {
    handlebars: Handlebars<'static>,
}

/// One payment for the amount-breakdown table - an order can have more than one
/// contributing transaction (docs/DESIGN.md §7.6's multi-payment handling).
#[derive(Debug, Serialize)]
pub struct PaymentViewModel {
    pub txid_short: String,
    pub amount_xmr: String,
    pub confirmations: u64,
    pub is_zero_conf: bool,
}

#[derive(Debug, Serialize)]
pub struct CheckoutViewModel {
    pub payment_id: String,
    pub status: String,
    pub status_label: String,
    pub status_class: String,
    pub address: String,
    pub qr_code_svg: String,
    pub xmr_amount: String,
    pub amount_received_xmr: String,
    pub fiat_amount: String,
    pub fiat_currency: String,
    pub confirmations: u64,
    pub confirmations_required: u64,
    pub is_terminal: bool,
    pub double_spend_detected_at: Option<i64>,
    pub expires_at: i64,
    pub merchant_order_id: Option<String>,
    pub description: Option<String>,
    pub payments: Vec<PaymentViewModel>,
}

impl TemplateEngine {
    /// `custom_dir`, if given, is checked first for each named template; any file
    /// missing there falls back to the embedded default rather than erroring - a
    /// merchant customizing the checkout page doesn't need to also carry forward
    /// files they never wanted to change.
    pub fn new(custom_dir: Option<&str>) -> Result<Self, TemplateError> {
        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(true);
        handlebars.register_helper("json", Box::new(json_helper));

        let checkout_source = match custom_dir {
            Some(dir) => {
                let path = Path::new(dir).join("checkout.html.hbs");
                if path.exists() {
                    std::fs::read_to_string(&path)
                        .map_err(|e| TemplateError::Read { path: path.display().to_string(), source: e })?
                } else {
                    DEFAULT_CHECKOUT_TEMPLATE.to_string()
                }
            }
            None => DEFAULT_CHECKOUT_TEMPLATE.to_string(),
        };
        handlebars.register_template_string("checkout", checkout_source)?;

        Ok(TemplateEngine { handlebars })
    }

    pub fn render_checkout(&self, data: &CheckoutViewModel) -> Result<String, TemplateError> {
        Ok(self.handlebars.render("checkout", data)?)
    }
}

/// `pending`/`unconfirmed`/`confirming`/`partial` are still "in progress";
/// `paid`/`overpaid`/`expired` are terminal - used to decide whether the page
/// should keep polling for updates. Mirrors `status::OrderStatus` without adding a
/// dependency from this module back onto it, since these are presentation
/// concerns (label text, CSS class, poll-or-not), not domain logic.
pub fn status_label(status: &str) -> (String, &'static str, bool) {
    match status {
        "pending" => ("Waiting for payment".to_string(), "status-pending", false),
        "unconfirmed" => ("Payment seen, unconfirmed".to_string(), "status-unconfirmed", false),
        "confirming" => ("Confirming".to_string(), "status-confirming", false),
        "partial" => ("Partial payment received".to_string(), "status-partial", false),
        "paid" => ("Paid".to_string(), "status-paid", true),
        "overpaid" => ("Overpaid".to_string(), "status-paid", true),
        "expired" => ("Expired".to_string(), "status-expired", true),
        other => (other.to_string(), "status-unknown", true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_view_model() -> CheckoutViewModel {
        CheckoutViewModel {
            payment_id: "pay_test123".to_string(),
            status: "pending".to_string(),
            status_label: "Waiting for payment".to_string(),
            status_class: "status-pending".to_string(),
            address: "5abcexampleaddress".to_string(),
            qr_code_svg: "<svg></svg>".to_string(),
            xmr_amount: "0.500000000000".to_string(),
            amount_received_xmr: "0.000000000000".to_string(),
            fiat_amount: "25.00".to_string(),
            fiat_currency: "USD".to_string(),
            confirmations: 0,
            confirmations_required: 10,
            is_terminal: false,
            double_spend_detected_at: None,
            expires_at: 9_999_999_999,
            merchant_order_id: None,
            description: None,
            payments: vec![],
        }
    }

    #[test]
    fn default_template_renders_without_error_and_includes_key_fields() {
        let engine = TemplateEngine::new(None).unwrap();
        let html = engine.render_checkout(&sample_view_model()).unwrap();
        assert!(html.contains("pay_test123"));
        assert!(html.contains("5abcexampleaddress"));
        assert!(html.contains("0.500000000000"));
        assert!(html.contains("<svg"));
    }

    #[test]
    fn double_spend_banner_only_renders_when_the_field_is_set() {
        let engine = TemplateEngine::new(None).unwrap();

        let without = engine.render_checkout(&sample_view_model()).unwrap();
        assert!(
            !without.contains(r#"id="double-spend-banner""#),
            "no banner expected when double_spend_detected_at is None"
        );

        let mut with_ds = sample_view_model();
        with_ds.double_spend_detected_at = Some(1_700_000_000);
        with_ds.status = "partial".to_string();
        let with = engine.render_checkout(&with_ds).unwrap();
        assert!(
            with.contains(r#"id="double-spend-banner""#),
            "banner must render when double_spend_detected_at is set"
        );
    }

    #[test]
    fn falls_back_to_the_embedded_default_when_a_custom_dir_lacks_the_file() {
        let dir = std::env::temp_dir().join(format!("moneropay_template_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let engine = TemplateEngine::new(Some(dir.to_str().unwrap())).unwrap();
        let html = engine.render_checkout(&sample_view_model()).unwrap();
        assert!(html.contains("pay_test123"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn uses_a_custom_template_file_when_present() {
        let dir = std::env::temp_dir().join(format!("moneropay_template_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("checkout.html.hbs"), "custom template for {{payment_id}}").unwrap();
        let engine = TemplateEngine::new(Some(dir.to_str().unwrap())).unwrap();
        let html = engine.render_checkout(&sample_view_model()).unwrap();
        assert_eq!(html, "custom template for pay_test123");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_json_helper_cannot_close_the_script_element_it_is_embedded_in() {
        // `serde_json` alone escapes this correctly *as JSON* and still emits a
        // literal `</script>`, which an HTML parser acts on before any JS parser
        // sees the string. The payload below would otherwise land as live markup on
        // the checkout page - next to the Monero address the customer is about to
        // pay, and replaceable by it.
        let dir = std::env::temp_dir().join(format!("moneropay_template_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("checkout.html.hbs"),
            "<script>var d = {{{json description}}};</script>",
        )
        .unwrap();
        let engine = TemplateEngine::new(Some(dir.to_str().unwrap())).unwrap();

        let mut model = sample_view_model();
        model.description = Some("</script><img src=x onerror=alert(1)>".to_string());
        let html = engine.render_checkout(&model).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            !html[..html.len() - "</script>".len()].contains("</script"),
            "no `</script` may appear before the real closing tag: {html}"
        );
        assert!(!html.contains("<img"), "markup must not survive into the page: {html}");
        assert!(html.contains("\\u003c/script\\u003e"), "got {html}");
    }

    #[test]
    fn the_json_helper_output_still_parses_back_to_the_original_value() {
        // The escaping is only correct if it is transparent - the JS that reads
        // these values must see exactly what the server put in.
        for value in [
            serde_json::json!("</script>"),
            serde_json::json!("a & b < c > d"),
            serde_json::json!("line\u{2028}sep\u{2029}para"),
            serde_json::json!("quotes \" and \\ backslash"),
            serde_json::json!({ "nested": ["</script>", 1, true, null] }),
            serde_json::json!(12345),
            serde_json::json!(null),
        ] {
            let escaped = escape_for_script_element(&serde_json::to_string(&value).unwrap());
            assert!(!escaped.contains('<') && !escaped.contains('>') && !escaped.contains('&'));
            let round_tripped: serde_json::Value = serde_json::from_str(&escaped).unwrap();
            assert_eq!(round_tripped, value);
        }
    }

    #[test]
    fn status_label_covers_every_real_status_and_marks_terminal_correctly() {
        assert_eq!(status_label("pending"), ("Waiting for payment".to_string(), "status-pending", false));
        assert_eq!(status_label("confirming"), ("Confirming".to_string(), "status-confirming", false));
        assert_eq!(status_label("paid"), ("Paid".to_string(), "status-paid", true));
        assert_eq!(status_label("expired"), ("Expired".to_string(), "status-expired", true));
    }
}
