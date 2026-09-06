/*
 * moneropay-client.js - the thin embed library for a static merchant site
 * (docs/DESIGN.md §14). Deliberately dependency-free, no build step, ES5-ish
 * syntax: it has to run unmodified on an arbitrary third-party page (a
 * GitHub Pages site, most plausibly) that Claude - or anyone else maintaining
 * this project - does not control the toolchain of.
 *
 * All payment logic and status rendering lives server-side in the
 * `/pay/v1/{pk}/{payment_id}` page this library iframes; this file only
 * creates orders, mounts that iframe, and relays its postMessage events.
 */
(function (global) {
  "use strict";

  // Orders remember the endpoint/publicKey they were created against, so
  // `mount(selector, paymentId, options)` can be called with just the id - as
  // shown in docs/DESIGN.md §14 - without the caller re-stating both. A page
  // that reloads and wants to remount a paymentId from a previous visit (no
  // createOrder call this pageload) can still pass `endpoint`/`publicKey`
  // explicitly via `options`.
  var knownOrders = {};

  // Every element that currently has a live mount, so a re-mount can tear the
  // previous one down first. `mount()` only removes its `message` listener from
  // the returned `destroy()`, which nothing calls automatically - so remounting
  // the same container (a SPA re-render, a "try again" button, a customer
  // switching between two order widgets) previously stacked a second listener on
  // top of the first and fired every callback once per past mount. A Map keyed by
  // the element avoids stashing bookkeeping on the merchant's own DOM node; the
  // WeakMap variant is used where available so a detached container doesn't
  // pin its entry forever.
  var activeMounts = typeof WeakMap === "function" ? new WeakMap() : new Map();

  // Captured here, while this file is still the executing script, rather than read
  // on demand inside createOrder/mount. `document.currentScript` names whatever
  // script is running *right now*, so by the time a merchant calls into this library
  // it is their code, not ours: null when called from an event handler or a module,
  // and their own page's origin when called from another classic <script src>. The
  // endpoint inference then either failed outright or - worse - silently pointed the
  // payment API at the merchant's own static host.
  var SCRIPT_ORIGIN = (function () {
    var script = document.currentScript;
    if (!script || !script.src) return null;
    try {
      return new URL(script.src).origin;
    } catch (e) {
      return null;
    }
  })();

  function scriptOrigin() {
    return SCRIPT_ORIGIN;
  }

  function createOrder(params) {
    params = params || {};
    var endpoint = (params.endpoint || scriptOrigin() || "").replace(/\/+$/, "");
    var publicKey = params.publicKey;
    if (!endpoint) {
      return Promise.reject(new Error("MoneroPay.createOrder: endpoint is required (could not infer it from the script tag)"));
    }
    if (!publicKey) {
      return Promise.reject(new Error("MoneroPay.createOrder: publicKey is required"));
    }
    if (params.fiatAmount === undefined || params.fiatAmount === null || !params.fiatCurrency) {
      return Promise.reject(new Error("MoneroPay.createOrder: fiatAmount and fiatCurrency are required"));
    }

    return fetch(endpoint + "/api/v1/t/" + encodeURIComponent(publicKey) + "/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        merchant_order_id: params.merchantOrderId,
        fiat_amount: String(params.fiatAmount),
        fiat_currency: params.fiatCurrency,
        description: params.description,
      }),
    })
      .then(function (response) {
        if (!response.ok) {
          return response
            .json()
            .catch(function () {
              return { error: "HTTP " + response.status };
            })
            .then(function (body) {
              throw new Error(body.error || "HTTP " + response.status);
            });
        }
        return response.json();
      })
      .then(function (data) {
        var order = {
          paymentId: data.payment_id,
          address: data.address,
          xmrAmountPiconero: data.xmr_amount_piconero,
          fiatAmount: data.fiat_amount,
          fiatCurrency: data.fiat_currency,
          expiresAt: data.expires_at,
          endpoint: endpoint,
          publicKey: publicKey,
        };
        knownOrders[order.paymentId] = { endpoint: endpoint, publicKey: publicKey };
        return order;
      });
  }

  function resolveTarget(selector) {
    if (typeof selector === "string") return document.querySelector(selector);
    return selector || null;
  }

  function mount(selector, paymentIdOrOrder, options) {
    options = options || {};
    var el = resolveTarget(selector);
    if (!el) {
      throw new Error("MoneroPay.mount: target element not found: " + selector);
    }

    var paymentId, endpoint, publicKey;
    if (paymentIdOrOrder && typeof paymentIdOrOrder === "object") {
      paymentId = paymentIdOrOrder.paymentId;
      endpoint = paymentIdOrOrder.endpoint;
      publicKey = paymentIdOrOrder.publicKey;
    } else {
      paymentId = paymentIdOrOrder;
    }
    endpoint = options.endpoint || endpoint || (knownOrders[paymentId] || {}).endpoint || scriptOrigin();
    publicKey = options.publicKey || publicKey || (knownOrders[paymentId] || {}).publicKey;

    if (!paymentId || !endpoint || !publicKey) {
      throw new Error(
        "MoneroPay.mount: could not resolve paymentId/endpoint/publicKey - pass an order object " +
          "from createOrder(), or {endpoint, publicKey} in options for a paymentId from a previous visit"
      );
    }

    // Tear down whatever this element was showing before, so a re-mount replaces
    // the previous mount rather than accumulating alongside it.
    var previous = activeMounts.get(el);
    if (previous) {
      previous.destroy();
    }

    var iframeSrc = endpoint + "/pay/v1/" + encodeURIComponent(publicKey) + "/" + encodeURIComponent(paymentId);
    // The only origin whose messages this mount will ever act on. Derived from the
    // frame's own URL rather than configured separately, so it cannot drift out of
    // sync with what was actually mounted.
    var expectedOrigin;
    try {
      expectedOrigin = new URL(iframeSrc, global.location.href).origin;
    } catch (e) {
      throw new Error("MoneroPay.mount: endpoint is not a valid URL: " + endpoint);
    }

    var iframe = document.createElement("iframe");
    iframe.src = iframeSrc;
    iframe.title = "Monero Payment";
    iframe.style.border = "none";
    iframe.style.width = options.width || "420px";
    iframe.style.height = options.height || "640px";
    iframe.setAttribute("sandbox", "allow-scripts allow-same-origin allow-popups");

    el.innerHTML = "";
    el.appendChild(iframe);

    function onMessage(event) {
      // `window.addEventListener("message", ...)` receives messages from *every*
      // script that can reach this window - a third-party ad, an analytics tag, any
      // other embedded frame on the merchant's page. The fields inside `event.data`
      // are attacker-chosen and prove nothing, so checking `data.source` and
      // `data.paymentId` alone let any such script forge
      // `{source:"moneropay", paymentId: <visible in the DOM>, status:"paid"}` and
      // drive the merchant's own `onPaid` handler. Only the browser-supplied
      // `event.origin` and `event.source` are trustworthy here:
      //   - origin pins the message to the payment server that served this frame,
      //   - source pins it to *this* frame instance specifically, so a second,
      //     unrelated frame from the same origin can't speak for this order either.
      if (event.origin !== expectedOrigin) return;
      if (event.source !== iframe.contentWindow) return;

      var data = event.data;
      if (!data || data.source !== "moneropay" || data.paymentId !== paymentId) return;
      if (typeof options.onStatusChange === "function") options.onStatusChange(data.status, data);
      if ((data.status === "paid" || data.status === "overpaid") && typeof options.onPaid === "function") {
        options.onPaid(data);
      }
      if (data.status === "expired" && typeof options.onExpired === "function") {
        options.onExpired(data);
      }
    }
    global.addEventListener("message", onMessage);

    var destroyed = false;
    var handle = {
      iframe: iframe,
      destroy: function () {
        if (destroyed) return;
        destroyed = true;
        global.removeEventListener("message", onMessage);
        if (activeMounts.get(el) === handle) activeMounts["delete"](el);
        if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
      },
    };
    activeMounts.set(el, handle);
    return handle;
  }

  global.MoneroPay = { createOrder: createOrder, mount: mount };
})(window);
