# Postern Browser — a hardened Firefox profile. Part of Postern OS (a Postern Labs
# product). Declarative enterprise policies + locked about:config prefs, an
# arkenfox-inspired privacy/anti-fingerprinting spine — no telemetry, strict
# tracking protection, HTTPS-only, no IP leaks. Pairs with the OS Tor client.
{ config, lib, pkgs, ... }:
{
  programs.firefox = {
    enable = true;

    # ── Enterprise policies (org-level, locked; -> policies.json) ─────────────
    policies = {
      DisableTelemetry = true;
      DisableFirefoxStudies = true;
      DisablePocket = true;
      DisableFormHistory = true;
      DontCheckDefaultBrowser = true;
      OfferToSaveLogins = false;
      PasswordManagerEnabled = false;          # use a real password manager
      EnableTrackingProtection = {
        Value = true;
        Locked = true;
        Cryptomining = true;
        Fingerprinting = true;
      };
      DNSOverHTTPS.Enabled = true;             # encrypted DNS in the browser too
      FirefoxHome = {
        Search = true; TopSites = false; SponsoredTopSites = false;
        Highlights = false; Pocket = false; SponsoredPocket = false; Snippets = false;
      };
      UserMessaging = {
        ExtensionRecommendations = false; FeatureRecommendations = false;
        SkipOnboarding = true; MoreFromMozilla = false;
      };
      # A couple of privacy add-ons, installed + locked.
      ExtensionSettings = {
        "uBlock0@raymondhill.net" = {
          installation_mode = "normal_installed";
          install_url = "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi";
        };
      };
    };

    # ── Locked about:config prefs (the hardening spine) ───────────────────────
    preferences = {
      # Anti-fingerprinting + tracking.
      "privacy.resistFingerprinting" = true;         # RFP: uniform fingerprint
      "privacy.trackingprotection.enabled" = true;
      "privacy.trackingprotection.socialtracking.enabled" = true;
      "browser.contentblocking.category" = "strict";
      "network.cookie.cookieBehavior" = 5;           # dFPI (total cookie protection)
      # Transport.
      "dom.security.https_only_mode" = true;
      # No speculative / prefetch leaks.
      "network.prefetch-next" = false;
      "network.dns.disablePrefetch" = true;
      "network.predictor.enabled" = false;
      "network.http.speculative-parallel-limit" = 0;
      # No WebRTC local-IP leak (keeps WebRTC usable).
      "media.peerconnection.ice.default_address_only" = true;
      "media.peerconnection.ice.no_host" = true;
      # No pings / beacons / geo.
      "beacon.enabled" = false;
      "browser.send_pings" = false;
      "geo.enabled" = false;
      # Telemetry off (belt-and-suspenders with the policy).
      "toolkit.telemetry.enabled" = false;
      "toolkit.telemetry.unified" = false;
      "datareporting.healthreport.uploadEnabled" = false;
      "datareporting.policy.dataSubmissionEnabled" = false;
      "app.shield.optoutstudies.enabled" = false;
      "browser.newtabpage.activity-stream.feeds.telemetry" = false;
      "browser.newtabpage.activity-stream.telemetry" = false;
      # No search-keystroke leakage.
      "browser.search.suggest.enabled" = false;
      "browser.urlbar.suggest.searches" = false;
    };
    preferencesStatus = "locked";
  };
}
