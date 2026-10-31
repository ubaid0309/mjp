// ByteMart browser script - DEMO DATA, intentionally vulnerable.
const params = new URLSearchParams(window.location.search);
const banner = document.getElementById("promo-banner");

// Vulnerable: ?promo=<img src=x onerror=alert(1)> runs script
banner.innerHTML = "Today's offer: " + params.get("promo");
