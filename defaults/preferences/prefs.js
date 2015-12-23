// Pre-defined set, needs to match the list provided in thundersec.js
pref("extensions.thundersec.zen.spamhaus.org", true);
pref("extensions.thundersec.b.barracudacentral.org", true);
pref("extensions.thundersec.dnsbl.abuse.ch", true);
pref("extensions.thundersec.cbl.abuseat.org", true);
pref("extensions.thundersec.ubl.unsubscore.com", true);
pref("extensions.thundersec.bl.spamcop.net", false);
pref("extensions.thundersec.dnsbl.sorbs.net", false);

// SURBL 
pref("extensions.thundersec.multi.uribl.com", true);
pref("extensions.thundersec.multi.surbl.org", true);

// For custom DNSBL and SURBL
pref("extensions.thundersec.custom_dnsbl_enabled", false);
pref("extensions.thundersec.custom_dnsbl", "dnsbl.example.com");
pref("extensions.thundersec.custom_surbl_enabled", false);
pref("extensions.thundersec.custom_surbl", "surbl.example.com");

// Advanced settings
pref("extensions.thundersec.api_enabled", true);
pref("extensions.thundersec.display_clean_message", true);
pref("extensions.thundersec.auto_junk_enabled", false);
