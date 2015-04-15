/*
    Security Extensions for Mozilla Thunderbird
    Copyright (C) 2015 by Ilker Temir (@ilkertemir) and Tim Sammut (@t1msammut)

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; version 2
    of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// Global variables
var DNSBL = {};
var SPF = {};
var DKIM = {};
var stats = { periodStart: Date.now() / 1000,
              periodEnd: null,
              inspectTotal: 0,
              dnsblLookup: 0,
              dnsblViolation: 0,
              dnsblWhitelist: 0,
              spfViolation: 0,
              spfWhitelist:0,
              dkimViolation: 0,
              dkimWhitelist: 0 };
var totalDNSlookups = {};
var currentMailID;
var connection;
var initialized = false;

if ( !initialized) {
    initialized = true; 
    initialize();
}

function initialize() {
    // We will watch for application-quit
    function quitObserver()
    {
       this.register();
    }
    quitObserver.prototype = {
      observe: function(subject, topic, data) {
         // This has to be an async request while application is quitting
         // Or Thunderbird will quit before the $.post completes 
         jQuery.ajaxSetup({async:false});
         apiSendGenericStats();
      },
      register: function() {
        var observerService = Components.classes["@mozilla.org/observer-service;1"]
                              .getService(Components.interfaces.nsIObserverService);
        observerService.addObserver(this, "quit-application", false);
      },
      unregister: function() {
        var observerService = Components.classes["@mozilla.org/observer-service;1"]
                                .getService(Components.interfaces.nsIObserverService);
        observerService.removeObserver(this, "quit-application");
      }
    }

    let observer = new quitObserver();

    // Add event listener
    var messagepane = document.getElementById("messagepane");
    messagepane.addEventListener('load', function () {
      pluginMain();
    }, true);

    // Check new version now (in a minute) and then every day
    setTimeout (apiCheckVersion, 60*1000); 
    setInterval (apiCheckVersion, 24*60*60*1000);

    setInterval (apiSendGenericStats, STAT_INTERVAL);

    if (!connection) {
        Components.utils.import("resource://gre/modules/Sqlite.jsm");
        Sqlite.openConnection(
            { path: DB_NAME }
        ).then(
            function onConnection(conn) {
               // Set the global variable
               connection = conn;

               conn.tableExists("dnsblWhiteList").then(
                   function (exists) {
                       if (!exists) {
                           // This means, database has just been created. Create the table.
                           createDnsblTable (conn);
                       }
                   }
               ); 

               conn.tableExists("spfWhiteList").then(
                   function (exists) {
                       if (!exists) {
                           // This means, database has just been created. Create the table.
                           createSpfTable (conn);
                       }
                   }
               ); 

               conn.tableExists("dkimWhiteList").then(
                   function (exists) {
                       if (!exists) {
                           // This means, database has just been created. Create the table.
                           createDkimTable (conn);
                       }
                   }
               ); 

            }, // on Connection
            function onError(error) {
                alert (error);
            }
        );
    } // if (!connection)
}

// Checks if we are running the latest version
function apiCheckVersion() {
    $.get (API_URL + 'version', function (data) {
        let latestVersion = data['version'];
        let description = data['description'];
 
        if ( version_compare (VERSION, latestVersion, '<') ) {
            let message = 'New Version Available\n\n' +
                          'ThunderSec v' + latestVersion + ' is available.\n' +
                          'Description: ' + description + '\n\n' +
                          'Would you like to download?';
 
            if ( window.confirm (message) ) {
                window.open (data['url'],'','chrome,centerscreen');
            }
        }
    }, 'json');
}

// Sends generic statistics to the API
function apiSendGenericStats() {
    var pref = Components.classes["@mozilla.org/preferences-service;1"]
                     .getService(Components.interfaces.nsIPrefService)
                     .getBranch("extensions.thundersec.");

    // Check if API usage is allowed in preferences
    if ( pref.getBoolPref('api_enabled') ) {
        // Set period end to now
        stats.periodEnd = Date.now() / 1000;

        // Add version information for the API
        stats.version = VERSION;
    
        // Send stats
        $.post (API_URL + 'stat', stats, function () {
            // Reset stats, only on success
            stats = { periodStart: Date.now() / 1000,
                      periodEnd: null,
                      inspectTotal: 0,
                      dnsblLookup: 0,
                      dnsblViolation: 0,
                      dnsblWhitelist: 0,
                      spfViolation: 0,
                      spfWhitelist:0,
                      dkimViolation: 0,
                      dkimWhitelist: 0 };
        });
    }
}

function createDnsblTable(connection) {
    let sql = " CREATE TABLE 'dnsblWhiteList' ( " +
              "   'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," +
    	      "	  'ipAddress'	TEXT NOT NULL," +
	      "   'dnsblSource'	TEXT NOT NULL," +
	      "   'code'	TEXT NOT NULL," +
	      "	  'sender'	TEXT NOT NULL," +
              "   UNIQUE(ipAddress, dnsblSource, code, sender) ); ";

    connection.execute (sql);
}

function createSpfTable(connection) {
    let sql = " CREATE TABLE 'spfWhiteList' ( " +
              "   'id'  INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," +
              "   'reason'      TEXT NOT NULL," +
              "   'sender'      TEXT NOT NULL," +
              "    UNIQUE(reason, sender) ); ";

    connection.execute (sql);
}

function createDkimTable(connection) {
    let sql = " CREATE TABLE 'dkimWhiteList' ( " +
              "   'id'  INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," +
              "   'reason'      TEXT NOT NULL," +
              "   'sender'      TEXT NOT NULL," +
              "    UNIQUE(reason, sender) ); ";

    connection.execute (sql);
}

// Notify the API for crowd-sourced improvements
// This should not send any sensitive information back
function apiSendDnsblStats (ip, code, source) {
    var pref = Components.classes["@mozilla.org/preferences-service;1"]
                     .getService(Components.interfaces.nsIPrefService)
                     .getBranch("extensions.thundersec.");

    // Check if API usage is allowed in preferences
    if ( pref.getBoolPref('api_enabled') ) {
        // We will hash the sender for privacy
        $.post( API_URL + 'dnsbl/stat',
               { 'ip': ip,
                 'code': code,
                 'dnsbl': source,
                 'version': VERSION } );
    }
}

// Notify the API for crowd-sourced improvements
// This should not send any sensitive information back
function apiSendWhiteList(ip, code, source,sender) {
    var pref = Components.classes["@mozilla.org/preferences-service;1"]
                     .getService(Components.interfaces.nsIPrefService)
                     .getBranch("extensions.thundersec.");

    // Check if API usage is allowed in preferences
    if ( pref.getBoolPref('api_enabled') ) {
        // We will hash the sender for privacy
        // We use SHA256 hash, it is a way one way hash (i.e. you cannnot go back from hash to email)
        let sha256Hash = CryptoJS.SHA256 (sender).toString(CryptoJS.enc.Hex);
        $.post( API_URL + 'dnsbl/whitelist',
               { 'ip': ip,
                 'code': code,
                 'dnsbl': source,
                 'senderHash': sha256Hash,
                 'version': VERSION } );
    }
}

function IPnumber(IPaddress) {
    var ip = IPaddress.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if(ip) {
        return (+ip[1]<<24) + (+ip[2]<<16) + (+ip[3]<<8) + (+ip[4]);
    }
    return null;
}

function IPmask(maskSize) {
    return -1<<(32-maskSize)
}

function isReserved (IPaddress) {
    var netblocks= [ { network: '10.0.0.0', maskLength: 8 },
     		     { network: '172.16.0.0', maskLength: 20 },
     		     { network: '192.168.0.0', maskLength: 16 },
     		     { network: '127.0.0.0', maskLength: 8 },
     		     { network: '0.0.0.0', maskLength: 8 },
     		     { network: '169.254.0.0', maskLength: 16 },
     		     { network: '192.0.0.0', maskLength: 24 },
     		     { network: '192.0.2.0', maskLength: 24 },
     		     { network: '192.88.99.0', maskLength: 24 },
     		     { network: '198.18.0.0', maskLength: 15 },
     		     { network: '198.51.100.0', maskLength: 24 },
     		     { network: '203.0.113.0', maskLength: 24 },
     		     { network: '240.0.0.0', maskLength: 4 },
     		     { network: '100.64.0.0', maskLength: 10 } ];
    var network;
    var prefix;

    for (var i in netblocks) {
        network = netblocks[i].network;
        prefix = netblocks[i].maskLength;

        if ( (IPnumber (IPaddress) & IPmask (prefix)) == IPnumber(network) ) {
            return true;
        }
    }
    return false;
}

function parseReceivedLine (receivedLine) {
   var addr=null;
   var match;

   // Parses "Received: by mail-xyz.google.com with SMTP id XXXX"
   match = /^by ([^\s]+)/.exec(receivedLine);
   if (match) {
      addr = match[1];
      return (addr);
   }

   // Parses "Received: from dc-XXX.example.com ([10.10.10.15]) by dc-YYY.example.com"
   match = /^from [^\s]+ \([^\[]*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/.exec(receivedLine);
   if (match) {
      addr = match[1];
      return (addr);
   }

   // Parses "Received: from dc-XXX.example.com (10.10.10.15) by mail.example.com"
   // Parses "Received: from (127.0.0.1) by mail142.wdc02.mcdlv.net"
   match = /^from [\[\(]?([^\s\]\)]+)/.exec(receivedLine);
   if (match) {
      addr = match[1];
      return (addr);
   }

   return addr;
}

function updateWhiteList(dnsbl, spf, dkim) {
    connection.execute("BEGIN IMMEDIATE TRANSACTION");
    for (var i in dnsbl) {
        let values = [ dnsbl[i].ip,
                       dnsbl[i].service, 
                       dnsbl[i].code,
                       dnsbl[i].sender ];
        let sql = "INSERT OR IGNORE INTO dnsblWhiteList " +
                  "('ipAddress', 'dnsblSource', 'code', 'sender') " +
                  "VALUES (?, ?, ?, ?)";
        connection.execute(sql, values);

        // Notify the API for crowd-sourced improvements
        apiSendWhiteList(dnsbl[i].ip, 
                         dnsbl[i].code,
                         dnsbl[i].service,
                         dnsbl[i].sender);
    }
    if (!spf.pass) {
        let values = [ spf.reason, spf.sender ];
        let sql = "INSERT OR IGNORE INTO spfWhiteList " +
                  "('reason', 'sender') " +
                  "VALUES (?, ?)";
        connection.execute(sql, values);
    }
    if (!dkim.pass) {
        let values = [ dkim.reason, dkim.sender ];
        let sql = "INSERT OR IGNORE INTO dkimWhiteList " +
                  "('reason', 'sender') " +
                  "VALUES (?, ?)";
        connection.execute(sql, values);
    }
    connection.execute("COMMIT TRANSACTION");
}

function markAsLegitimate(notf, desc) {
    var confirm = window.confirm ("Are you sure to mark this e-mail as legitimate?\n\n" + 
                                  "This will be remembered and similar messages from " +
                                  "this user will no longer be marked for the same " +
                                  "reason in the future.");
    if (confirm) {
        // We need to pass the DNSBL here, otherwise it will be reset before the database is processed
        updateWhiteList( DNSBL[currentMailID], SPF[currentMailID], DKIM[currentMailID] );
    } else {
        throw new Error('Preventing notification bar from closing.'); 
    }
}

function detailsBox(notf, desc) {
    var params = { dnsbl: DNSBL[currentMailID],
                   dkim: DKIM[currentMailID],
                   spf: SPF[currentMailID] };

    window.openDialog("chrome://thundersec/content/details.xul", "",
                      "chrome, dialog, centerscreen, resizable=no",
                      params);

    throw new Error('Preventing notification bar from closing.');
}

function optionsBox(notf, desc) {
    var features = "chrome,titlebar,toolbar,centerscreen,dialog=yes";
    window.openDialog("chrome://thundersec/content/options.xul", "Preferences", features);
    throw new Error('Preventing notification bar from closing.');
}

function updateNotification(mailID) {
   if (mailID != currentMailID) { 
       // User has moved on, don't updae the notificationbox
       return;
   }

   var buttons = [
     {
       label: 'Details',
       accessKey: 'D',
       popup: null,
       callback: detailsBox
     },
     {
       label: 'Mark as Legitimate',
       accessKey: 'M',
       popup: null,
       callback: markAsLegitimate
     },
     {
       label: 'Preferences',
       accessKey: 'P',
       popup: null,
       callback: optionsBox
     },
   ];

   let notificationBox = document.getElementById("msgNotificationBar");
   if ( notificationBox.getNotificationWithValue( 'dnsbl' ) ) {
       notificationBox.removeCurrentNotification();
   }


   let violations = [];
   let plural = false;

   if ( DNSBL[currentMailID].length == 1 ) { 
       violations.push ("DNSBL");
   }
   else if ( DNSBL[currentMailID].length > 1 ) {
       violations.push ("Multiple DNSBL");
       plural = true;
   }

   if ( !SPF[currentMailID].pass ) {
      violations.push ("SPF");
   }

   if ( !DKIM[currentMailID].pass ) {
      violations.push ("DKIM");
   }

   let notificationText = '';
   
   if ( violations.length == 1 ) {
       if (plural) {
           notificationText = notificationText + 
                              violations[0] + ' violations. ';
       }
       else {
           notificationText = notificationText +
                              violations[0] + ' violation. ';
       }
   }
   if ( violations.length == 2 ) {
       notificationText = notificationText + 
                          violations[0] + ' and ' +  
                          violations[1] + ' violations. ';
   }
   if ( violations.length == 3 ) {
       notificationText = notificationText + 
                          violations[0] + ', ' +  
                          violations[1] + ' and ' +  
                          violations[2] + ' violations. ';
   }

   notificationText = notificationText + "Please check Details for more information."

   notificationBox.appendNotification(notificationText,
                                      "dnsbl",
                                      null,
                                      10,
                                      buttons);
}

function updateDNSBLinfo(mailID) {
    if (mailID != currentMailID) {
        // User has moved on, don't updae the notificationbox
        return;
    }
    var numLookups = totalDNSlookups[mailID]

    var dnsblInfo = document.getElementById("dnsblInfo");
    var imgSpinner = document.getElementById("imgSpinner");
    var label;
    if (numLookups != 0) { 
        label = "Number of outstanding DNSBL lookups: " + numLookups;
        imgSpinner.hidden = false;
    }
    else {
        label = "";
        imgSpinner.hidden = true;
    }
    dnsblInfo.label = label;
}
    
function doDNSBLcheck(relays, dnsblService, returnPath, mailID) {
    var match;
    var reverseAddr;
    var numDNSLookups = 0;
    var numSQLLookups = 0;
    var safeMail = true;

    let DnsService = Components.classes["@mozilla.org/network/dns-service;1"]
                     .createInstance(Components.interfaces.nsIDNSService);

    let Thread = Components.classes["@mozilla.org/thread-manager;1"]
                 .getService(Components.interfaces.nsIThreadManager).currentThread;

    for (var i in relays) {
        let dnsblQuery;
        let addr;
        let resolvedAddr;

        let Listener = {
             onLookupComplete: function(request, record, status) {
               numDNSLookups--;
               totalDNSlookups[mailID]--;
               updateDNSBLinfo(mailID);

               if (Components.isSuccessCode(status)) {
                   while ( record && record.hasMore() ) {
                       // Update stats
                       stats.dnsblViolation++;

                       resolvedAddr = record.getNextAddrAsString();
                       // This query HAS TO return only a single row
                       let sql = "SELECT COUNT(id) as cnt FROM dnsblWhiteList " +
                                 "WHERE ipAddress=? AND dnsblSource=? AND code=? AND sender=?";
                       let values = [ addr,
                                      dnsblService,
                                      resolvedAddr,
                                      returnPath ];
                       numSQLLookups++;
                       connection.execute(sql, values, function(row) {
                            numSQLLookups--;

                           // This will be 1 for existing records, 0 for non-existent ones
                           let count = row.getResultByName('cnt');
                           if (!count) { 
                               DNSBL[mailID].push ( { ip: addr,
			        			 service: dnsblService, 
                                                         code: resolvedAddr,
                                                         sender: returnPath } );
                               apiSendDnsblStats (addr, resolvedAddr, dnsblService);
                               safeMail = false;
                           } else {
                               // Previously white listed
                               // Update stats
                               stats.dnsblWhitelist++;
                           }
                           // Make sure we finished all lookups, both DNS and SQL
                           if ( numSQLLookups == 0 ) {
                               if (safeMail) {
                                    // Pass
                               } else {
                                   updateNotification (mailID)
                               }
                           }
                       });
                   }
               }
               else {
                   // No response from DNS DNSBL safe
               }

            }
        };

        addr = relays[i];

        match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec (addr);
        if (match) {
           reverseAddr = match[4] + "." + match[3] + "." + match[2] + "." + match[1];
           dnsblQuery = reverseAddr + "." + dnsblService + ".";

           // Update stats
           stats.dnsblLookup++;

           numDNSLookups++;

           totalDNSlookups[mailID]++;
           updateDNSBLinfo(mailID);

           DnsService.asyncResolve(dnsblQuery, 0, Listener, Thread);
       
        }
    }
}

// For debugging only, should not be used in production code
function mydump(arr,level) {
    var dumped_text = "";
    if(!level) level = 0;

    var level_padding = "";
    for(var j=0;j<level+1;j++) level_padding += "    ";

    if(typeof(arr) == 'object') {  
        for(var item in arr) {
            var value = arr[item];

            if(typeof(value) == 'object') { 
                dumped_text += level_padding + "'" + item + "' ...\n";
                dumped_text += mydump(value,level+1);
            } else {
                dumped_text += level_padding + "'" + item + "' => \"" + value + "\"\n";
            }
        }
    } else { 
        dumped_text = "===>"+arr+"<===("+typeof(arr)+")";
    }
    return dumped_text;
}

// Perform all DNSBL checks by calling doDNSBLcheck iteratively
function doDNSBLchecks(relays, returnPath, mailID) {
    var dnsblServices = [ 'zen.spamhaus.org',
			'b.barracudacentral.org',
                        'dnsbl.abuse.ch',
                        'cbl.abuseat.org',
                        'ubl.unsubscore.com',
		        'bl.spamcop.net',
		        'dnsbl.sorbs.net' ];

    var pref = Components.classes["@mozilla.org/preferences-service;1"]
                         .getService(Components.interfaces.nsIPrefService)
                         .getBranch("extensions.thundersec.");

    // Do this for each of the DNSBL services
    for (var i in dnsblServices) {
        // Check if enabled in preferences
        if ( pref.getBoolPref(dnsblServices[i]) ){
            doDNSBLcheck (relays, dnsblServices[i], returnPath, mailID);
        }
    }

    // Process Custom DNSBL if it is enabled
    if ( pref.getBoolPref('custom_dnsbl_enabled') && pref.getCharPref('custom_dnsbl') ) {
        var customDNSBLs = pref.getCharPref('custom_dnsbl').split(/\s*\,\s*|\s+/);
        for (var i in customDNSBLs) {
            doDNSBLcheck (relays, customDNSBLs[i], returnPath, mailID);
        }
    }

}

function parseAuthResults(input) {
    var parts = new Array();
    for(var i = 0, mark = ';', part = ''; 
        i < input.length; 
        i++) {

        part += input[i];
        if (input[i] == mark) { 
            parts[parts.length] = part.trim().replace(/;$/, '').replace(/\s+/g, ' ');
            part = '';
        }
        if (input[i] == '\"') {
            mark = mark == ';' ? 'AA' : ';';
        }
    }
    parts[parts.length] = part.trim().replace(/;$/, '').replace(/\s+/g, ' ');
    return parts;
}

function isDKIMsuccess(authResults, sender, mailID) {
    DKIM[mailID] = { pass: true,
                     reason: null,
                     sender: sender };

    for (let i in authResults) {
        let item = authResults[i];
        let match = item.match (/dkim=([^\s]+)/);
        if ( (match) && 
             (match[1] != 'pass') &&
             (match[1] != 'neutral') &&
             (match[1] != 'none') ) {
               // Update stats
               stats.dkimViolation++;

               // Try to extract reason but this is not foolproof
               let match = item.match (/dkim=[^\s]+ \((.*?)\)/ );
               let reason = '';
               if (match) {
                   reason=match[1];
               }
               // Check if previously white-listed
               let sql = "SELECT COUNT(id) as cnt FROM dkimWhiteList " +
                         "WHERE reason=? AND sender=?";
               let values = [ reason,
                              sender ];

               connection.execute(sql, values, function(row) {
                 // This will be 1 for existing records, 0 for non-existent ones
                 let count = row.getResultByName('cnt');
                 if (count == 0) {
                     DKIM[mailID] = { pass: false, 
                                      reason: reason,
                                      sender: sender };
                     updateNotification (mailID);
                 }
                 else {
                    // White-listed
                    // Update stats
                    stats.dkimWhitelist++;
                 }
               });
         } // if match 
    } // for
}

function isSPFsuccess(authResults, sender, mailID) {
    SPF[mailID] = { pass: true, 
                    reason: null,
                    sender: sender };

    for (let i in authResults) {
        let item = authResults[i];
        let match = item.match (/^([^\s]+)/);
        if ( (match) && 
             (match[1].toLowerCase() != 'pass') &&
             (match[1].toLowerCase() != 'neutral') &&
             (match[1].toLowerCase() != 'none') ) {
               // Update stats
               stats.spfViolation++;

               // Try to extract reason but this is not foolproof
               let match = item.match (/^[^\s]+ \((.*?)\)/ );
               let reason = null;
               if (match) {
                   reason=match[1];
               }

               // Check if previously white-listed
               let sql = "SELECT COUNT(id) as cnt FROM spfWhiteList " +
                         "WHERE reason=? AND sender=?";
               let values = [ reason,
                              sender ];

               connection.execute(sql, values, function(row) {
                 // This will be 1 for existing records, 0 for non-existent ones
                 let count = row.getResultByName('cnt');
                 if (count == 0) {
                     SPF[mailID] = { pass: false, 
                                     reason: reason,
                                     sender: sender };
                     updateNotification (mailID);
                 }
                 else {
                    // White-listed
                    // Update stats
                    stats.spfWhitelist++;
                 }
               });
         }
    }
}

function pluginMain() {
    // Use the document URL as a unique email identifier 
    var mailID = document.getElementById("messagepane").contentDocument.URL;

    currentMailID = mailID;

    // Initialize DNSBL
    DNSBL[mailID] = [];

    // Initialize totalDNSlookups
    if (!totalDNSlookups[mailID]) {
        totalDNSlookups[mailID] = 0;
    }
    updateDNSBLinfo(mailID);

    if (!gFolderDisplay) {
      return
    }

    let msgHdr = gFolderDisplay.selectedMessage;

    if (!msgHdr) {
      return
    }
 
    MsgHdrToMimeMessage(msgHdr, null, function (aMsgHdr, aMimeMsg) {
       // Update counters
      stats.inspectTotal++;
			 
      var relay = null;
      var relays = [];
      var addr;
      var numDNSLookups = 0;
      var temp = 0;

      // Return-Path should exist in all messages per RFC but it doesn't
      // See Issue #13 on GitHub
      if ('return-path' in aMimeMsg.headers) {
          // This comes back as an array, we want it as string
          // Some odd instances return multiple 'return-path's separated by comma 
          var returnPath =  aMimeMsg.headers['return-path'].join().split(',')[0];
      }
      else {
          var returnPath =  aMimeMsg.headers['from'].join().split(',')[0];;
      }

      // Addresses show up as sender@example.com, <sender@example.com> or Sender <sender@example.com>
      // We need to normalize it
      let match = returnPath.match(/<([^>]+)>/);
      if (match) {
          returnPath = match[1];
      }

      // We will inspect the Authentication-Results header for DKIM 
      let authResults = aMimeMsg.headers['authentication-results'];
      if (authResults) {
          let authResultsArray = parseAuthResults(authResults);

          // Updates DKIM[mailID]
          isDKIMsuccess(authResultsArray, returnPath, mailID);
      } else {
          DKIM[mailID] = { pass: true, reason: null, sender: null };
      }
   
      // We will inspect the Received-SPF header for SPF
      let receivedSpfArray = aMimeMsg.headers['received-spf'];
      if (receivedSpfArray) {
          // Updates SPF[mailID]
          isSPFsuccess(receivedSpfArray, returnPath, mailID);
      } else {
          SPF[mailID] = { pass: true, reason: null, sender: null };
      }

      let DnsService = Components.classes["@mozilla.org/network/dns-service;1"]
                      .createInstance(Components.interfaces.nsIDNSService);

      let Thread = Components.classes["@mozilla.org/thread-manager;1"]
                  .getService(Components.interfaces.nsIThreadManager).currentThread;

      let Listener = {
          onLookupComplete: function(request, record, status) {
             numDNSLookups--;

             totalDNSlookups[mailID]--;
             updateDNSBLinfo(mailID);

             if (Components.isSuccessCode(status)) {
                while ( record && record.hasMore() ) {
                    addr = record.getNextAddrAsString();
                    if ( /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.exec (addr) ) {
                        if ( relays.indexOf (addr) == -1 ) {
                            if ( !isReserved(addr) ) { 
                                relays.push (addr);
                            }
                        }
                    }
                }
             }
             else {
                // DNS Lookup Error
             }

             if (numDNSLookups == 0) {
                 doDNSBLchecks (relays, returnPath, mailID);
             }
          }
      };

      for (var item in aMimeMsg.headers["received"]) {
         if ( relay = parseReceivedLine (aMimeMsg.headers["received"][item]) ) {
             if ( relay.indexOf(':') != -1 ) {
                 // IPv6 - Not supported 
             }
             else if ( /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.exec (relay) ) {
                 if ( relays.indexOf (relay) == -1 ) {
                     if ( !isReserved(relay) ) { 
                         relays.push ( relay );
                     }
                 }
             }
             else {
                 numDNSLookups++;

                 totalDNSlookups[mailID]++;
                 updateDNSBLinfo(mailID);

                 DnsService.asyncResolve(relay, DnsService.RESOLVE_DISABLE_IPV6, Listener, Thread);
             }
         }
      }

      if (numDNSLookups == 0) {
          doDNSBLchecks (relays, returnPath, mailID);
      }
   }, true);
}
