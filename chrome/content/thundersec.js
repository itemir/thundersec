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
var totalDNSlookups = {};
var currentMailID;
var connection;
var initialized = false;

if ( !initialized) {
    initialized = true; 
    initialize();
}

function initialize() {
    // Add event listener
    var messagepane = document.getElementById("messagepane");
    messagepane.addEventListener('load', function () {
      pluginMain();
    }, true);

    // Check new version now (in a minute) and then every day
    setTimeout (apiCheckVersion, 60*1000); 
    setInterval (apiCheckVersion, 24*60*60*1000);
  
    if (!connection) {
        Components.utils.import("resource://gre/modules/Sqlite.jsm");
        Sqlite.openConnection(
            { path: DB_NAME }
        ).then(
            function onConnection(conn) {
               conn.tableExists("WhiteList").then(
                   function (exists) {
                       if (!exists) {
                           // This means, database has just been created. Create the table.
                           createTable (conn);
                       }
                       // Set the global variable
                       connection = conn;
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
                window.open (HOME_URL,'','chrome,centerscreen');
            }
        }
    }, 'json');
}

// Notify the API for crowd-sourced improvements
// This should not send any sensitive information back
function apiSendStats (ip, code, source) {
    var pref = Components.classes["@mozilla.org/preferences-service;1"]
                     .getService(Components.interfaces.nsIPrefService)
                     .getBranch("extensions.thundersec.");

    // Check if API usage is allowed in preferences
    if ( pref.getBoolPref('api_enabled') ) {
        // We will hash the sender for privacy
        // We use SHA256 hash, it is a way one way hash (i.e. you cannnot go back from hash to email)
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
        $.post( API_URL + 'dnsbl/whitelist',
               { 'ip': ip,
                 'code': code,
                 'dnsbl': source,
                 'senderHash': Sha256.hash (sender),
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

function createTable(connection) {
    var sql = 
    sql = " CREATE TABLE 'WhiteList' ( " +
          "       'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," +
    	  "	  'ipAddress'	TEXT NOT NULL," +
	  " 	  'dnsblSource'	TEXT NOT NULL," +
	  " 	  'code'	TEXT NOT NULL," +
	  "	  'sender'	TEXT NOT NULL," +
          "       UNIQUE(ipAddress, dnsblSource, code, sender) ); ";

    connection.execute (sql);
}

function updateWhiteList(dnsblNotes) {
    connection.execute("BEGIN IMMEDIATE TRANSACTION");
    for (var i in dnsblNotes) {
        let dnsblNote = dnsblNotes[i];
        let values = [ dnsblNote.ip,
                       dnsblNote.service, 
                       dnsblNote.code,
                       dnsblNote.sender ];
        let sql = "INSERT OR IGNORE INTO WhiteList " +
                  "('ipAddress', 'dnsblSource', 'code', 'sender') " +
                  "VALUES (?, ?, ?, ?)";
        connection.execute(sql, values);

        // Notify the API for crowd-sourced improvements
        apiSendWhiteList(dnsblNote.ip, 
                         dnsblNote.code,
                         dnsblNote.service,
                         dnsblNote.sender);
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
        updateWhiteList( DNSBL[currentMailID] );
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

   let notificationText = '';

   if ( DNSBL[currentMailID].length == 1 ) { 
       notificationText = notificationText + "DNSBL failure. ";
   }
   else if ( DNSBL[currentMailID].length > 1 ) {
       notificationText = notificationText + "Multiple DNSBL failures. ";
   }

   if ( !SPF[currentMailID].pass ) {
      notificationText = notificationText + "SPF failure. ";
   }

   if ( !DKIM[currentMailID].pass ) {
      notificationText = notificationText + "DKIM failure. ";
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
                       resolvedAddr = record.getNextAddrAsString();
                       // This query HAS TO return only a single row
                       let sql = "SELECT COUNT(id) as cnt FROM WhiteList " +
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
                               apiSendStats (addr, resolvedAddr, dnsblService);
                               safeMail = false;
                           } else {
                               // Previously white listed
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

function isDKIMsuccess(authResults) {
    for (let i in authResults) {
        let item = authResults[i];
        let match = item.match (/dkim=([^\s]+)/);
        if ( (match) && 
             (match[1] != 'pass') &&
             (match[1] != 'none') ) {
               // Try to extract reason but this is not foolproof
               let match = item.match (/dkim=[^\s]+ \((.*?)\)/ );
               let reason = '';
               if (match) {
                   reason=match[1];
               }
               return ( { pass: false, reason: reason } );
         }
    }
    return ( { pass: true, reason: null } );
}

function isSPFsuccess(authResults) {
    for (let i in authResults) {
        let item = authResults[i];
        let match = item.match (/spf=([^\s]+)/);
        if ( (match) && 
             (match[1] != 'pass') &&
             (match[1] != 'neutral') &&
             (match[1] != 'none') ) {
               // Try to extract reason but this is not foolproof
               let match = item.match (/spf=[^\s]+ \((.*?)\)/ );
               let reason = '';
               if (match) {
                   reason=match[1];
               }
               return ( { pass: false, reason: reason } );
         }
    }
    return ( { pass: true, reason: null } );
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

    let msgHdr = gFolderDisplay.selectedMessage;
    MsgHdrToMimeMessage(msgHdr, null, function (aMsgHdr, aMimeMsg) {
      var relay = null;
      var relays = [];
      var addr;
      var numDNSLookups = 0;
      var temp = 0;

      // This comes back as an array, we want it as string
      // Some odd instances return multiple 'return-path's separated by comma 
      var returnPath =  aMimeMsg.headers['return-path'].join().split(',')[0];

      // We will inspect the Authentication-Results header for DKIM and SPF
      let authResults = aMimeMsg.headers['authentication-results'];
      if (authResults) {
          let authResultsArray = parseAuthResults(authResults);
          DKIM[mailID] = isDKIMsuccess(authResultsArray);
          SPF[mailID] = isSPFsuccess(authResultsArray);
          if ( !DKIM[mailID].pass || !SPF[mailID].pass ) {
              updateNotification (mailID);
          }
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
