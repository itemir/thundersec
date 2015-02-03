/*
    DNSBL/RBL Add-on for Mozilla Thunderbird
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
var RBLNotes = {};
var totalDNSlookups = {};
var currentMailID;

var messagepane = document.getElementById("messagepane");
messagepane.addEventListener('load', function () {
  pluginMain();
}, true);

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

function detailsBox(notf, desc) {
    var params = { notes: RBLNotes[currentMailID] };
    window.openDialog("chrome://dnsbl/content/details.xul", "", "chrome, dialog, centerscreen, resizable=no", params);
    throw new Error('Preventing notification bar from closing.');
}

function optionsBox(notf, desc) {
    var features = "chrome,titlebar,toolbar,centerscreen,dialog=yes";
    window.openDialog("chrome://dnsbl/content/options.xul", "Preferences", features);
    throw new Error('Preventing notification bar from closing.');
}

function aboutBox(notf, desc) {
    var features = "chrome,titlebar,toolbar,centerscreen,dialog=yes";
    window.openDialog("chrome://dnsbl/content/about.xul", "Preferences", features);
    throw new Error('Preventing notification bar from closing.');
}

function updateNotification(notes, mailID) {
   if (mailID != currentMailID) { 
       // User has moved on, don't updae the notificationbox
       return;
   }

   var buttons = [
     {
       label: 'Details',
       accessKey: 'B',
       popup: null,
       callback: detailsBox
     },
     {
       label: 'Preferences',
       accessKey: 'P',
       popup: null,
       callback: optionsBox
     },
     {
       label: 'About',
       accessKey: 'A',
       popup: null,
       callback: aboutBox
     },
   ];

   let notificationBox = document.getElementById("msgNotificationBar");
   if ( notificationBox.getNotificationWithValue( 'rbl' ) ) {
       notificationBox.removeCurrentNotification();
   }

   var notificationText;
   if (notes.length == 1) { 
       notificationText = "1 RBL failure.";
   }
   else {
       notificationText = notes.length + " RBL failures.";
   }
   notificationText = notificationText + " Please check Details for more information."

   notificationBox.appendNotification(notificationText,
                                      "rbl",
                                      null,
                                      10,
                                      buttons);
}

function updateRBLinfo(mailID) {
    if (mailID != currentMailID) {
        // User has moved on, don't updae the notificationbox
        return;
    }
    var numLookups = totalDNSlookups[mailID]

    var rblInfo = document.getElementById("rblInfo");
    var imgSpinner = document.getElementById("imgSpinner");
    var label;

    if (numLookups != 0) { 
        label = "Number of outstanding RBL lookups: " + numLookups;
        imgSpinner.hidden = false;
    }
    else {
        label = "";
        imgSpinner.hidden = true;
    }
    rblInfo.label = label;
}
    
function doRBLcheck(relays, rblService, mailID) {
    var match;
    var reverseAddr;
    var numDNSLookups = 0;
    var safeMail = true;

    let DnsService = Components.classes["@mozilla.org/network/dns-service;1"]
                     .createInstance(Components.interfaces.nsIDNSService);

    let Thread = Components.classes["@mozilla.org/thread-manager;1"]
                 .getService(Components.interfaces.nsIThreadManager).currentThread;

    for (var i in relays) {
        let rblQuery;
        let addr;
        let resolvedAddr;

        let Listener = {
             onLookupComplete: function(request, record, status) {
               numDNSLookups--;

               totalDNSlookups[mailID]--;
               updateRBLinfo(mailID);

               if (Components.isSuccessCode(status)) {
                   while ( record && record.hasMore() ) {
                       resolvedAddr = record.getNextAddrAsString();
                       RBLNotes[mailID].push ( { ip: addr, service: rblService, code: resolvedAddr } );
                       safeMail = false;
                   }
               }
               else {
                   // RBL safe
               }

               if (numDNSLookups == 0) {
                   if (safeMail) {
                       // Pass
                   }
                   else {
                       updateNotification (RBLNotes[currentMailID], mailID)
                   }
               }
            }
        };

        addr = relays[i];

        match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec (addr);
        if (match) {
           reverseAddr = match[4] + "." + match[3] + "." + match[2] + "." + match[1];
           rblQuery = reverseAddr + "." + rblService;

           numDNSLookups++;

           totalDNSlookups[mailID]++;
           updateRBLinfo(mailID);

           DnsService.asyncResolve(rblQuery, 0, Listener, Thread);
       
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

// Perform all RBL checks by calling doRBLcheck iteratively
function doRBLchecks(relays, mailID) {
    var rblServices = [ 'zen.spamhaus.org',
			'b.barracudacentral.org',
                        'dnsbl.abuse.ch',
                        'cbl.abuseat.org',
                        'ubl.unsubscore.com',
		        'bl.spamcop.net',
		        'dnsbl.sorbs.net' ];

    var pref = Components.classes["@mozilla.org/preferences-service;1"]
                         .getService(Components.interfaces.nsIPrefService)
                         .getBranch("extensions.dnsbl.");

    // Do this for each of the RBL services
    for (var i in rblServices) {
        // Check if enabled in preferences
        if ( pref.getBoolPref(rblServices[i]) ){
            doRBLcheck (relays, rblServices[i], mailID);
        }
    }

    // Process Custom RBL if it is enabled
    if ( pref.getBoolPref('custom_rbl_enabled') && pref.getCharPref('custom_rbl') ) {
        var customRBLs = pref.getCharPref('custom_rbl').split(/\s*\,\s*|\s+/);
        for (var i in customRBLs) {
            doRBLcheck (relays, customRBLs[i], mailID);
        }
    }

}

function pluginMain() {
    // Use the document URL as a unique email identifier 
    var mailID = document.getElementById("messagepane").contentDocument.URL
    currentMailID = mailID;
			 
    // Initialize RBLNotes
    RBLNotes[mailID] = [];

    // Initialize totalDNSlookups
    if (!totalDNSlookups[mailID]) {
        totalDNSlookups[mailID] = 0;
    }
    updateRBLinfo(mailID);

    let msgHdr = gFolderDisplay.selectedMessage;
    MsgHdrToMimeMessage(msgHdr, null, function (aMsgHdr, aMimeMsg) {
      var relay = null;
      var relays = [];
      var addr;
      var numDNSLookups = 0;
      var temp = 0;

      let DnsService = Components.classes["@mozilla.org/network/dns-service;1"]
                      .createInstance(Components.interfaces.nsIDNSService);

      let Thread = Components.classes["@mozilla.org/thread-manager;1"]
                  .getService(Components.interfaces.nsIThreadManager).currentThread;

      let Listener = {
          onLookupComplete: function(request, record, status) {
             numDNSLookups--;

             totalDNSlookups[mailID]--;
             updateRBLinfo(mailID);

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
                 doRBLchecks (relays, mailID);
             }
          }
      };

      for (var item in aMimeMsg.headers["received"]) {
         if ( relay = parseReceivedLine (aMimeMsg.headers["received"][item]) ) {
             if ( /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.exec (relay) ) {
                 if ( relays.indexOf (relay) == -1 ) {
                     if ( !isReserved(relay) ) { 
                         relays.push ( relay );
                     }
                 }
             }
             else {
                 numDNSLookups++;

                 totalDNSlookups[mailID]++;
                 updateRBLinfo(mailID);

                 DnsService.asyncResolve(relay, DnsService.RESOLVE_DISABLE_IPV6, Listener, Thread);
             }
         }
      }

      if (numDNSLookups == 0) {
          doRBLchecks (relays, mailID);
      }
   }, true);
}
