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

function sanitizeInput (inputText) {
    // Easy way of escaping with jQuery
   let returnText = $('<span/>').text(inputText).html();
   return (returnText);
}

function updateDnsblWhitelist(whitelist) {
   var html = "<div style='width: 500px; height: 350px; overflow: scroll; margin: auto;'>";
   
   if (whitelist.length) {
       html = html + "<table style='width: 100%; padding-top: 10px;'>";
       html = html + "<tr><td style='font-weight: bold;'>IP Address</td>" +
                     "<td style='font-weight: bold;'>Service</td>" +
                     "<td style='font-weight: bold;'>Code</td>" + 
                     "<td style='font-weight: bold;'>Sender</td></tr>";
    
       for (var i in whitelist) {
           let ip = sanitizeInput (whitelist[i].ip); 
           let source = sanitizeInput (whitelist[i].source); 
           let code = sanitizeInput (whitelist[i].code); 
           let sender = sanitizeInput (whitelist[i].sender); 
    
           html = html + "<tr><td style='padding: 5px;'>" + ip + 
                         "</td><td style='padding: 5px;'>" + source + 
                         "</td><td style='padding: 5px;'>" + code + 
                         "</td><td style='padding: 5px;'>" + sender + 
                         "</td></tr>";
       }   

       html = html + "</table>";
   } else {
       html = html + "<p style='text-align: center; padding-top: 60px; font-size: 10pt;'>";
       html = html + "DNSBL whitelist is empty";
       html = html + "</p>";
   }

   html = html + "</div>";

   var container = document.getElementById("dnsblWhitelistBox");
   var divHTML = document.createElementNS("http://www.w3.org/1999/xhtml","div");

   // Updating innerHTML dynamically causes security warnings in Mozilla Add-on validator 
   // If you are here for such warning, please review above how this value is generated
   // 'html' is a combination of safe static html and sanitized input
   divHTML.innerHTML = html;

   container.appendChild(divHTML);
}

function queryDnsblWhitelist(conn) {
   var whiteList = [];

   conn.tableExists("dnsblWhiteList").then(
       function (exists) {
           let sql = 'SELECT * FROM dnsblWhiteList';
           conn.execute (sql, null, function(row) {
              let ip = row.getResultByName('ipAddress');
              let source = row.getResultByName('dnsblSource');
              let code = row.getResultByName('code');
              let sender = row.getResultByName('sender');

              whiteList.push ( { ip: ip,
                                 source: source,
                                 code: code,
                                 sender: sender } );
           }).then(
              function onStatementComplete(result) {
                  if (whiteList.length) {
                      document.getElementById("dnsblTab").label = "DNSBL (" + whiteList.length + ")";
                  }
                  updateDnsblWhitelist(whiteList);
              },
              function onError(err) {
                  alert ('SQL query failed: ' + err);
              }
           );
       }
   );
}

function updateSpfWhitelist(whitelist) {
   var html = "<div style='width: 500px; height: 350px; overflow: scroll; margin: auto;'>";
   
   if (whitelist.length) {
       html = html + "<table style='width: 100%; padding-top: 10px;'>";
       html = html + "<tr><td style='font-weight: bold;'>Reason</td>" +
                     "<td style='font-weight: bold;'>Sender</td></tr>";
    
       for (var i in whitelist) {
           let reason = sanitizeInput (whitelist[i].reason); 
           let sender = sanitizeInput (whitelist[i].sender); 
    
           html = html + "<tr><td style='padding: 5px;'>" + reason + 
                         "</td><td style='padding: 5px;'>" + sender + 
                         "</td></tr>";
       }   

       html = html + "</table>";
   } else {
       html = html + "<p style='text-align: center; padding-top: 60px; font-size: 10pt;'>";
       html = html + "SPF whitelist is empty";
       html = html + "</p>";
   }

   html = html + "</div>";

   var container = document.getElementById("spfWhitelistBox");
   var divHTML = document.createElementNS("http://www.w3.org/1999/xhtml","div");

   // Updating innerHTML dynamically causes security warnings in Mozilla Add-on validator 
   // If you are here for such warning, please review above how this value is generated
   // 'html' is a combination of safe static html and sanitized input
   divHTML.innerHTML = html;

   container.appendChild(divHTML);
}

function querySpfWhitelist(conn) {
   var whiteList = [];

   conn.tableExists("spfWhiteList").then(
       function (exists) {
           let sql = 'SELECT * FROM spfWhiteList';
           conn.execute (sql, null, function(row) {
              let reason = row.getResultByName('reason');
              let sender = row.getResultByName('sender');

              whiteList.push ( { reason: reason,
                                 sender: sender } );
           }).then(
              function onStatementComplete(result) {
                  if (whiteList.length) {
                      document.getElementById("spfTab").label = "SPF (" + whiteList.length + ")";
                  }
                  updateSpfWhitelist(whiteList);
              },
              function onError(err) {
                  alert ('SQL query failed: ' + err);
              }
           );
       }
   );
}


function updateDkimWhitelist(whitelist) {
   var html = "<div style='width: 500px; height: 350px; overflow: scroll; margin: auto;'>";
   
   if (whitelist.length) {
       html = html + "<table style='width: 100%; padding-top: 10px;'>";
       html = html + "<tr><td style='font-weight: bold;'>Reason</td>" +
                     "<td style='font-weight: bold;'>Sender</td></tr>";
    
       for (var i in whitelist) {
           let reason = sanitizeInput (whitelist[i].reason); 
           let sender = sanitizeInput (whitelist[i].sender); 
    
           html = html + "<tr><td style='padding: 5px;'>" + reason + 
                         "</td><td style='padding: 5px;'>" + sender + 
                         "</td></tr>";
       }   

       html = html + "</table>";
   } else {
       html = html + "<p style='text-align: center; padding-top: 60px; font-size: 10pt;'>";
       html = html + "DKIM whitelist is empty";
       html = html + "</p>";
   }

   html = html + "</div>";

   var container = document.getElementById("dkimWhitelistBox");
   var divHTML = document.createElementNS("http://www.w3.org/1999/xhtml","div");

   // Updating innerHTML dynamically causes security warnings in Mozilla Add-on validator 
   // If you are here for such warning, please review above how this value is generated
   // 'html' is a combination of safe static html and sanitized input
   divHTML.innerHTML = html;

   container.appendChild(divHTML);
}

function queryDkimWhitelist(conn) {
   var whiteList = [];

   conn.tableExists("dkimWhiteList").then(
       function (exists) {
           let sql = 'SELECT * FROM dkimWhiteList';
           conn.execute (sql, null, function(row) {
              let reason = row.getResultByName('reason');
              let sender = row.getResultByName('sender');

              whiteList.push ( { reason: reason,
                                 sender: sender } );
           }).then(
              function onStatementComplete(result) {
                  if (whiteList.length) {
                      document.getElementById("dkimTab").label = "DKIM (" + whiteList.length + ")";
                  }
                  updateDkimWhitelist(whiteList);
              },
              function onError(err) {
                  alert ('SQL query failed: ' + err);
              }
           );
       }
   );
}

function viewWhitelist() {
   Components.utils.import("resource://gre/modules/Sqlite.jsm");
   Sqlite.openConnection(
       { path: DB_NAME }
   ).then(
       function onConnection(conn) {
           queryDnsblWhitelist(conn);
           querySpfWhitelist(conn);
           queryDkimWhitelist(conn);
           // Give a second then close the connection
           // There should be a better way to do it 
           setTimeout (function() {
               conn.close();
           }, 1000);
       }, 
       function onError(error) {
           alert ('Connection failed: ' + error);
       }
   );
}
