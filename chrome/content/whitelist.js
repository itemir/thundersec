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

function updateWhitelistTable(whitelist) {
   var html = "<div style='width: 660px; height: 450px; overflow: scroll;'>";
   
   if (whitelist.length) {
       html = html + "<table style='width: 100%; padding-top: 10px;'>";
       html = html + "<tr><td style='font-weight: bold;'>IP Address</td>" +
                     "<td style='font-weight: bold;'>Service</td>" +
                     "<td style='font-weight: bold;'>Code</td>" + 
                     "<td style='font-weight: bold;'>Sender</td></tr>";
    
       for (var i in whitelist) {
           let ip = whitelist[i].ip; 
           let source = whitelist[i].source; 
           let code = whitelist[i].code; 
           let sender = whitelist[i].sender; 
           // Easy way of escaping with jQuery
           sender = $('<span/>').text(sender).html();
    
           html = html + "<tr><td style='padding: 5px;'>" + ip + 
                         "</td><td style='padding: 5px;'>" + source + 
                         "</td><td style='padding: 5px;'>" + code + 
                         "</td><td style='padding: 5px;'>" + sender + 
                         "</td></tr>";
       }   

       html = html + "</table>";
   } else {
       html = html + "<div style='text-align: center; padding-top: 60px; font-size: 14pt;'>";
       html = html + "Your whitelist is currently empty.";
       html = html + "</div>";
   }

   html = html + "</div>";

   var container = document.getElementById("whitelistBox");
   var divHTML = document.createElementNS("http://www.w3.org/1999/xhtml","div");

   divHTML.innerHTML = html;

   container.appendChild(divHTML);
}

function queryWhitelist(conn) {
   var whiteList = [];

   conn.tableExists("WhiteList").then(
       function (exists) {
           let sql = 'SELECT * FROM WhiteList';
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
                  updateWhitelistTable(whiteList);
                  conn.close();
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
           queryWhitelist(conn);
       }, 
       function onError(error) {
           alert ('Connection failed: ' + error);
       }
   );
}
