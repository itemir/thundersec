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

// Clear input on click if it is the same value
function clearInput() {
   var textField = document.getElementById("string.custom_dnsbl");
   if (textField.value == "dnsbl.example.com") {
       alert ('You can enter your DNSBL servers of choice.\n\n' +
              'If you want to add multiple sources, separate them with comma or space.\n\n' +
              'Example: dnsbl.domain1.com, rbl.domain2.com');
       document.getElementById("string.custom_dnsbl").value = "";
   }
}

// Enables and disables DNSBL entry box based on checkbox
function enableCustomDNSBL(item) {
   var textField = document.getElementById("string.custom_dnsbl");
   // .checked is updated after this event fires, so actions are pro-active
   if (item.checked) {
       document.getElementById("string.custom_dnsbl").setAttribute("disabled", true);
   }
   else {
       document.getElementById("string.custom_dnsbl").removeAttribute("disabled");
   } 
}

// Brings in whitelist popup
function viewWhitelist() {
    var features = "chrome, dialog, centerscreen, scrollbars";
    window.openDialog("chrome://thundersec/content/whitelist.xul", "Whitelist", features);
}

// Clears the whitelist
function clearWhitelist() {
  if ( window.confirm ('Your whitelist will be cleared. Are you sure?') ){
      Components.utils.import("resource://gre/modules/Sqlite.jsm");
      Sqlite.openConnection(
          { path: DB_NAME }
      ).then(
          function onConnection(conn) {
              conn.execute("BEGIN IMMEDIATE TRANSACTION");
              conn.execute ("DELETE FROM dnsblWhiteList;");
              conn.execute ("DELETE FROM spfWhiteList;");
              conn.execute ("DELETE FROM dkimWhiteList;");
              conn.execute("COMMIT TRANSACTION");
              conn.close();
          }
      );
  }
}
