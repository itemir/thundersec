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

function updateDNSBLtab(dnsbl) {
   var ip;
   var code;
   var ipLink;
   var codeLink;

   if ( dnsbl.length > 0 ) {
       document.getElementById("dnsblTab").label = "DNSBL (" + dnsbl.length + ")";
       document.getElementById("detailsTabs").selectedIndex = 0;
   }

   var html = "<div style='width: 420px; font-size: 10pt; text-align: center; padding: 20px; -moz-user-select: text;'>";
   if (dnsbl.length > 0) {
       html = html + "<span style='font-size: 12pt; color: #9a0000; font-weight: bold;'>";
       if (dnsbl.length == 1) {
           html = html + dnsbl.length + " DNSBL violation";
       }
       else {
           html = html + dnsbl.length + " DNSBL violations";
       }
       html = html + "</span>";
       html = html + "<table style='width: 400px; padding-top: 10px;'>";
       html = html + "<tr><td style='font-weight: bold;'>IP Address</td><td style='font-weight: bold;'>Return Code</td><td style='font-weight: bold;'>Service</td></tr>";
       for (var i in dnsbl) {
           ip = sanitizeInput (dnsbl[i].ip);
           code = sanitizeInput (dnsbl[i].code);
           service = sanitizeInput (dnsbl[i].service);
           html = html + "<tr><td>" + ip + "</td><td>" + code + "</td><td>" + service + "</td></tr>";
       }   
       html = html + "</table>";
   }
   else {
       html = html + "<p>No DNSBL violations.</p>";
   }
   html = html + "</div>";

   let container = document.getElementById("dnsblBox");
   let divHTML = document.createElementNS("http://www.w3.org/1999/xhtml","div");

   // Updating innerHTML dynamically causes security warnings in Mozilla Add-on validator
   // If you are here for such warning, please review above how this value is generated
   // 'html' is a combination of safe static html and sanitized input 
   divHTML.innerHTML = html;

   container.appendChild(divHTML);
}

function updateSPFtab(spf) {
   if ( !spf.pass ) {
       document.getElementById("spfTab").label = "SPF (1)";
       document.getElementById("detailsTabs").selectedIndex = 1;
   }

   var html = "<div style='width: 420px; font-size: 10pt; text-align: center; padding: 20px; -moz-user-select: text;'>";
   if (spf.pass) {
     html = html + "<p>No SPF failures</p>";
   } 
   else {
     html = html + "<p style='font-size: 12pt; color: #9a0000; font-weight: bold;'>SPF Failure</p>";
     if (spf.reason) {
        let reason = sanitizeInput (spf.reason);
        html = html + "<p style='font-style: italic;'>" + reason + "</p>";
     }
     else {
        html = html + "<p>No explicit reason identified, please manually inspect e-mail headers.</p>";
     }
   }
   html = html + "</div>";

   let container = document.getElementById("spfBox");
   let divHTML = document.createElementNS("http://www.w3.org/1999/xhtml","div");


   // Updating innerHTML dynamically causes security warnings in Mozilla Add-on validator 
   // If you are here for such warning, please review above how this value is generated
   // 'html' is a combination of safe static html and sanitized input
   divHTML.innerHTML = html;

   container.appendChild(divHTML);
}

function updateDKIMtab(dkim) {
   if ( !dkim.pass ) {
       document.getElementById("dkimTab").label = "DKIM (1)";
       document.getElementById("detailsTabs").selectedIndex = 2;
   }

   var html = "<div style='width: 420px; font-size: 10pt; text-align: center; padding: 20px; -moz-user-select: text;'>";
   if (dkim.pass) {
     html = html + "<p>No DKIM failures</p>";
   } 
   else {
     html = html + "<p style='font-size: 12pt; color: #9a0000; font-weight: bold;'>DKIM Failure</p>";
     if (dkim.reason) {
        let reason = sanitizeInput (dkim.reason);
        html = html + "<p style='font-style: italic;'>" + reason + "</p>";
     }
     else {
        html = html + "<p>No explicit reason identified, please manually inspect e-mail headers.</p>";
     }
   }
   html = html + "</div>";

   let container = document.getElementById("dkimBox");
   let divHTML = document.createElementNS("http://www.w3.org/1999/xhtml","div");

   // Updating innerHTML dynamically causes security warnings in Mozilla Add-on validator 
   // If you are here for such warning, please review above how this value is generated
   // 'html' is a combination of safe static html and sanitized input
   divHTML.innerHTML = html;

   container.appendChild(divHTML);
}

function updateDetails() {
   var DNSBL = window.arguments[0].dnsbl;
   var SPF = window.arguments[0].spf;
   var DKIM = window.arguments[0].dkim;

   // Reverse order defines the selected tab if multiple are active
   updateDKIMtab(DKIM);
   updateSPFtab(SPF);
   updateDNSBLtab(DNSBL);
}
