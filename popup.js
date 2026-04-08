document.getElementById("settingsBtn").addEventListener("click",function(){chrome.runtime.openOptionsPage();window.close();});

var ALL=["virustotal","abuseipdb","otx","threatfox","malwarebazaar","pulsedive","opencti","recordedfuture","ipinfo","spur","shodan","censys","zoomeye","greynoise","spamhaus","urlscan","wayback","dnsdumpster","validin","mxtoolbox","whois","github","leakcheck","torarchive","nvd","mitre_cve","exploitdb","ms_eventid","ms_errorcode"];

var API_SERVICES={"virustotal":"vt_key","abuseipdb":"abuseipdb_key","opencti":"opencti_token","recordedfuture":"rf_token","spur":"spur_token","dnsdumpster":"dnsdumpster_key","validin":"validin_key","urlscan":"urlscan_key","leakcheck":"leakcheck_key"};

chrome.storage.sync.get(["cc_config"],function(result){
  var cfg=(result&&result.cc_config)?result.cc_config:{};

  var enabled=ALL.filter(function(id){return cfg["enabled_"+id]!==false;}).length;
  var apiConfigured=0;
  var apiKeys=Object.keys(API_SERVICES);
  apiKeys.forEach(function(svc){
    var key=API_SERVICES[svc];
    if(cfg[key]&&String(cfg[key]).trim()!=="")apiConfigured++;
  });

  var html='<div class="stat-row"><span>Services enabled</span><span class="stat-val">'+enabled+' / '+ALL.length+'</span></div>';
  html+='<div class="stat-row"><span>API integrations configured</span><span class="stat-val'+(apiConfigured>0?' green':'')+'">'+apiConfigured+' / '+apiKeys.length+'</span></div>';
  document.getElementById("stats").innerHTML=html;
});

var manifest=chrome.runtime.getManifest();
document.getElementById("version").textContent="v"+manifest.version;
