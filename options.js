var SERVICES=[
  {id:"virustotal",name:"VirusTotal",cat:"Threat Intel",types:["IP","Domain","Hash","URL","Email"],color:"#394eff",needsApi:false,fields:[{key:"vt_key",label:"API Key (optional - enables auto-check)",ph:"Your VirusTotal API key"},{key:"vt_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"abuseipdb",name:"AbuseIPDB",cat:"Threat Intel",types:["IP","Domain"],color:"#00b4d8",needsApi:false,fields:[{key:"abuseipdb_key",label:"API Key (optional - enables auto-check)",ph:"Your AbuseIPDB API key"},{key:"abuseipdb_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"otx",name:"AlienVault OTX",cat:"Threat Intel",types:["IP","Domain","Hash","URL"],color:"#7b68ee",needsApi:false},
  {id:"threatfox",name:"ThreatFox",cat:"Threat Intel",types:["Hash","IP"],color:"#ff6b35",needsApi:false},
  {id:"malwarebazaar",name:"MalwareBazaar",cat:"Threat Intel",types:["Hash"],color:"#e84393",needsApi:false},
  {id:"pulsedive",name:"Pulsedive",cat:"Threat Intel",types:["IP","Domain","URL"],color:"#1dd1a1",needsApi:false},
  {id:"opencti",name:"OpenCTI",cat:"Threat Intel",types:["All"],color:"#001bda",needsApi:true,fields:[{key:"opencti_url",label:"Instance URL",ph:"https://opencti.yourorg.com"},{key:"opencti_token",label:"API Token",ph:"Your OpenCTI token"},{key:"opencti_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"recordedfuture",name:"Recorded Future",cat:"Threat Intel",types:["All"],color:"#e63946",needsApi:true,fields:[{key:"rf_token",label:"API Token",ph:"RF token"},{key:"rf_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"ipinfo",name:"IPInfo",cat:"Network Intel",types:["IP"],color:"#0984e3",needsApi:false},
  {id:"spur",name:"Spur",cat:"Network Intel",types:["IP"],color:"#6c5ce7",needsApi:true,fields:[{key:"spur_token",label:"API Token",ph:"Your Spur API token"},{key:"spur_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"shodan",name:"Shodan",cat:"Network Intel",types:["IP"],color:"#d63031",needsApi:false},
  {id:"censys",name:"Censys",cat:"Network Intel",types:["IP"],color:"#0652DD",needsApi:false},
  {id:"zoomeye",name:"ZoomEye",cat:"Network Intel",types:["IP"],color:"#e17055",needsApi:false},
  {id:"greynoise",name:"GreyNoise",cat:"Network Intel",types:["IP"],color:"#00d2d3",needsApi:false},
  {id:"spamhaus",name:"Spamhaus",cat:"Network Intel",types:["IP","Domain"],color:"#c0392b",needsApi:false},
  {id:"urlscan",name:"URLScan.io",cat:"URL / Domain",types:["URL"],color:"#00cec9",needsApi:false,fields:[{key:"urlscan_key",label:"API Key (optional - enables auto-search)",ph:"Your URLScan API key"},{key:"urlscan_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"wayback",name:"Wayback Machine",cat:"URL / Domain",types:["URL","Domain"],color:"#636e72",needsApi:false},
  {id:"dnsdumpster",name:"DNSDumpster",cat:"URL / Domain",types:["Domain"],color:"#2d3436",needsApi:true,fields:[{key:"dnsdumpster_key",label:"API Key",ph:"Your DNSDumpster API key"},{key:"dnsdumpster_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"validin",name:"Validin",cat:"URL / Domain",types:["Domain","IP"],color:"#a29bfe",needsApi:true,fields:[{key:"validin_key",label:"API Key",ph:"Your Validin API key"},{key:"validin_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"mxtoolbox",name:"MXToolbox",cat:"URL / Domain",types:["Domain","Email"],color:"#f39c12",needsApi:false},
  {id:"whois",name:"WHOIS",cat:"URL / Domain",types:["Domain"],color:"#a29bfe",needsApi:false},
  {id:"github",name:"GitHub Code Search",cat:"Code & Leaks",types:["Hash","Domain","IP","Email"],color:"#8b949e",needsApi:false},
  {id:"leakcheck",name:"LeakCheck",cat:"Code & Leaks",types:["Email"],color:"#fd79a8",needsApi:true,fields:[{key:"leakcheck_key",label:"API Key",ph:"Your LeakCheck API key"},{key:"leakcheck_autocheck",label:"Auto-check on select",type:"checkbox",ph:""}]},
  {id:"torarchive",name:"TOR Archive",cat:"Network Intel",types:["IP"],color:"#7f5af0",needsApi:false},
  {id:"nvd",name:"NVD (NIST)",cat:"Vulnerability",types:["CVE"],color:"#2ecc71",needsApi:false},
  {id:"mitre_cve",name:"MITRE CVE",cat:"Vulnerability",types:["CVE"],color:"#e67e22",needsApi:false},
  {id:"exploitdb",name:"Exploit-DB",cat:"Vulnerability",types:["CVE"],color:"#c0392b",needsApi:false},
  {id:"ms_eventid",name:"MS Docs (Event ID)",cat:"Documentation",types:["Event ID"],color:"#0078d4",needsApi:false},
  {id:"ms_errorcode",name:"MS Docs (Error Code)",cat:"Documentation",types:["Error Code"],color:"#0078d4",needsApi:false}
];
var config={};
function save(){chrome.storage.sync.set({cc_config:config},function(){var t=document.getElementById("toast");t.classList.add("show");setTimeout(function(){t.classList.remove("show");},1400);});}
function render(){
  var c=document.getElementById("services");c.innerHTML="";var seen={},cats=[];
  SERVICES.forEach(function(s){if(!seen[s.cat]){seen[s.cat]=true;cats.push(s.cat);}});
  cats.forEach(function(cat){
    var cd=document.createElement("div");cd.className="cat";
    var t=document.createElement("div");t.className="cat-title";t.innerHTML="<span>"+cat+"</span>";cd.appendChild(t);
    SERVICES.filter(function(s){return s.cat===cat;}).forEach(function(svc){
      var card=document.createElement("div");card.className="svc";
      var isOn=config["enabled_"+svc.id]!==false;
      var types=svc.types.map(function(t){return '<span class="svc-type">'+t+"</span>";}).join("");
      var badge=svc.needsApi?'<span class="badge-api">Needs setup</span>':'<span class="badge-free">Works</span>';
      card.innerHTML='<div class="svc-top"><div class="svc-name">'+svc.name+"</div>"+badge+'<div class="toggle '+(isOn?"on":"")+'" data-svc="'+svc.id+'" role="switch" tabindex="0"><div class="knob"></div></div></div><div class="svc-types" style="margin-top:6px">'+types+"</div>";
      if(svc.fields&&svc.fields.length){var ad=document.createElement("div");ad.className="svc-api";svc.fields.forEach(function(f){if(f.type==="checkbox"){var row=document.createElement("div");row.style.cssText="display:flex;align-items:center;gap:10px;padding:6px 0";var tl=document.createElement("span");tl.style.cssText="font-size:12px;color:var(--text2)";tl.textContent=f.label;var isOn=config[f.key]!==false;var tg=document.createElement("div");tg.className="toggle"+(isOn?" on":"");tg.setAttribute("role","switch");tg.tabIndex=0;tg.innerHTML='<div class="knob"></div>';tg.addEventListener("click",function(){var on=tg.classList.toggle("on");config[f.key]=on;save();});tg.addEventListener("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();tg.click();}});row.append(tl,tg);ad.appendChild(row);}else{var l=document.createElement("label");l.textContent=f.label;ad.appendChild(l);var i=document.createElement("input");i.type=f.key.indexOf("token")!==-1?"password":"text";i.placeholder=f.ph;i.value=config[f.key]||"";i.addEventListener("input",function(){config[f.key]=i.value;save();});ad.appendChild(i);}});card.appendChild(ad);}
      cd.appendChild(card);
    });c.appendChild(cd);
  });
  var tgs=document.querySelectorAll(".toggle[data-svc]");for(var i=0;i<tgs.length;i++){(function(el){el.addEventListener("click",function(){var id=el.getAttribute("data-svc");var on=el.classList.toggle("on");config["enabled_"+id]=on;save();});el.addEventListener("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();el.click();}});})(tgs[i]);}
}
chrome.storage.sync.get(["cc_config"],function(r){config=(r&&r.cc_config)?r.cc_config:{};render();});
