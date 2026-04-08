/**
 * ThreatCheck
 * github.com/mthcht/threatcheck
 * No ads. No data collection. It just works.
 */
(() => {
  "use strict";
  const e=v=>encodeURIComponent(v);

  /* ═══════════ SERVICES ═══════════
   * apiSvc: if set, background.js is called for auto-scoring when API key present
   */
  const S=[
    {id:"virustotal",n:"VirusTotal",c:"ti",t:["ip","domain","hash","url","email"],api:false,apiSvc:"virustotal",co:"#394eff",
      u(t,v){const m={ip:"ip-address",domain:"domain",hash:"file"};return m[t]?`https://www.virustotal.com/gui/${m[t]}/${e(v)}`:`https://www.virustotal.com/gui/search/${e(v)}`;}},
    {id:"abuseipdb",n:"AbuseIPDB",c:"ti",t:["ip","domain"],api:false,apiSvc:"abuseipdb",co:"#00b4d8",
      u(_,v){return `https://www.abuseipdb.com/check/${e(v)}`;}},
    {id:"otx",n:"AlienVault OTX",c:"ti",t:["ip","domain","hash","url"],api:false,co:"#7b68ee",
      u(t,v){const m={ip:"ip",domain:"domain",hash:"file",url:"url"};return `https://otx.alienvault.com/indicator/${m[t]}/${v}`;}},
    {id:"threatfox",n:"ThreatFox",c:"ti",t:["hash","ip"],api:false,co:"#ff6b35",
      u(_,v){return `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(v)}`;}},
    {id:"malwarebazaar",n:"MalwareBazaar",c:"ti",t:["hash"],api:false,co:"#e84393",
      u(_,v){let p="sha256";if(v.length===32)p="md5";else if(v.length===40)p="sha1";return `https://bazaar.abuse.ch/browse.php?search=${p}%3A${e(v)}`;}},
    {id:"pulsedive",n:"Pulsedive",c:"ti",t:["ip","domain","url"],api:false,co:"#1dd1a1",
      u(_,v){return `https://pulsedive.com/indicator/?indicator=${e(v)}`;}},
    /* API auto-check services */
    {id:"opencti",n:"OpenCTI",c:"ti",t:["ip","domain","hash","url","email","cve"],api:true,
      af:[{key:"opencti_url"},{key:"opencti_token"}],apiSvc:"opencti",co:"#001bda",
      u(_,v,cfg){const b=(cfg?.opencti_url||"").replace(/\/+$/,"");return b?`${b}/dashboard/search/knowledge/${e(v)}`:null;}},
    {id:"recordedfuture",n:"Recorded Future",c:"ti",t:["ip","domain","hash","url","email","cve"],api:true,
      af:[{key:"rf_token"}],apiSvc:"recordedfuture",co:"#e63946",
      u(_,v){return `https://app.recordedfuture.com/live/sc/entity?query=${e(v)}`;}},
    {id:"ipinfo",n:"IPInfo",c:"ni",t:["ip"],api:false,co:"#0984e3",
      u(_,v){return `https://ipinfo.io/${e(v)}`;}},
    {id:"spur",n:"Spur",c:"ni",t:["ip"],api:true,
      af:[{key:"spur_token"}],apiSvc:"spur",co:"#6c5ce7",
      u(_,v){return `https://app.spur.us/context?q=${e(v)}`;}},
    {id:"shodan",n:"Shodan",c:"ni",t:["ip"],api:false,co:"#d63031",
      u(_,v){return `https://www.shodan.io/host/${e(v)}`;}},
    {id:"censys",n:"Censys",c:"ni",t:["ip"],api:false,co:"#0652DD",
      u(_,v){return `https://search.censys.io/hosts/${e(v)}`;}},
    {id:"zoomeye",n:"ZoomEye",c:"ni",t:["ip"],api:false,co:"#e17055",
      u(_,v){return `https://www.zoomeye.org/searchResult?q=ip%3A${e(v)}`;}},
    {id:"greynoise",n:"GreyNoise",c:"ni",t:["ip"],api:false,co:"#00d2d3",
      u(_,v){return `https://viz.greynoise.io/ip/${e(v)}`;}},
    {id:"spamhaus",n:"Spamhaus",c:"ni",t:["ip","domain"],api:false,co:"#c0392b",
      u(_,v){return `https://check.spamhaus.org/listed/?searchterm=${e(v)}`;}},
    {id:"urlscan",n:"URLScan",c:"ud",t:["url","domain"],api:false,apiSvc:"urlscan",co:"#00cec9",
      u(t,v){return t==="domain"?`https://urlscan.io/search/#domain%3A${e(v)}`:`https://urlscan.io/search/#page.url%3A%22${e(v)}%22`;}},
    {id:"wayback",n:"Wayback",c:"ud",t:["url","domain"],api:false,co:"#636e72",
      u(_,v){return `https://web.archive.org/web/*/${v}`;}},
    {id:"dnsdumpster",n:"DNSDumpster",c:"ud",t:["domain"],api:true,
      af:[{key:"dnsdumpster_key"}],apiSvc:"dnsdumpster",co:"#2d3436",
      u(){return null;}},
    {id:"validin",n:"Validin",c:"ud",t:["domain","ip"],api:true,
      af:[{key:"validin_key"}],apiSvc:"validin",co:"#a29bfe",
      u(t,v){return t==="ip"?`https://app.validin.com/detail?find=${e(v)}&type=ip4`:`https://app.validin.com/detail?type=dom&find=${e(v)}`;}},
    {id:"mxtoolbox",n:"MXToolbox",c:"ud",t:["domain","email"],api:false,co:"#f39c12",
      u(t,v){if(t==="email"){const d=v.split("@")[1];return d?`https://mxtoolbox.com/emailhealth/${e(d)}`:`https://mxtoolbox.com/emailhealth/${e(v)}`;}return `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${e(v)}&run=toolpage`;}},
    {id:"whois",n:"WHOIS",c:"ud",t:["domain"],api:false,co:"#a29bfe",
      u(_,v){return `https://who.is/whois/${e(v)}`;}},
    {id:"github",n:"GitHub Code",c:"cl",t:["hash","domain","ip","email"],api:false,co:"#8b949e",
      u(_,v){return `https://github.com/search?q=${e(v)}&type=code`;}},
    {id:"leakcheck",n:"LeakCheck",c:"cl",t:["email"],api:true,
      af:[{key:"leakcheck_key"}],apiSvc:"leakcheck",co:"#fd79a8",
      u(){return null;}},
    {id:"torarchive",n:"TOR Archive",c:"ni",t:["ip"],api:false,co:"#7f5af0",
      u(_,v){return `https://tor-archive.github.io/#q=${e(v)}`;}},
    {id:"nvd",n:"NVD (NIST)",c:"vuln",t:["cve"],api:false,co:"#2ecc71",
      u(_,v){return `https://nvd.nist.gov/vuln/detail/${v.toUpperCase()}`;}},
    {id:"mitre_cve",n:"MITRE CVE",c:"vuln",t:["cve"],api:false,co:"#e67e22",
      u(_,v){return `https://www.cve.org/CVERecord?id=${v.toUpperCase()}`;}},
    {id:"exploitdb",n:"Exploit-DB",c:"vuln",t:["cve"],api:false,co:"#c0392b",
      u(_,v){const num=v.toUpperCase().replace(/^CVE-/,"");return `https://www.exploit-db.com/search?cve=${e(num)}`;}},
    {id:"ms_eventid",n:"MS Docs",c:"doc",t:["eventid"],api:false,co:"#0078d4",
      u(_,v){const id=parseInt(v,10);if((id>=4608&&id<=4978)||(id>=5024&&id<=5168)||(id>=1100&&id<=1108))return `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-${id}`;if(id>=1&&id<=29)return `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events`;return `https://www.google.com/search?q=site%3Alearn.microsoft.com+windows+event+id+${id}`;}},
    {id:"ms_errorcode",n:"MS Docs",c:"doc",t:["errorcode"],api:false,co:"#0078d4",
      u(_,v){if(/^AADSTS/i.test(v))return `https://login.microsoftonline.com/error?code=${e(v)}`;return `https://www.google.com/search?q=site%3Alearn.microsoft.com+${e(v)}`;}}
  ];

  const IC={virustotal:`<svg viewBox="0 0 16 16"><path d="M2 8l5 5L14 3"/></svg>`,abuseipdb:`<svg viewBox="0 0 16 16"><path d="M8 1L2 4v4c0 4 6 7 6 7s6-3 6-7V4L8 1z"/></svg>`,otx:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M5 8h6M8 5v6"/></svg>`,threatfox:`<svg viewBox="0 0 16 16"><path d="M8 2l6 10H2L8 2z"/></svg>`,malwarebazaar:`<svg viewBox="0 0 16 16"><rect x="2" y="6" width="12" height="7" rx="1.5"/><path d="M5 6V4a3 3 0 016 0v2"/></svg>`,pulsedive:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="3"/><circle cx="8" cy="8" r="6"/></svg>`,opencti:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M8 5v6M5 8h6"/></svg>`,recordedfuture:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M8 4v4l3 2"/></svg>`,ipinfo:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M8 7v4M8 5.5v0"/></svg>`,spur:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M7 5l3 3-3 3"/></svg>`,shodan:`<svg viewBox="0 0 16 16"><rect x="2" y="4" width="12" height="8" rx="1"/><path d="M5 7h1M5 9h1M8 7h3M8 9h3"/></svg>`,censys:`<svg viewBox="0 0 16 16"><circle cx="7" cy="7" r="4"/><path d="M10 10l3.5 3.5"/></svg>`,zoomeye:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2"/></svg>`,greynoise:`<svg viewBox="0 0 16 16"><path d="M2 12C4 4,7 4,8 8C9 12,12 12,14 4"/></svg>`,spamhaus:`<svg viewBox="0 0 16 16"><path d="M8 1L2 4v4c0 4 6 7 6 7s6-3 6-7V4L8 1z"/><path d="M6 8h4"/></svg>`,urlscan:`<svg viewBox="0 0 16 16"><path d="M2 4h12M2 8h8M2 12h10"/></svg>`,wayback:`<svg viewBox="0 0 16 16"><path d="M4 2v12M8 4v10M12 2v12M2 8h12"/></svg>`,dnsdumpster:`<svg viewBox="0 0 16 16"><circle cx="8" cy="4" r="2"/><circle cx="4" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><path d="M8 6v2L4 12M8 8l4 4"/></svg>`,validin:`<svg viewBox="0 0 16 16"><path d="M2 8l4 4 8-8"/></svg>`,mxtoolbox:`<svg viewBox="0 0 16 16"><rect x="1" y="4" width="14" height="8" rx="1.5"/><path d="M4 7l2 2 2-2M10 7v3"/></svg>`,whois:`<svg viewBox="0 0 16 16"><path d="M8 2a6 6 0 100 12A6 6 0 008 2zM8 2v12M2 8h12M3 4.5h10M3 11.5h10"/></svg>`,github:`<svg viewBox="0 0 16 16"><circle cx="8" cy="5" r="3"/><path d="M8 8v4M5 12h6"/></svg>`,leakcheck:`<svg viewBox="0 0 16 16"><path d="M8 2C6 5 4 7 4 10a4 4 0 008 0c0-3-2-5-4-8z"/></svg>`,torarchive:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M8 5v6M5.5 6.5h5"/></svg>`,nvd:`<svg viewBox="0 0 16 16"><path d="M8 1L2 4v4c0 4 6 7 6 7s6-3 6-7V4L8 1z"/><path d="M6 8l2 2 3-4"/></svg>`,mitre_cve:`<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M6 6l4 4M10 6l-4 4"/></svg>`,exploitdb:`<svg viewBox="0 0 16 16"><path d="M4 2v12M4 8h8M12 5v6"/></svg>`,ms_eventid:`<svg viewBox="0 0 16 16"><rect x="2" y="2" width="5" height="5" rx=".5"/><rect x="9" y="2" width="5" height="5" rx=".5"/><rect x="2" y="9" width="5" height="5" rx=".5"/><rect x="9" y="9" width="5" height="5" rx=".5"/></svg>`,ms_errorcode:`<svg viewBox="0 0 16 16"><rect x="2" y="2" width="5" height="5" rx=".5"/><rect x="9" y="2" width="5" height="5" rx=".5"/><rect x="2" y="9" width="5" height="5" rx=".5"/><rect x="9" y="9" width="5" height="5" rx=".5"/></svg>`};

  /* ═══════════ DETECT ═══════════ */
  const P={ipv4:/^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/,ipv6:/^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$/,url:/^https?:\/\/[^\s/$.?#].[^\s]*$/i,email:/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/,sha256:/^[0-9a-fA-F]{64}$/,sha1:/^[0-9a-fA-F]{40}$/,md5:/^[0-9a-fA-F]{32}$/,cve:/^CVE-\d{4}-\d{4,}$/i,domain:/^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$/,eventId:/^(?:event\s*(?:id)?[\s:]*)?(\d{1,5})$/i,errorCode:/^(?:0x[0-9a-fA-F]{4,8}|AADSTS\d{4,6}|CA\d{4,6}|(?:error|code|err)[\s:#-]*\d{3,10})$/i};
  const ER=[[1,29],[1024,1108],[4608,4978],[5024,5168],[7000,7045],[10000,10099]];

  function refang(s){return s.replace(/\[\.\]/g,".").replace(/\[dot\]/gi,".").replace(/\(\.\)/g,".").replace(/\(dot\)/gi,".").replace(/hxxps/gi,"https").replace(/hxxp/gi,"http").replace(/\[:\/\/\]/g,"://").replace(/\(:\/\/\)/g,"://").replace(/\[:\]/g,":").replace(/\[at\]/gi,"@").replace(/\[@\]/g,"@").replace(/\(at\)/gi,"@");}

  /* 1285 IANA TLDs (April 2026, excluding punycode IDNs) */
  const TLDS=new Set([
    "aaa","aarp","abb","abbott","abbvie","abc","able","abogado","abudhabi","ac","academy","accenture","accountant","accountants","aco","actor","ad","ads","adult","ae",
    "aeg","aero","aetna","af","afl","africa","ag","agakhan","agency","ai","aig","airbus","airforce","airtel","akdn","al","alibaba","alipay","allfinanz","allstate",
    "ally","alsace","alstom","am","amazon","americanexpress","americanfamily","amex","amfam","amica","amsterdam","analytics","android","anquan","anz","ao","aol","apartments","app","apple",
    "aq","aquarelle","ar","arab","aramco","archi","army","arpa","art","arte","as","asda","asia","associates","at","athleta","attorney","au","auction","audi",
    "audible","audio","auspost","author","auto","autos","aw","aws","ax","axa","az","azure","ba","baby","baidu","banamex","band","bank","bar","barcelona",
    "barclaycard","barclays","barefoot","bargains","baseball","basketball","bauhaus","bayern","bb","bbc","bbt","bbva","bcg","bcn","bd","be","beats","beauty","beer","berlin",
    "best","bestbuy","bet","bf","bg","bh","bharti","bi","bible","bid","bike","bing","bingo","bio","biz","bj","black","blackfriday","blockbuster","blog",
    "bloomberg","blue","bm","bms","bmw","bn","bnpparibas","bo","boats","boehringer","bofa","bom","bond","boo","book","booking","bosch","bostik","boston","bot",
    "boutique","box","br","bradesco","bridgestone","broadway","broker","brother","brussels","bs","bt","build","builders","business","buy","buzz","bv","bw","by","bz",
    "bzh","ca","cab","cafe","cal","call","calvinklein","cam","camera","camp","canon","capetown","capital","capitalone","car","caravan","cards","care","career","careers",
    "cars","casa","case","cash","casino","cat","catering","catholic","cba","cbn","cbre","cc","cd","center","ceo","cern","cf","cfa","cfd","cg",
    "ch","chanel","channel","charity","chase","chat","cheap","chintai","christmas","chrome","church","ci","cipriani","circle","cisco","citadel","citi","citic","city","ck",
    "cl","claims","cleaning","click","clinic","clinique","clothing","cloud","club","clubmed","cm","cn","co","coach","codes","coffee","college","cologne","com","commbank",
    "community","company","compare","computer","comsec","condos","construction","consulting","contact","contractors","cooking","cool","coop","corsica","country","coupon","coupons","courses","cpa","cr",
    "credit","creditcard","creditunion","cricket","crown","crs","cruise","cruises","cu","cuisinella","cv","cw","cx","cy","cymru","cyou","cz","dad","dance","data",
    "date","dating","datsun","day","dclk","dds","de","deal","dealer","deals","degree","delivery","dell","deloitte","delta","democrat","dental","dentist","desi","design",
    "dev","dhl","diamonds","diet","digital","direct","directory","discount","discover","dish","diy","dj","dk","dm","dnp","do","docs","doctor","dog","domains",
    "dot","download","drive","dtv","dubai","dupont","durban","dvag","dvr","dz","earth","eat","ec","eco","edeka","edu","education","ee","eg","email",
    "emerck","energy","engineer","engineering","enterprises","epson","equipment","er","ericsson","erni","es","esq","estate","et","eu","eurovision","eus","events","exchange","expert",
    "exposed","express","extraspace","fage","fail","fairwinds","faith","family","fan","fans","farm","farmers","fashion","fast","fedex","feedback","ferrari","ferrero","fi","fidelity",
    "fido","film","final","finance","financial","fire","firestone","firmdale","fish","fishing","fit","fitness","fj","fk","flickr","flights","flir","florist","flowers","fly",
    "fm","fo","foo","food","football","ford","forex","forsale","forum","foundation","fox","fr","free","fresenius","frl","frogans","frontier","ftr","fujitsu","fun",
    "fund","furniture","futbol","fyi","ga","gal","gallery","gallo","gallup","game","games","gap","garden","gay","gb","gbiz","gd","gdn","ge","gea",
    "gent","genting","george","gf","gg","ggee","gh","gi","gift","gifts","gives","giving","gl","glass","gle","global","globo","gm","gmail","gmbh",
    "gmo","gmx","gn","godaddy","gold","goldpoint","golf","goodyear","goog","google","gop","got","gov","gp","gq","gr","grainger","graphics","gratis","green",
    "gripe","grocery","group","gs","gt","gu","gucci","guge","guide","guitars","guru","gw","gy","hair","hamburg","hangout","haus","hbo","hdfc","hdfcbank",
    "health","healthcare","help","helsinki","here","hermes","hiphop","hisamitsu","hitachi","hiv","hk","hkt","hm","hn","hockey","holdings","holiday","homedepot","homegoods","homes",
    "homesense","honda","horse","hospital","host","hosting","hot","hotels","hotmail","house","how","hr","hsbc","ht","hu","hughes","hyatt","hyundai","ibm","icbc",
    "ice","icu","id","ie","ieee","ifm","ikano","il","im","imamat","imdb","immo","immobilien","in","inc","industries","infiniti","info","ing","ink",
    "institute","insurance","insure","int","international","intuit","investments","io","ipiranga","iq","ir","irish","is","ismaili","ist","istanbul","it","itau","itv","jaguar",
    "java","jcb","je","jeep","jetzt","jewelry","jio","jll","jm","jmp","jnj","jo","jobs","joburg","jot","joy","jp","jpmorgan","jprs","juegos",
    "juniper","kaufen","kddi","ke","kerryhotels","kerryproperties","kfh","kg","kh","ki","kia","kids","kim","kindle","kitchen","kiwi","km","kn","koeln","komatsu",
    "kosher","kp","kpmg","kpn","kr","krd","kred","kuokgroup","kw","ky","kyoto","kz","la","lacaixa","lamborghini","lamer","land","landrover","lanxess","lasalle",
    "lat","latino","latrobe","law","lawyer","lb","lc","lds","lease","leclerc","lefrak","legal","lego","lexus","lgbt","li","lidl","life","lifeinsurance","lifestyle",
    "lighting","like","lilly","limited","limo","lincoln","link","live","living","lk","llc","llp","loan","loans","locker","locus","lol","london","lotte","lotto",
    "love","lpl","lplfinancial","lr","ls","lt","ltd","ltda","lu","lundbeck","luxe","luxury","lv","ly","ma","madrid","maif","maison","makeup","man",
    "management","mango","map","market","marketing","markets","marriott","marshalls","mattel","mba","mc","mckinsey","md","me","med","media","meet","melbourne","meme","memorial",
    "men","menu","merckmsd","mg","mh","miami","microsoft","mil","mini","mint","mit","mitsubishi","mk","ml","mlb","mls","mm","mma","mn","mo",
    "mobi","mobile","moda","moe","moi","mom","monash","money","monster","mormon","mortgage","moscow","moto","motorcycles","mov","movie","mp","mq","mr","ms",
    "msd","mt","mtn","mtr","mu","museum","music","mv","mw","mx","my","mz","na","nab","nagoya","name","navy","nba","nc","ne",
    "nec","net","netbank","netflix","network","neustar","new","news","next","nextdirect","nexus","nf","nfl","ng","ngo","nhk","ni","nico","nike","nikon",
    "ninja","nissan","nissay","nl","no","nokia","norton","now","nowruz","nowtv","np","nr","nra","nrw","ntt","nu","nyc","nz","obi","observer",
    "office","okinawa","olayan","olayangroup","ollo","om","omega","one","ong","onl","online","ooo","open","oracle","orange","org","organic","origins","osaka","otsuka",
    "ott","ovh","pa","page","panasonic","paris","pars","partners","parts","party","pay","pccw","pe","pet","pf","pfizer","pg","ph","pharmacy","phd",
    "philips","phone","photo","photography","photos","physio","pics","pictet","pictures","pid","pin","ping","pink","pioneer","pizza","pk","pl","place","play","playstation",
    "plumbing","plus","pm","pn","pnc","pohl","poker","politie","porn","post","pr","praxi","press","prime","pro","prod","productions","prof","progressive","promo",
    "properties","property","protection","pru","prudential","ps","pt","pub","pw","pwc","py","qa","qpon","quebec","quest","racing","radio","re","read","realestate",
    "realtor","realty","recipes","red","redumbrella","rehab","reise","reisen","reit","reliance","ren","rent","rentals","repair","report","republican","rest","restaurant","review","reviews",
    "rexroth","rich","richardli","ricoh","ril","rio","rip","ro","rocks","rodeo","rogers","room","rs","rsvp","ru","rugby","ruhr","run","rw","rwe",
    "ryukyu","sa","saarland","safe","safety","sakura","sale","salon","samsclub","samsung","sandvik","sandvikcoromant","sanofi","sap","sarl","sas","save","saxo","sb","sbi",
    "sbs","sc","scb","schaeffler","schmidt","scholarships","school","schule","schwarz","science","scot","sd","se","search","seat","secure","security","seek","select","sener",
    "services","seven","sew","sex","sexy","sfr","sg","sh","shangrila","sharp","shell","shia","shiksha","shoes","shop","shopping","shouji","show","si","silk",
    "sina","singles","site","sj","sk","ski","skin","sky","skype","sl","sling","sm","smart","smile","sn","sncf","so","soccer","social","softbank",
    "software","sohu","solar","solutions","song","sony","soy","spa","space","sport","spot","sr","srl","ss","st","stada","staples","star","statebank","statefarm",
    "stc","stcgroup","stockholm","storage","store","stream","studio","study","style","su","sucks","supplies","supply","support","surf","surgery","suzuki","sv","swatch","swiss",
    "sx","sy","sydney","systems","sz","tab","taipei","talk","taobao","target","tatamotors","tatar","tattoo","tax","taxi","tc","tci","td","tdk","team",
    "tech","technology","tel","temasek","tennis","teva","tf","tg","th","thd","theater","theatre","tiaa","tickets","tienda","tips","tires","tirol","tj","tjmaxx",
    "tjx","tk","tkmaxx","tl","tm","tmall","tn","to","today","tokyo","tools","top","toray","toshiba","total","tours","town","toyota","toys","tr",
    "trade","trading","training","travel","travelers","travelersinsurance","trust","trv","tt","tube","tui","tunes","tushu","tv","tvs","tw","tz","ua","ubank","ubs",
    "ug","uk","unicom","university","uno","uol","ups","us","uy","uz","va","vacations","vana","vanguard","vc","ve","vegas","ventures","verisign","versicherung",
    "vet","vg","vi","viajes","video","vig","viking","villas","vin","vip","virgin","visa","vision","viva","vivo","vlaanderen","vn","vodka","volvo","vote",
    "voting","voto","voyage","vu","wales","walmart","walter","wang","wanggou","watch","watches","weather","weatherchannel","webcam","weber","website","wed","wedding","weibo","weir",
    "wf","whoswho","wien","wiki","williamhill","win","windows","wine","winners","wme","woodside","work","works","world","wow","ws","wtc","wtf","xbox","xerox",
    "xihuan","xin","xxx","xyz","yachts","yahoo","yamaxun","yandex","ye","yodobashi","yoga","yokohama","you","youtube","yt","yun","za","zappos","zara","zero",
    "zip","zm","zone","zuerich","zw"
  ]);

  function validTld(str){
    const parts=str.toLowerCase().split(".");
    const tld=parts[parts.length-1].split("/")[0]; /* handle domain.tld/path */
    return TLDS.has(tld);
  }

  function tryDetect(t){
    if(P.url.test(t))return{type:"url",label:"URL",value:t};
    if(P.email.test(t)&&validTld(t))return{type:"email",label:"Email",value:t};
    if(P.ipv4.test(t))return{type:"ip",label:"IPv4",value:t};
    if(P.ipv6.test(t))return{type:"ip",label:"IPv6",value:t};
    if(P.sha256.test(t))return{type:"hash",label:"SHA-256",value:t};
    if(P.sha1.test(t))return{type:"hash",label:"SHA-1",value:t};
    if(P.md5.test(t))return{type:"hash",label:"MD5",value:t};
    if(P.cve.test(t))return{type:"cve",label:"CVE",value:t.toUpperCase()};
    if(/^AADSTS\d+$/i.test(t))return{type:"errorcode",label:"AADSTS",value:t};
    if(/^CA\d+$/i.test(t))return{type:"errorcode",label:"CA err",value:t};
    if(P.errorCode.test(t))return{type:"errorcode",label:"Error",value:t};
    const em=t.match(P.eventId);if(em){const id=parseInt(em[1]||em[0],10);if(ER.some(([a,b])=>id>=a&&id<=b))return{type:"eventid",label:"EvtID",value:String(id)};}
    /* Bare URL: domain.tld/path without protocol */
    if(/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}\/\S+$/.test(t)&&validTld(t))return{type:"url",label:"URL",value:"https://"+t};
    /* Domain */
    if(P.domain.test(t)&&t.includes(".")&&validTld(t))return{type:"domain",label:"Domain",value:t};
    return null;
  }

  function detect(text){
    const t=text.replace(/^[\s\u200B-\uFEFF]+|[\s\u200B-\uFEFF]+$/g,"");
    if(!t||t.length>2048)return null;
    const raw=tryDetect(t);if(raw)return raw;
    const r=refang(t);if(r!==t)return tryDetect(r);return null;
  }

  /* ═══════════ BULK SCAN ═══════════ */
  const SCAN={url:/https?:\/\/[^\s"'<>(){}\[\]]+/gi,email:/[a-zA-Z0-9._%+\-]+(?:@|\[at\]|\[@\]|\(at\))[a-zA-Z0-9.\-]+(?:\.|\[\.\]|\[dot\]|\(\.\)|\(dot\))[a-zA-Z]{2,}/gi,ipv4:/(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\]|\[dot\]|\(\.\))){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)/g,sha256:/\b[0-9a-fA-F]{64}\b/g,sha1:/\b[0-9a-fA-F]{40}\b/g,md5:/\b[0-9a-fA-F]{32}\b/g,cve:/CVE-\d{4}-\d{4,}/gi,domain:/(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.\]|\[dot\]|\(\.\)|\(dot\)))+[a-zA-Z]{2,}/g,errorCode:/(?:AADSTS\d{4,6}|CA\d{4,6}|0x[0-9a-fA-F]{4,8})/gi};
  const DOMAIN_EXCLUDE=/^\d+\.\d+\.\d+\.\d+$|^[0-9a-fA-F]{32,64}$/;

  function bulkDetect(text){
    const rf=refang(text);const found=new Map();
    for(const m of rf.matchAll(SCAN.url)){const v=m[0].replace(/[.,;:!?)]+$/,"");if(!found.has(v)){found.set(v,{type:"url",label:"URL",value:v});const d=v.replace(/^https?:\/\//i,"").split(/[/?#:]/)[0].toLowerCase();if(d&&d.includes(".")&&validTld(d)&&!found.has(d))found.set(d,{type:"domain",label:"Domain",value:d});}}
    for(const m of rf.matchAll(SCAN.email)){const v=refang(m[0]);if(P.email.test(v)&&!found.has(v))found.set(v,{type:"email",label:"Email",value:v});}
    for(const m of rf.matchAll(SCAN.ipv4)){const v=refang(m[0]);if(P.ipv4.test(v)&&!found.has(v)&&v!=="0.0.0.0"&&v!=="127.0.0.1")found.set(v,{type:"ip",label:"IPv4",value:v});}
    for(const m of rf.matchAll(SCAN.sha256)){const v=m[0];if(!found.has(v))found.set(v,{type:"hash",label:"SHA-256",value:v});}
    for(const m of rf.matchAll(SCAN.sha1)){const v=m[0];if(!found.has(v)&&![...found.keys()].some(k=>k.includes(v)))found.set(v,{type:"hash",label:"SHA-1",value:v});}
    for(const m of rf.matchAll(SCAN.md5)){const v=m[0];if(!found.has(v)&&![...found.keys()].some(k=>k.includes(v)))found.set(v,{type:"hash",label:"MD5",value:v});}
    for(const m of rf.matchAll(SCAN.cve)){const v=m[0].toUpperCase();if(!found.has(v))found.set(v,{type:"cve",label:"CVE",value:v});}
    for(const m of rf.matchAll(SCAN.errorCode)){const v=m[0];if(!found.has(v))found.set(v,{type:"errorcode",label:"Error",value:v});}
    for(const m of rf.matchAll(SCAN.domain)){const v=refang(m[0]).toLowerCase();if(DOMAIN_EXCLUDE.test(v)||found.has(v))continue;if([...found.values()].some(f=>f.type==="url"&&f.value.includes(v)))continue;if(validTld(v))found.set(v,{type:"domain",label:"Domain",value:v});}
    return [...found.values()];
  }

  /* ═══════════ CONFIG ═══════════ */
  let cfg={};
  function loadCfg(){if(typeof chrome!=="undefined"&&chrome.storage?.sync)chrome.storage.sync.get(["cc_config"],r=>{cfg=r?.cc_config||{};});}
  loadCfg();
  if(typeof chrome!=="undefined"&&chrome.storage?.onChanged)chrome.storage.onChanged.addListener(ch=>{if(ch.cc_config)cfg=ch.cc_config.newValue||{};});
  function ok(svc){if(cfg["enabled_"+svc.id]===false)return false;if(svc.api&&svc.af)return svc.af.every(f=>cfg[f.key]&&String(cfg[f.key]).trim()!=="");return true;}

  /* Look up the raw service definition */
  function svcDef(id){return S.find(s=>s.id===id);}

  function getUrls(det){
    const urls=[];
    for(const svc of S){if(!svc.t.includes(det.type)||!ok(svc))continue;const url=svc.u(det.type,det.value,cfg);if(url||svc.apiSvc)urls.push({id:svc.id,n:svc.n,url:url||null,co:svc.co,apiSvc:svc.apiSvc||null});}
    return urls;
  }

  /* ═══════════ UI ═══════════ */
  let popup=null;
  function kill(){if(!popup)return;popup.classList.add("cc-out");const r=popup;setTimeout(()=>r.remove(),100);popup=null;}

  function posPopup(el,mx,my,selDir){
    const rect=el.getBoundingClientRect();const vw=window.innerWidth,vh=window.innerHeight;
    let left,top=my-8;
    if(selDir==="ltr"){left=mx+14;if(left+rect.width>vw-6)left=mx-rect.width-6;}
    else{left=mx-rect.width-14;if(left<6)left=mx+14;}
    if(top+rect.height>vh-6)top=my-rect.height+8;
    if(left<4)left=4;if(top<4)top=4;
    el.style.left=(left+window.scrollX)+"px";el.style.top=(top+window.scrollY)+"px";
  }

  /* ── Trigger background API check and update score badge ── */
  function triggerApiCheck(scoreEl, rowEl, listEl, apiSvc, type, value) {
    scoreEl.textContent="…";
    scoreEl.style.color="#6b7280";
    /* Guard: if extension was reloaded but page wasn't, chrome.runtime is dead */
    if(!chrome.runtime?.id){scoreEl.textContent="reload";scoreEl.title="Extension updated - reload this tab";return;}
    const timer=setTimeout(()=>{if(scoreEl.textContent==="…")scoreEl.textContent="timeout";},8000);
    try{
      chrome.runtime.sendMessage(
        {action:"apiCheck",service:apiSvc,type:type,value:value,config:cfg},
        (resp)=>{
          clearTimeout(timer);
          if(chrome.runtime.lastError){
            console.error("[ThreatCheck]",apiSvc,"sendMessage error:",chrome.runtime.lastError.message);
            scoreEl.textContent="err";scoreEl.title=chrome.runtime.lastError.message;return;
          }
          if(!resp){scoreEl.textContent="";return;}
          if(resp.error){
            console.warn("[ThreatCheck]",apiSvc,"API error:",resp.error);
            scoreEl.textContent="err";scoreEl.title=resp.error;return;
          }
          if(resp.label){
            scoreEl.textContent=resp.label;
            scoreEl.style.color=resp.color||"#6b7280";
          }else{scoreEl.textContent="";}

          /* If response includes rich context (RF/OpenCTI), make badge clickable to expand */
          if(resp.context&&resp.context.rules&&resp.context.rules.length>0){
            scoreEl.style.cursor="pointer";
            scoreEl.title="Click for details";
            let detailEl=null;
            scoreEl.addEventListener("click",(ev)=>{
              ev.preventDefault();ev.stopPropagation();
              if(detailEl){detailEl.remove();detailEl=null;return;}
              detailEl=document.createElement("div");
              detailEl.className="cc-ctx";
              if(resp.context.riskSummary){
                const sum=document.createElement("div");sum.className="cc-ctx-sum";
                sum.textContent=resp.context.riskSummary;
                detailEl.appendChild(sum);
              }
              /* Context sections (RF) */
              if(resp.context.contexts&&resp.context.contexts.length){
                const cw=document.createElement("div");cw.className="cc-ctx-sections";
                for(const ctx of resp.context.contexts){
                  const cs=document.createElement("span");cs.className="cc-ctx-tag";
                  cs.textContent=ctx.name+(ctx.score!=null?` (${ctx.score})`:"");
                  cw.appendChild(cs);
                }
                detailEl.appendChild(cw);
              }
              /* Rules - each expandable */
              for(const rule of resp.context.rules){
                const wrap=document.createElement("div");wrap.className="cc-ctx-rw";
                const hdr=document.createElement("div");hdr.className="cc-ctx-rule";
                const dot=document.createElement("span");dot.className="cc-ctx-dot";
                const lv=rule.crit||0;
                dot.style.background=lv>=4?"#ef4444":lv>=3?"#f59e0b":lv>=2?"#3b82f6":"#22c55e";
                const name=document.createElement("span");name.className="cc-ctx-name";
                name.textContent=rule.name;
                const crit=document.createElement("span");crit.className="cc-ctx-crit";
                crit.textContent=rule.critLabel||"";
                crit.style.color=lv>=4?"#ef4444":lv>=3?"#f59e0b":lv>=2?"#3b82f6":"#22c55e";
                hdr.append(dot,name,crit);
                wrap.appendChild(hdr);
                /* Expandable detail - selectable, clean RF tags, linkify URLs */
                const detail=document.createElement("div");detail.className="cc-ctx-det";
                const meta=[];
                if(rule.timestamp)meta.push(rule.timestamp.split("T")[0]);
                if(typeof rule.count==="number")meta.push(`count: ${rule.count}`);
                if(typeof rule.sightings==="number")meta.push(`sightings: ${rule.sightings}`);
                if(meta.length){const m=document.createElement("div");m.className="cc-ctx-meta";m.textContent=meta.join(" · ");detail.appendChild(m);}
                if(rule.evidence){
                  const d=document.createElement("div");d.className="cc-ctx-desc";
                  d.innerHTML=linkifyText(cleanRfTags(rule.evidence));
                  d.querySelectorAll("a").forEach(a=>{a.addEventListener("click",ev=>ev.stopPropagation());});
                  detail.appendChild(d);
                }
                wrap.appendChild(detail);
                hdr.addEventListener("click",(ev)=>{ev.stopPropagation();detail.classList.toggle("show");});
                detailEl.appendChild(wrap);
              }
              rowEl.after(detailEl);
            });
          }
        }
      );
    }catch(ex){
      clearTimeout(timer);
      console.error("[ThreatCheck]",apiSvc,"exception:",ex);
      scoreEl.textContent="err";scoreEl.title=String(ex);
    }
  }

  function scoreColor(s){
    if(s>=75)return"#ef4444";if(s>=50)return"#f59e0b";if(s>=25)return"#3b82f6";return"#22c55e";
  }

  /* Strip RF custom XML tags like <e id=...>text</e> → text */
  function cleanRfTags(str){
    return (str||"").replace(/<\/?e[^>]*>/gi,"").replace(/<[^>]+>/g,"").trim();
  }

  /* Escape HTML then linkify URLs */
  function linkifyText(str){
    const esc=str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    return esc.replace(/(https?:\/\/[^\s<>"'`,;)}\]]+)/gi,'<a href="$1" target="_blank" rel="noopener noreferrer" class="cc-ctx-link">$1</a>');
  }

  /* Defang IOC for safe sharing in reports/tickets/emails */
  function defang(val,type){
    if(type==="hash"||type==="cve"||type==="eventid"||type==="errorcode")return val;
    let d=val;
    d=d.replace(/https:\/\//gi,"hxxps://").replace(/http:\/\//gi,"hxxp://");
    d=d.replace(/@/g,"[at]");
    d=d.replace(/\./g,"[.]");
    return d;
  }
  function defangList(items){return items.map(i=>defang(i.value||i,i.type||"")).join("\n");}

  /* ── Single IOC popup ── */
  function showSingle(det,mx,my,selDir,backFn){
    kill();
    const items=getUrls(det);if(!items.length)return;
    popup=document.createElement("div");popup.className="cc-p";popup.setAttribute("data-cc-threatcheck","1");
    /* Header */
    const hdr=document.createElement("div");hdr.className="cc-h";
    /* Back button (only when drilled down from bulk panel) */
    if(backFn){
      const back=document.createElement("button");back.className="cc-ib cc-back";back.title="Back to IOC list";
      back.innerHTML=`<svg viewBox="0 0 14 14"><path d="M9 3L4 7l5 4"/></svg>`;
      back.addEventListener("click",ev=>{ev.stopPropagation();backFn();});
      hdr.appendChild(back);
    }
    const badge=document.createElement("span");badge.className="cc-b";badge.textContent=det.label;
    const val=document.createElement("span");val.className="cc-v";val.textContent=det.value;val.title=det.value;
    const ggl=document.createElement("a");ggl.className="cc-ib";ggl.href=`https://www.google.com/search?q=${e(det.value)}`;ggl.target="_blank";ggl.rel="noopener noreferrer";ggl.title="Google";ggl.innerHTML=`<svg viewBox="0 0 14 14"><text x="3" y="11" font-size="11" font-weight="700" font-family="Arial,sans-serif" fill="currentColor">G</text></svg>`;ggl.addEventListener("click",ev=>ev.stopPropagation());
    const xbtn=document.createElement("a");xbtn.className="cc-ib";xbtn.href=`https://x.com/search?q=${e(det.value)}&f=live`;xbtn.target="_blank";xbtn.rel="noopener noreferrer";xbtn.title="Search on X";xbtn.innerHTML=`<svg viewBox="0 0 14 14"><path d="M1.5 1.5l4.3 5.5L1.5 12.5h1l3.6-4.5 3 4.5h3.4L8.2 6.8l4-5.3h-1L7.7 6 5 1.5z"/></svg>`;xbtn.addEventListener("click",ev=>ev.stopPropagation());
    /* RF Intelligence Search - if token configured */
    let rfBtn=null;
    if(cfg.rf_token){
      rfBtn=document.createElement("a");rfBtn.className="cc-ib";rfBtn.href=`https://app.recordedfuture.com/live/sc/universal#!/search?query=${e(det.value)}`;rfBtn.target="_blank";rfBtn.rel="noopener noreferrer";rfBtn.title="Search Recorded Future Intelligence";rfBtn.style.color="#e63946";rfBtn.innerHTML=`<svg viewBox="0 0 14 14"><circle cx="7" cy="7" r="5.5"/><path d="M7 4v3l2.5 1.5"/></svg>`;rfBtn.addEventListener("click",ev=>ev.stopPropagation());
    }
    const cp=document.createElement("button");cp.className="cc-ib";cp.title="Copy";cp.innerHTML=`<svg viewBox="0 0 14 14"><rect x="5" y="5" width="6.5" height="6.5" rx="1"/><path d="M3 9.5V3h6.5"/></svg>`;cp.addEventListener("click",ev=>{ev.stopPropagation();navigator.clipboard.writeText(det.value).then(()=>{cp.innerHTML=`<svg viewBox="0 0 14 14"><path d="M3 7l3 3 5-5" stroke="#34d399"/></svg>`;setTimeout(()=>{cp.innerHTML=`<svg viewBox="0 0 14 14"><rect x="5" y="5" width="6.5" height="6.5" rx="1"/><path d="M3 9.5V3h6.5"/></svg>`;},800);});});
    /* Defang copy button */
    const df=document.createElement("button");df.className="cc-ib";df.title="Copy defanged";df.innerHTML=`<svg viewBox="0 0 14 14"><path d="M7 1L2 4v3c0 3.5 5 6 5 6s5-2.5 5-6V4L7 1z"/><path d="M5 7l2 2 3-3" stroke-width="1.2"/></svg>`;df.addEventListener("click",ev=>{ev.stopPropagation();const dv=defang(det.value,det.type);navigator.clipboard.writeText(dv).then(()=>{df.innerHTML=`<svg viewBox="0 0 14 14"><path d="M3 7l3 3 5-5" stroke="#34d399"/></svg>`;setTimeout(()=>{df.innerHTML=`<svg viewBox="0 0 14 14"><path d="M7 1L2 4v3c0 3.5 5 6 5 6s5-2.5 5-6V4L7 1z"/><path d="M5 7l2 2 3-3" stroke-width="1.2"/></svg>`;},800);});});
    const cl=document.createElement("button");cl.className="cc-ib";cl.innerHTML=`<svg viewBox="0 0 14 14"><path d="M4 4l6 6M10 4l-6 6"/></svg>`;cl.addEventListener("click",ev=>{ev.stopPropagation();kill();});
    const hdrItems=[badge,val,ggl,xbtn];if(rfBtn)hdrItems.push(rfBtn);hdrItems.push(cp,df,cl);
    hdr.append(...hdrItems);popup.appendChild(hdr);
    /* Service list - NO separators */
    const list=document.createElement("div");list.className="cc-l";
    for(const it of items){
      const a=document.createElement(it.url?"a":"div");a.className="cc-r";if(it.url){a.href=it.url;a.target="_blank";a.rel="noopener noreferrer";}a.style.setProperty("--c",it.co);
      const icoSpan=`<i class="cc-i">${IC[it.id]||""}</i>`;
      const nameSpan=`<span class="cc-nm">${it.n}</span>`;
      const scoreSpan=document.createElement("span");scoreSpan.className="cc-sc";
      a.innerHTML=icoSpan+nameSpan;
      a.appendChild(scoreSpan);
      a.addEventListener("click",ev=>ev.stopPropagation());
      list.appendChild(a);
      /* Fire API auto-check if service supports it */
      if(it.apiSvc){
        /* Validin: manual check by default to save tokens */
        if(it.apiSvc==="validin"&&!cfg.validin_autocheck){
          scoreSpan.textContent="check";
          scoreSpan.style.color="#a29bfe";
          scoreSpan.style.cursor="pointer";
          scoreSpan.title="Click to check via API (tokens are limited)";
          scoreSpan.addEventListener("click",(ev)=>{
            ev.preventDefault();ev.stopPropagation();
            triggerApiCheck(scoreSpan,a,list,it.apiSvc,det.type,det.value);
          });
        }else if(it.apiSvc==="urlscan"&&!cfg.urlscan_key){
          /* URLScan: skip auto-check when no key */
        }else if(it.apiSvc==="virustotal"&&!cfg.vt_key){
          /* VT: skip auto-check when no key */
        }else if(it.apiSvc==="virustotal"&&cfg.vt_key&&cfg.vt_autocheck===false){
          scoreSpan.textContent="check";scoreSpan.style.color="#394eff";scoreSpan.style.cursor="pointer";
          scoreSpan.title="Click to check via VirusTotal API";
          scoreSpan.addEventListener("click",(ev)=>{ev.preventDefault();ev.stopPropagation();triggerApiCheck(scoreSpan,a,list,it.apiSvc,det.type,det.value);});
        }else if(it.apiSvc==="abuseipdb"&&!cfg.abuseipdb_key){
          /* AbuseIPDB: skip auto-check when no key */
        }else{
          triggerApiCheck(scoreSpan,a,list,it.apiSvc,det.type,det.value);
        }
      }
    }
    popup.appendChild(list);
    document.body.appendChild(popup);
    posPopup(popup,mx,my,selDir);
  }

  /* ── Bulk IOC panel ── */
  function showBulk(iocs,mx,my,selDir){
    kill();
    popup=document.createElement("div");popup.className="cc-bp";popup.setAttribute("data-cc-threatcheck","1");
    const hdr=document.createElement("div");hdr.className="cc-bh";
    hdr.innerHTML=`<span class="cc-bt">${iocs.length} IOCs extracted</span>`;
    const clb=document.createElement("button");clb.className="cc-ib";clb.innerHTML=`<svg viewBox="0 0 14 14"><path d="M4 4l6 6M10 4l-6 6"/></svg>`;clb.addEventListener("click",ev=>{ev.stopPropagation();kill();});
    hdr.appendChild(clb);popup.appendChild(hdr);
    const tb=document.createElement("div");tb.className="cc-btb";
    const selAll=document.createElement("label");selAll.className="cc-bsa";
    const saBox=document.createElement("input");saBox.type="checkbox";saBox.checked=true;
    selAll.appendChild(saBox);selAll.appendChild(document.createTextNode(" All"));
    const cpAll=document.createElement("button");cpAll.className="cc-bact";cpAll.textContent="Copy list";
    const dfAll=document.createElement("button");dfAll.className="cc-bact";dfAll.textContent="Copy defanged";
    tb.append(selAll,cpAll,dfAll);popup.appendChild(tb);
    const list=document.createElement("div");list.className="cc-bl";
    const checks=[];
    for(const ioc of iocs){
      const row=document.createElement("div");row.className="cc-br";
      const cb=document.createElement("input");cb.type="checkbox";cb.checked=true;cb.dataset.value=ioc.value;cb.dataset.type=ioc.type;
      checks.push(cb);cb.addEventListener("click",ev=>ev.stopPropagation());
      const bdg=document.createElement("span");bdg.className="cc-bb";bdg.textContent=ioc.label;
      const vt=document.createElement("span");vt.className="cc-bv";vt.textContent=ioc.value;vt.title=ioc.value;
      /* Auto-check score badges for API services */
      const scoreWrap=document.createElement("span");scoreWrap.className="cc-bsc";
      if(chrome.runtime?.id){
        const det={type:ioc.type,label:ioc.label,value:ioc.value};
        const apiServices=getUrls(det).filter(s=>s.apiSvc);
        for(const svc of apiServices){
          if(svc.apiSvc==="validin"&&!cfg.validin_autocheck)continue;
          if(svc.apiSvc==="urlscan"&&!cfg.urlscan_key)continue;
          if(svc.apiSvc==="virustotal"&&(!cfg.vt_key||cfg.vt_autocheck===false))continue;
          if(svc.apiSvc==="abuseipdb"&&!cfg.abuseipdb_key)continue;
          const sc=document.createElement("span");sc.className="cc-sc";sc.textContent="…";sc.style.color="#6b7280";
          sc.title=svc.n;
          scoreWrap.appendChild(sc);
          triggerApiCheck(sc,row,list,svc.apiSvc,ioc.type,ioc.value);
        }
      }
      const arrow=document.createElement("span");arrow.className="cc-ba";arrow.textContent="›";
      row.append(cb,bdg,vt,scoreWrap,arrow);
      row.addEventListener("click",ev=>{
        ev.stopPropagation();if(ev.target===cb)return;
        const det={type:ioc.type,label:ioc.label,value:ioc.value};
        const rect=row.getBoundingClientRect();
        const bx=rect.right+window.scrollX,by=rect.top+window.scrollY+rect.height/2;
        showSingle(det,bx,by,"ltr",()=>showBulk(iocs,mx,my,selDir));
      });
      list.appendChild(row);
    }
    popup.appendChild(list);
    saBox.addEventListener("change",()=>{checks.forEach(c=>{c.checked=saBox.checked;});});
    cpAll.addEventListener("click",ev=>{ev.stopPropagation();const vals=checks.filter(c=>c.checked).map(c=>c.dataset.value).join("\n");navigator.clipboard.writeText(vals).then(()=>{cpAll.textContent="Copied!";setTimeout(()=>{cpAll.textContent="Copy list";},1000);});});
    dfAll.addEventListener("click",ev=>{ev.stopPropagation();const vals=checks.filter(c=>c.checked).map(c=>defang(c.dataset.value,c.dataset.type)).join("\n");navigator.clipboard.writeText(vals).then(()=>{dfAll.textContent="Copied!";setTimeout(()=>{dfAll.textContent="Copy defanged";},1000);});});
    document.body.appendChild(popup);
    posPopup(popup,mx,my,selDir);
  }

  /* ═══════════ EVENTS ═══════════ */
  let tmr=null,mouseDownX=0;
  document.addEventListener("mousedown",ev=>{mouseDownX=ev.clientX;if(popup&&!ev.target.closest("[data-cc-threatcheck]"))kill();});
  document.addEventListener("mouseup",ev=>{
    if(ev.target.closest("[data-cc-threatcheck]"))return;
    clearTimeout(tmr);const upX=ev.clientX,upY=ev.clientY;const selDir=upX>=mouseDownX?"ltr":"rtl";
    tmr=setTimeout(()=>{
      const sel=window.getSelection();const txt=sel?sel.toString():"";
      if(!txt||!txt.trim()){kill();return;}
      const single=detect(txt);
      if(single){
        /* If URL detected, also extract domain and let user choose */
        if(single.type==="url"){
          const domainMatch=single.value.replace(/^https?:\/\//i,"").split(/[/?#:]/)[0].toLowerCase();
          if(domainMatch&&domainMatch.includes(".")&&validTld(domainMatch)){
            const iocs=[
              single,
              {type:"domain",label:"Domain",value:domainMatch}
            ];
            showBulk(iocs,upX,upY,selDir);return;
          }
        }
        showSingle(single,upX,upY,selDir);return;
      }
      if(txt.length>10){const iocs=bulkDetect(txt);if(iocs.length===1){showSingle(iocs[0],upX,upY,selDir);return;}if(iocs.length>1){showBulk(iocs,upX,upY,selDir);return;}}
      kill();
    },150);
  });
  document.addEventListener("keydown",ev=>{if(ev.key==="Escape")kill();});

  /* Context menu and keyboard shortcut handler */
  if(chrome.runtime?.id){
    chrome.runtime.onMessage.addListener((msg)=>{
      if(msg.action==="contextMenuLookup"&&msg.text){
        const txt=refang(msg.text.trim());
        triggerLookupFromText(txt);
      }
      if(msg.action==="shortcutLookup"){
        const sel=window.getSelection().toString().trim();
        if(sel){const txt=refang(sel);triggerLookupFromText(txt);}
      }
    });
  }

  function triggerLookupFromText(txt){
    if(!txt)return;
    /* Try center of viewport as popup position */
    const cx=window.innerWidth/2,cy=window.innerHeight/3;
    const single=detect(txt);
    if(single){
      if(single.type==="url"){
        const domainMatch=single.value.replace(/^https?:\/\//i,"").split(/[/?#:]/)[0].toLowerCase();
        if(domainMatch&&domainMatch.includes(".")&&validTld(domainMatch)){
          showBulk([single,{type:"domain",label:"Domain",value:domainMatch}],cx,cy,"ltr");return;
        }
      }
      showSingle(single,cx,cy,"ltr");return;
    }
    if(txt.length>10){const iocs=bulkDetect(txt);if(iocs.length===1){showSingle(iocs[0],cx,cy,"ltr");return;}if(iocs.length>1){showBulk(iocs,cx,cy,"ltr");return;}}
  }
})();
