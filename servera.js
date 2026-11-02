// MellStore server: без зависимостей, нужен только Node.js 18+  ->  node server.js
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const PORT=process.env.PORT||3000,MAX=(+process.env.MAX_MB||300)*1048576;
const DIR=process.env.DATA_DIR||path.join(__dirname,"data"),FD=path.join(DIR,"files"),DBF=path.join(DIR,"db.json");
const SUPER=["хлеб","denis"],CATS=["Игры","Соцсети","Утилиты","Музыка","Фото","Учёба"];
fs.mkdirSync(FD,{recursive:true});
let db={users:[],apps:[],sess:{},nid:1};
try{db=JSON.parse(fs.readFileSync(DBF,"utf8"))}catch(e){}
const save=()=>{fs.writeFileSync(DBF+".tmp",JSON.stringify(db));fs.renameSync(DBF+".tmp",DBF)};
for(const t in db.sess)if(db.sess[t].exp<Date.now())delete db.sess[t];
const hash=(p,s)=>crypto.scryptSync(p,s,32).toString("hex");
const send=(res,c,o)=>{res.writeHead(c,{"Content-Type":"application/json","Access-Control-Allow-Origin":"*"});res.end(JSON.stringify(o))};
const body=req=>new Promise(ok=>{let b="",n=0;req.on("data",d=>{n+=d.length;if(n>1e6){req.destroy();return}b+=d});req.on("end",()=>{try{ok(JSON.parse(b||"{}"))}catch(e){ok({})}})});
const auth=(req,u)=>{const t=(req.headers.authorization||"").slice(7)||u.searchParams.get("t")||"",s=db.sess[t];return s&&s.exp>Date.now()?db.users.find(x=>x.n.toLowerCase()===s.n):null};
const isA=u=>u&&(u.role==="super"||u.role==="mod");
const pub=(u,me)=>({n:u.n,role:u.role,g:u.g,i:u.i,an:u.an,av:u.av,...(me&&me.role==="super"?{ban:u.ban}:{}),...(me&&me.n===u.n?{in:u.in||[]}:{})});
const okImg=s=>typeof s==="string"&&s.startsWith("data:image/jpeg;base64,")&&s.length<90000;
const fails={};
const sess=(res,n)=>{const t=crypto.randomBytes(32).toString("hex");db.sess[t]={n:n.toLowerCase(),exp:Date.now()+30*864e5};save();send(res,200,{tok:t})};
const rmApp=a=>{db.apps=db.apps.filter(x=>x.id!==a.id);db.users.forEach(u=>u.in=(u.in||[]).filter(i=>i!==a.id));fs.unlink(path.join(FD,String(a.id)),()=>{})};
const MIME={".html":"text/html; charset=utf-8",".js":"text/javascript",".css":"text/css",".png":"image/png"};
http.createServer(async(req,res)=>{try{
 const u=new URL(req.url,"http://x"),p=u.pathname;
 if(req.method==="OPTIONS"){res.writeHead(204,{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"Authorization,Content-Type","Access-Control-Allow-Methods":"GET,POST,PUT,OPTIONS"});return res.end()}
 if(!p.startsWith("/api/")){const f=[path.join(__dirname,"public","index.html"),path.join(__dirname,"index.html")].find(fs.existsSync);if(!f){res.writeHead(404);return res.end("index.html не найден")}return fs.readFile(f,(e,d)=>{res.writeHead(200,{"Content-Type":"text/html; charset=utf-8"});res.end(d)})}
 const me=auth(req,u);let m;
 if(req.method==="GET"&&p==="/api/state")return send(res,200,{open:!!process.env.OPEN_UPLOADS,users:db.users.map(x=>pub(x,me)),apps:db.apps.filter(a=>a.st==="ok"||isA(me)||(me&&me.n===a.by))});
 if(m=p.match(/^\/api\/file\/(\d+)$/)){const a=db.apps.find(x=>x.id===+m[1]);if(!a)return send(res,404,{error:"Нет такого приложения"});const fp=path.join(FD,String(a.id));
  if(req.method==="GET"){if(a.st!=="ok"&&!(isA(me)||(me&&me.n===a.by)))return send(res,403,{error:"Ещё на проверке"});if(!fs.existsSync(fp))return send(res,404,{error:"Файл не загружен"});res.writeHead(200,{"Content-Type":"application/octet-stream","Content-Disposition":"attachment; filename*=UTF-8''"+encodeURIComponent(a.fn),"Content-Length":fs.statSync(fp).size,"X-Content-Type-Options":"nosniff","Content-Security-Policy":"sandbox","Access-Control-Allow-Origin":"*"});return fs.createReadStream(fp).pipe(res)}
  if(req.method==="PUT"){if(!me||me.n!==a.by)return send(res,403,{error:"Не твоё приложение"});let n=0,bad=0;const ws=fs.createWriteStream(fp);req.on("data",d=>{n+=d.length;if(n>MAX&&!bad){bad=1;ws.destroy();fs.unlink(fp,()=>{});send(res,413,{error:"Файл слишком большой (лимит "+MAX/1048576+" МБ)"})}});req.pipe(ws);return ws.on("finish",()=>{if(!bad){a.fs=n;save();send(res,200,{ok:1})}})}}
 if(req.method!=="POST")return send(res,404,{error:"Не найдено"});
 const b=await body(req);
 if(p==="/api/register"){const n=String(b.n||"").trim(),pw=String(b.p||"");
  if(!/^[\wа-яё]{2,16}$/i.test(n))return send(res,400,{error:"Ник: 2–16 символов, буквы, цифры, _"});
  if(pw.length<4||pw.length>100)return send(res,400,{error:"Пароль 4–100 символов"});
  if(db.users.some(x=>x.n.toLowerCase()===n.toLowerCase()))return send(res,400,{error:"Ник занят"});
  const sp=SUPER.includes(n.toLowerCase());
  if(sp&&process.env.ADMIN_KEY&&b.key!==process.env.ADMIN_KEY)return send(res,403,{error:"Неверный ключ админа"});
  const s=crypto.randomBytes(16).toString("hex");
  db.users.push({n,s,h:hash(pw,s),role:sp?"super":"user",g:sp?11:db.users.length%11,i:sp?(n.toLowerCase()==="хлеб"?5:1):0,an:sp,ban:0,in:[]});
  return sess(res,n)}
 if(p==="/api/login"){const ip=req.socket.remoteAddress,f=fails[ip]=fails[ip]||{n:0,t:0};if(Date.now()-f.t>6e5)f.n=0;if(f.n>=10)return send(res,429,{error:"Слишком много попыток, подожди 10 минут"});
  const x=db.users.find(y=>y.n.toLowerCase()===String(b.n||"").trim().toLowerCase());
  const good=x&&crypto.timingSafeEqual(Buffer.from(hash(String(b.p||""),x.s),"hex"),Buffer.from(x.h,"hex"));
  if(!good){f.n++;f.t=Date.now();await new Promise(r=>setTimeout(r,400));return send(res,400,{error:"Неверный ник или пароль"})}
  if(x.ban)return send(res,403,{error:"Аккаунт заблокирован"});f.n=0;return sess(res,x.n)}
 if(!me)return send(res,401,{error:"Нужно войти"});
 if(me.ban)return send(res,403,{error:"Аккаунт заблокирован"});
 if(p==="/api/me"){if(Number.isInteger(b.g)&&b.g>=0&&b.g<12)me.g=b.g;if(Number.isInteger(b.i)&&b.i>=0&&b.i<16)me.i=b.i;if(typeof b.an==="boolean")me.an=b.an;if(okImg(b.av))me.av=b.av;save();return send(res,200,{ok:1})}
 if(p==="/api/app"){if(!isA(me)&&!process.env.OPEN_UPLOADS)return send(res,403,{error:"Загружать приложения могут только админы"});const name=String(b.name||"").trim().slice(0,40),d=String(b.d||"").trim().slice(0,300);if(!name||!d)return send(res,400,{error:"Заполни название и описание"});
  const a={id:db.nid++,name,ic:String(b.ic||"📦").slice(0,4),img:okImg(b.img)?b.img:null,d,c:CATS.includes(b.c)?b.c:CATS[0],by:me.n,st:isA(me)?"ok":"pend",inst:0,rate:4,b:0,fn:String(b.fn||"app").replace(/[\\\/]/g,"_").slice(0,100),fs:0};
  db.apps.push(a);save();return send(res,200,{id:a.id})}
 if(p==="/api/install"){const a=db.apps.find(x=>x.id===b.id&&x.st==="ok");if(!a)return send(res,404,{error:"Нет такого приложения"});me.in=me.in||[];const i=me.in.indexOf(a.id);if(i<0){me.in.push(a.id);a.inst++}else{me.in.splice(i,1);a.inst=Math.max(0,a.inst-1)}save();return send(res,200,{ok:1})}
 if(p==="/api/delme"){db.apps.filter(a=>a.by===me.n).forEach(rmApp);db.users=db.users.filter(x=>x!==me);for(const t in db.sess)if(db.sess[t].n===me.n.toLowerCase())delete db.sess[t];save();return send(res,200,{ok:1})}
 if(p==="/api/admin"){const a=db.apps.find(x=>x.id===b.id),t=db.users.find(x=>x.n===b.n),sup=me.role==="super";
  if(b.op==="ok"&&isA(me)&&a){a.st="ok"}
  else if(b.op==="del"&&a&&(isA(me)||a.by===me.n)){rmApp(a)}
  else if(sup&&t&&b.op==="role"&&["user","mod","super"].includes(b.v)&&!SUPER.includes(t.n.toLowerCase())){t.role=b.v}
  else if(sup&&t&&b.op==="ban"&&!SUPER.includes(t.n.toLowerCase())){t.ban=b.v?1:0;if(t.ban)for(const k in db.sess)if(db.sess[k].n===t.n.toLowerCase())delete db.sess[k]}
  else if(sup&&t&&b.op==="look"&&(b.k==="g"||b.k==="i")){const v=+b.v;if(Number.isInteger(v)&&v>=0&&v<(b.k==="g"?12:16))t[b.k]=v}
  else return send(res,403,{error:"Нет прав"});
  save();return send(res,200,{ok:1})}
 send(res,404,{error:"Не найдено"})
}catch(e){console.error(e);try{send(res,500,{error:"Ошибка сервера"})}catch(_){}}}).listen(PORT,()=>console.log("MellStore: http://localhost:"+PORT));
