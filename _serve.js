const h=require('http'),f=require('fs'),p=require('path');
const ROOT=__dirname;
const T={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml'};
h.createServer((q,u)=>{
  let fp=q.url==='/'?'/mors-app.html':q.url.split('?')[0];
  const safe=p.normalize(fp).replace(/^(\.\.[\\/])+/,'/');
  const file=p.join(ROOT,safe);
  f.readFile(file,(e,d)=>{
    if(e){u.writeHead(404);u.end('File not found');}
    else{u.writeHead(200,{'content-type':T[p.extname(safe)]||'application/octet-stream'});u.end(d);}
  });
}).listen(5173,()=>console.log('CODE MORS server: http://localhost:5173'));