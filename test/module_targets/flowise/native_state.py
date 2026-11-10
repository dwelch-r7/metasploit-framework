"""Scoped byte/name/mode snapshots; never traverse or remove a foreign path."""
STATE_SCRIPT = r'''
const fs=require('fs'),p=require('path');
const allowed=q=>q==='/root/.npm'||q.startsWith('/root/.npm/')||/^\/tmp\/module-target-flowise-[^/]+(?:\/|$)/.test(q);
function snapshot(){let files={},links={},directories=[];
 const walk=q=>{
 let st;try{st=fs.lstatSync(q);}catch(e){if(e.code==='ENOENT')return;throw e;}
 if(st.isSymbolicLink()){links[q]=fs.readlinkSync(q);return;}
 if(st.isDirectory()){directories.push(q);for(const n of fs.readdirSync(q))walk(p.join(q,n));}
 else if(st.isFile())files[q]={bytes:fs.readFileSync(q).toString('base64'),mode:st.mode&0o777,uid:st.uid,gid:st.gid};};
 walk('/root/.npm');for(const n of fs.readdirSync('/tmp'))if(n.startsWith('module-target-flowise-'))walk(p.join('/tmp',n));
 return {files,links,directories:directories.sort()};}
function restore(before){const after=snapshot();
 for(const q of [...Object.keys(before.files),...Object.keys(before.links),...before.directories,...Object.keys(after.files),...Object.keys(after.links),...after.directories])if(!allowed(q))throw Error('Unowned path '+q);
 for(const q of Object.keys(after.links))fs.unlinkSync(q);
 for(const q of Object.keys(after.files))if(!(q in before.files))fs.unlinkSync(q);
 for(const q of after.directories.filter(q=>!before.directories.includes(q)).sort((a,b)=>b.length-a.length))fs.rmdirSync(q);
 for(const q of before.directories)fs.mkdirSync(q,{recursive:true});
 for(const [q,item]of Object.entries(before.files)){fs.mkdirSync(p.dirname(q),{recursive:true});fs.writeFileSync(q,Buffer.from(item.bytes,'base64'));fs.chmodSync(q,item.mode);fs.chownSync(q,item.uid,item.gid);}
 for(const [q,target]of Object.entries(before.links)){if(fs.existsSync(q))fs.unlinkSync(q);fs.symlinkSync(target,q);}
 return {before,after,restored:snapshot()};}
'''
