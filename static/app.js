const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const sh=h=>h.slice(0,10)+"…",tick=v=>v?'<span class="ok">✓</span>':'<span class="bad">✗</span>';
function show(t){$$(".tab").forEach(e=>e.classList.toggle("on",e.id===t));$$("nav button").forEach(b=>b.classList.toggle("on",b.dataset.tab===t));
 if(t==="dash")dash();if(t==="chain")chains();}
$$("nav button").forEach(b=>b.onclick=()=>show(b.dataset.tab));
async function dash(){const s=await (await fetch("/api/stats")).json();
 $("#kpis").innerHTML=[["Certificates issued",s.issued],["Verifications",s.verifications],["Accepted",s.accepted],["Avg latency (ms)",s.avg_latency_ms],["Overall ASR",s.asr==null?"–":s.asr+"%"]].map(k=>`<div class="kpi"><b>${k[1]}</b><span>${k[0]}</span></div>`).join("");
 $("#nodes").innerHTML="<tr><th>Organisation</th><th>Blocks</th><th>Head</th><th>Intact</th></tr>"+s.nodes.map(n=>`<tr><td>${n.node}</td><td>${n.blocks}</td><td class="hash">${sh(n.head)}</td><td>${tick(n.valid)}</td></tr>`).join("");
 const a=Object.entries(s.asr_by_attack);$("#asr").innerHTML=a.length?"<tr><th>Attack</th><th>Attempts</th><th>ASR</th></tr>"+a.map(([k,v])=>`<tr><td>${k}</td><td>${v.attempts}</td><td>${v.asr}%</td></tr>`).join(""):"<tr><td class='hint'>No tampered attempts logged yet.</td></tr>";}
$("#issueForm").onsubmit=async e=>{e.preventDefault();const r=await fetch("/api/issue",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});const d=await r.json();
 if(!r.ok){$("#issueMsg").textContent=d.error;return}
 $("#issued").innerHTML=`<img src="${d.cert_url}?t=${Date.now()}" alt="Issued certificate"><p><b>${d.record.cert_id}</b> recorded in block #${d.block.index}</p><p class="hash">${d.block.hash}</p><p class="hint">QR points to ${d.qr_url}</p>`;
 const f=$("#verifyForm");for(const k of["cert_id","name","programme","grade","issue_date"])f[k].value=d.record[k];};
$("#seed").onclick=async()=>{const d=await (await fetch("/api/seed",{method:"POST"})).json();$("#issueMsg").textContent=`Issued ${d.issued.length} demo certificates (${d.issued[0].cert_id}–${d.issued.at(-1).cert_id}).`};
$("#verifyForm").onsubmit=async e=>{e.preventDefault();const r=await (await fetch("/api/verify",{method:"POST",body:new FormData(e.target)})).json();const c=r.checks,ok=r.verdict==="VALID";
 let h=`<div class="stamp ${ok?"ok":"bad"}">${ok?"VERIFIED":"REJECTED"}</div><table><tr><td>Record found on ledger</td><td>${tick(c.record_found)}</td></tr><tr><td>Node consensus</td><td>${c.node_consensus}</td></tr><tr><td>Chain integrity</td><td>${tick(c.chain_integrity)}</td></tr>`;
 if(c.field_match)h+=Object.entries(c.field_match).map(([k,v])=>`<tr><td>Field “${k}” matches</td><td>${tick(v)}</td></tr>`).join("")+`<tr><td>Record hash</td><td>${tick(c.record_hash_match)}</td></tr>`;
 h+="</table>";if(Object.keys(r.info).length)h+=`<p class="hint">Not enforced by baseline: ${Object.entries(r.info).filter(([k])=>k!=="note").map(([k,v])=>k+" = "+v).join(" · ")}</p>`;
 $("#result").innerHTML=h+`<p class="hint">Decided in ${r.latency_ms} ms · mode ${r.mode}</p>`;};
async function chains(){const d=await (await fetch("/api/chain")).json();
 $("#chains").innerHTML=d.map(n=>`<div class="node panel"><h3>${n.node} ${tick(n.valid)}</h3><div class="blocks">${n.chain.map(b=>`<div class="blk"><b>#${b.index} ${b.data.cert_id||"Genesis"}</b><div class="hash">${sh(b.hash)}<br>prev ${sh(b.prev_hash)}</div></div>`).join("")}</div></div>`).join("");}
const m=location.hash.match(/verify=(\w+)/);if(m){$("#verifyForm").cert_id.value=m[1];show("verify")}else dash();
