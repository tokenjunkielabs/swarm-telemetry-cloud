import {createHash,createCipheriv,createDecipheriv,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {gzipSync,gunzipSync} from 'node:zlib';
import {pathToFileURL} from 'node:url';

export const NOTE='These measurements are a lower bound. Peers can improve this tool, its adapters and source coverage.';
export const sha=b=>createHash('sha256').update(b).digest('hex');
export function seal(raw,key){
  const iv=randomBytes(16),c=createCipheriv('aes-256-cbc',key.subarray(0,32),iv);
  const ciphertext=Buffer.concat([c.update(raw),c.final()]);
  const mac=createHmac('sha256',key.subarray(32)).update(Buffer.concat([Buffer.from('swarm-source-v1'),iv,ciphertext])).digest();
  return {ref:'source:'+sha(raw),sha256:sha(raw),byte_length:raw.length,key_reference:'telemetry/source-custody-key',format:'swarm-source-v1',iv:iv.toString('base64'),ciphertext:ciphertext.toString('base64'),mac:mac.toString('base64')};
}
export function unseal(record,key){
  const iv=Buffer.from(record.iv,'base64'),ciphertext=Buffer.from(record.ciphertext,'base64');
  const mac=createHmac('sha256',key.subarray(32)).update(Buffer.concat([Buffer.from('swarm-source-v1'),iv,ciphertext])).digest();
  if(!timingSafeEqual(mac,Buffer.from(record.mac,'base64')))throw Error('custody_mac_mismatch');
  const d=createDecipheriv('aes-256-cbc',key.subarray(0,32),iv),raw=Buffer.concat([d.update(ciphertext),d.final()]);
  if(sha(raw)!==record.sha256||raw.length!==record.byte_length)throw Error('custody_hash_mismatch');
  return raw;
}
export function project(rows,{kind,account,at,source_ref}){
  return rows.filter(x=>x&&typeof x==='object').map(x=>{
    const actor=x.user||x.actor||{},url=x.html_url||x.url||x.subject?.url||null;
    const occurred_at=x.submitted_at||x.created_at||null,updated_at=x.updated_at||occurred_at;
    const id=x.node_id||x.id||url;
    return {event_id:sha(JSON.stringify([account,kind,id,updated_at,x.state,x.body])),event_type:'github_interaction',kind,
      account_ref:account,provider_id:id,url,actor_login:actor.login||null,actor_id:actor.id||null,
      direction:actor.login?actor.login===account.split('/').at(-1)?'outgoing':'incoming':'unknown',
      occurred_at,provider_updated_at:updated_at,observed_at:at,source_ref,
      state:x.state||null,reason:x.reason||null,body:x.body??null,title:x.title||x.subject?.title||null,
      repository:x.repository?.full_name||null,subject_url:x.subject?.url||null,latest_comment_url:x.subject?.latest_comment_url||null};
  });
}
export function nextLink(headers){return /<([^>]+)>;\s*rel="next"/.exec(headers.get('link')||'')?.[1]||null;}
function apiURL(path){const u=new URL(path,'https://api.github.com');if(u.origin!=='https://api.github.com')throw Error('provider_origin_rejected');return u.toString();}
export function selectSubjectJobs(pending){
  const hot=pending.filter(x=>Number(x.priority||0)>0),cold=pending.filter(x=>Number(x.priority||0)<=0);
  const selected=[...hot.splice(0,6),...cold.splice(0,2)];
  while(selected.length<8&&(hot.length||cold.length))selected.push((hot.length?hot:cold).shift());
  return {selected,remaining:[...hot,...cold]};
}
export async function readCloud({token,key,repo='tokenjunkielabs/swarm-telemetry-custody',now=Date.now()}){
  async function get(path,binary=false){const r=await fetch(apiURL(path),{headers:{Authorization:'Bearer '+token,Accept:binary?'application/octet-stream':'application/vnd.github+json'},signal:AbortSignal.timeout(25000)});if(!r.ok)throw Error('cloud_read_'+r.status);return binary?Buffer.from(await r.arrayBuffer()):r.json();}
  const release=await get('/repos/'+repo+'/releases/tags/telemetry-custody-v1'),pointer=JSON.parse(release.body||'{}');
  if(!pointer.events_asset_id)return {status:'pending',events:[],counts_are_lower_bounds:true,corpus_complete:false,peer_note:NOTE};
  const original=JSON.parse(await get('/repos/'+repo+'/releases/assets/'+pointer.events_asset_id,true));
  const batch=JSON.parse(unseal(original,key)),status=JSON.parse(await get('/repos/'+repo+'/releases/assets/'+pointer.status_asset_id,true));
  const age=(now-Date.parse(batch.observed_at))/1000,fresh=age>=0&&age<=300;
  return {...batch,status:'observed',age_seconds:age,fresh,current_interaction_event_count:fresh?batch.events.length:null,reported_interaction_event_count:batch.events.length,
    execution_state:fresh?'observed':'unknown',provider_status:status,source_custody_repo:repo,pointer,
    history_scope:'Latest retained cloud batch only; earlier encrypted batches and provider history remain independently retained. This page is not the corpus.',
    counts_are_lower_bounds:true,corpus_complete:false,peer_note:NOTE};
}

export async function run(env=process.env){
  const working=env.SWARM_GITHUB_WORKING_TOKEN,main=env.SWARM_GITHUB_MAIN_TOKEN,key=Buffer.from(env.SWARM_SOURCE_CUSTODY_KEY||'','base64');
  const repo=env.SWARM_CUSTODY_REPO||'tokenjunkielabs/swarm-telemetry-custody';
  if(!working||!main||key.length!==64)throw Error('shared_secure_binding_unavailable');
  const tokens={'github/tokenjunkielabs':working,'github/woahwhattheheck':main};
  async function request(path,token=working,method='GET',body){
    const r=await fetch(apiURL(path),{method,headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Commons-Swarm-Telemetry'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(25000)});
    const raw=Buffer.from(await r.arrayBuffer()),at=new Date().toISOString();return {r,raw,at};
  }
  async function readJSON(path){const {r,raw}=await request(path);if(!r.ok)throw Error('cloud_custody_read_'+r.status);return JSON.parse(raw);}
  const release=await readJSON('/repos/'+repo+'/releases/tags/telemetry-custody-v1');
  const pointer=JSON.parse(release.body||'{}');
  const shardTag='telemetry-sources-'+new Date().toISOString().slice(0,13).replace(/[^a-zA-Z0-9-]/g,'-');
  let shardResponse=await request('/repos/'+repo+'/releases/tags/'+shardTag);
  if(shardResponse.r.status===404)shardResponse=await request('/repos/'+repo+'/releases',working,'POST',{tag_name:shardTag,target_commitish:'main',name:shardTag,body:'{}',prerelease:true});
  if(!shardResponse.r.ok)throw Error('cloud_shard_unavailable_'+shardResponse.r.status);
  const shard=JSON.parse(shardResponse.raw);
  let state={version:1,selectors:{},pending_subjects:[],root_cycle:0,source_coverage_complete:false};
  async function asset(id){const r=await fetch('https://api.github.com/repos/'+repo+'/releases/assets/'+id,{headers:{Authorization:'Bearer '+working,Accept:'application/octet-stream'},signal:AbortSignal.timeout(25000)});if(!r.ok)throw Error('cloud_asset_read_'+r.status);return Buffer.from(await r.arrayBuffer());}
  if(pointer.state_asset_id)state=JSON.parse(unseal(JSON.parse(await asset(pointer.state_asset_id)),key));
  const events=[],reads=[];
  async function blob(path,content){
    const bytes=Buffer.from(content),name=sha(bytes)+'-'+path.replace(/[^a-zA-Z0-9._-]/g,'_');
    if(bytes.length>=2147483648)throw Error('cloud_asset_capacity_exceeded');
    const url=shard.upload_url.replace(/\{.*$/,'')+'?'+new URLSearchParams({name});
    if(new URL(url).origin!=='https://uploads.github.com')throw Error('cloud_upload_origin_rejected');
    const b=await fetch(url,{method:'POST',headers:{Authorization:'Bearer '+working,'Content-Type':'application/octet-stream'},body:bytes,signal:AbortSignal.timeout(25000)});
    if(!b.ok)throw Error('cloud_asset_unacknowledged_'+b.status);
    const v=await b.json();if(v.size!==bytes.length)throw Error('cloud_asset_size_mismatch');
    const actual=await asset(v.id);if(sha(actual)!==sha(bytes))throw Error('cloud_asset_readback_mismatch');return v.id;
  }
  async function retain(response,context){
    // The complete provider response is sealed in cloud storage before its cursor or projection changes.
    const packet=Buffer.from(JSON.stringify({context,actual_api_return_at:response.at,status:response.r.status,headers:Object.fromEntries(response.r.headers),body_base64:response.raw.toString('base64')}));
    const record=seal(packet,key),compressed=gzipSync(Buffer.from(JSON.stringify(record)));
    const asset_id=await blob('sources/'+record.sha256+'.json.gz',compressed);
    const source_ref={ref:record.ref,sha256:record.sha256,byte_length:record.byte_length,asset_id,repository:repo,release_id:shard.id,encoding:'gzip-json-aes-cbc-hmac',key_reference:record.key_reference};
    reads.push({context,actual_api_return_at:response.at,http_status:response.r.status,source_ref});return source_ref;
  }
  const identities=[['github/tokenjunkielabs',311286379],['github/woahwhattheheck',293286387]];
  for(const [account,id] of identities){const response=await request('/user',tokens[account]);await retain(response,{account_ref:account,endpoint:'/user',kind:'identity'});if(!response.r.ok||JSON.parse(response.raw).id!==id)throw Error('provider_actor_mismatch');}
  const roots=[];
  for(const [account] of identities){
    const login=account.split('/').at(-1);
    roots.push({account,credential:account,kind:'notifications',endpoint:'/notifications?all=true&per_page=100'});
    roots.push({account,credential:'github/tokenjunkielabs',kind:'received_events',endpoint:'/users/'+login+'/received_events?per_page=100'});
    for(const term of ['author:','involves:','review-involves:'])roots.push({account,credential:'github/tokenjunkielabs',kind:'search_interactions',endpoint:'/search/issues?'+new URLSearchParams({q:term+login,sort:'updated',order:'desc',per_page:'100'})});
  }
  const selected=roots.filter(x=>x.kind==='notifications'),rotating=roots.filter(x=>x.kind!=='notifications');
  for(let n=0;n<2;n++){selected.push(rotating[(state.root_cycle+n)%rotating.length]);}
  state.root_cycle=(state.root_cycle+2)%rotating.length;
  state.pending_subjects.sort((a,b)=>Number(b.priority||0)-Number(a.priority||0)||String(b.provider_updated_at||'').localeCompare(String(a.provider_updated_at||'')));
  const subjects=selectSubjectJobs(state.pending_subjects);selected.push(...subjects.selected);state.pending_subjects=subjects.remaining;
  for(const job of selected){
    const sid=sha(JSON.stringify([job.account,job.kind,job.endpoint])),checkpoint=state.selectors[sid]||{};
    if(Date.now()<Number(checkpoint.retry_epoch||0)){if(!roots.includes(job))state.pending_subjects.push(job);continue;}
    const endpoint=checkpoint.next_endpoint||job.endpoint,response=await request(endpoint,tokens[job.credential]);
    const source_ref=await retain(response,{account_ref:job.account,credential_ref:job.credential,endpoint,kind:job.kind,selector_id:sid});
    if(!response.r.ok){state.selectors[sid]={...checkpoint,last_status:response.r.status,last_read_at:response.at,source_ref,complete:false,retry_epoch:Number(response.r.headers.get('x-ratelimit-reset')||0)*1000||Date.now()+Number(response.r.headers.get('retry-after')||60)*1000};if(!roots.includes(job))state.pending_subjects.push(job);continue;}
    const payload=JSON.parse(response.raw),rows=Array.isArray(payload)?payload:payload.items||[payload];
    events.push(...project(rows,{kind:job.kind,account:job.account,at:response.at,source_ref}));
    for(const row of rows){
      for(const target of [row.subject?.url,row.subject?.latest_comment_url,row.pull_request?.url]){
        if(target&&target.startsWith('https://api.github.com/'))state.pending_subjects.push({account:job.account,credential:'github/tokenjunkielabs',kind:'subject',endpoint:target,priority:job.kind==='notifications'?2:1,provider_updated_at:row.updated_at});
      }
      const u=row.url||'',m=/\/repos\/([^/]+\/[^/]+)\/(?:issues|pulls)\/(\d+)$/.exec(u);
      if(m&&(job.kind.startsWith('search_interactions')||job.kind==='subject')){
        for(const [kind,suffix] of [['issue_comments','issues/'+m[2]+'/comments'],['timeline','issues/'+m[2]+'/timeline'],...(row.pull_request||u.includes('/pulls/')?[['reviews','pulls/'+m[2]+'/reviews'],['review_comments','pulls/'+m[2]+'/comments']]:[])])state.pending_subjects.push({account:job.account,credential:'github/tokenjunkielabs',kind,endpoint:'/repos/'+m[1]+'/'+suffix+'?per_page=100',priority:job.priority||1,provider_updated_at:row.updated_at});
      }
    }
    const next=nextLink(response.r.headers);
    if(next){if(roots.includes(job))state.pending_subjects.push({...job,kind:job.kind+'_backfill',endpoint:next,priority:0});else state.pending_subjects.push(job);}
    state.selectors[sid]={next_endpoint:roots.includes(job)?null:next,last_read_at:response.at,source_ref,last_status:response.r.status,complete:!next,provider_incomplete_results:payload.incomplete_results??null,provider_total_count:payload.total_count??null,unread_regions:payload.total_count>1000?['GitHub search ceiling; date-partition backfill pending']:[]};
  }
  state.pending_subjects=[...new Map(state.pending_subjects.map(x=>[JSON.stringify([x.account,x.kind,x.endpoint]),x])).values()];
  const at=new Date().toISOString(),batch=sha(JSON.stringify(reads));
  const eventsAssetId=await blob('events/'+at.replace(/[:.]/g,'-')+'-'+batch+'.json',JSON.stringify(seal(Buffer.from(JSON.stringify({observed_at:at,events,reads,peer_note:NOTE,counts_are_lower_bounds:true,corpus_complete:false})),key)));
  state.observed_at=at;state.peer_note=NOTE;state.counts_are_lower_bounds=true;state.corpus_complete=false;
  const stateAssetId=await blob('state/current.json',JSON.stringify(seal(Buffer.from(JSON.stringify(state)),key)));
  const summary={observed_at:at,reads:reads.length,interaction_events:events.length,pending_subjects:state.pending_subjects.length,counts_are_lower_bounds:true,corpus_complete:false,peer_note:NOTE,provider_read_watermarks:reads.map(x=>({account_ref:x.context.account_ref,kind:x.context.kind,at:x.actual_api_return_at,status:x.http_status,ref:x.source_ref})),scope:'Account notifications, received events, authored/participated/reviewed subjects and replies; historical coverage incomplete'};
  const statusAssetId=await blob('status/latest.json',JSON.stringify(summary));
  const current=await readJSON('/repos/'+repo+'/releases/'+release.id);if(current.body!==release.body)throw Error('cloud_checkpoint_changed');
  const nextPointer=JSON.stringify({state_asset_id:stateAssetId,status_asset_id:statusAssetId,events_asset_id:eventsAssetId,source_release_id:shard.id,batch,observed_at:at});
  await request('/repos/'+repo+'/releases/'+release.id,working,'PATCH',{body:nextPointer});
  const actual=await readJSON('/repos/'+repo+'/releases/'+release.id);if(actual.body!==nextPointer)throw Error('cloud_cursor_commit_unconfirmed');
  console.log(JSON.stringify({...summary,release_id:release.id,state_asset_id:stateAssetId,cloud_custody_verified:true}));return summary;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const task=process.argv.includes('--read')?readCloud({token:process.env.SWARM_GITHUB_WORKING_TOKEN,key:Buffer.from(process.env.SWARM_SOURCE_CUSTODY_KEY||'','base64')}).then(x=>console.log(JSON.stringify(x))):run();task.catch(e=>{console.error(JSON.stringify({status:'unknown',error:String(e.message).replace(/[^a-zA-Z0-9_:-]/g,'').slice(0,120),counts_are_lower_bounds:true,corpus_complete:false,peer_note:NOTE}));process.exitCode=1;});}
