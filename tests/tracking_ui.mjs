import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const source = fs.readFileSync(new URL('../sgw/admin/src/dashboard.php', import.meta.url), 'utf8');
const script = source.match(/<script>([\s\S]*?)<\/script>/)[1].replace(/<\?=[\s\S]*?\?>/g, '"test"');
new vm.Script(script); // Compile all dashboard JavaScript, not just the helpers.
const context = vm.createContext({});
vm.runInContext(script.slice(script.indexOf('function trackingMappingState('), script.indexOf('async function createTrackingSplit(')), context);
let passed = 1;
const group = {status: 'ACTIVE', mapping_count: 6, mapping_filled_count: 6, has_active_children: 0};
for (const [filled, text, className] of [[6, '6/6 已完成', 'mapping-done'], [4, '4/6 部分可用', 'mapping-partial'], [0, '0/6 无可用映射', 'mapping-missing']]) {
    const result = context.trackingMappingState({...group, mapping_filled_count: filled});
    assert.equal(result.text, text);
    assert.ok(result.className.includes(className));
    assert.equal(result.complete, filled === 6);
    passed++;
}
assert.equal(context.trackingMappingState({...group, has_active_children: 1, mapping_filled_count: 0}).text, '已拆分'); passed++;
assert.equal(context.trackingMappingState({...group, status: 'DRAFT', mapping_filled_count: 0}).text, '0/6 无可用映射 · 待配置'); passed++;
assert.equal(context.trackingMappingState({...group, mapping_count: 0, mapping_filled_count: 0}).complete, false); passed++;
for (const path of ['1', '2', '3', '2.1.2']) {
    assert.deepEqual(Array.from(context.trackingSplitPreview(path)), [path + '.1', path + '.2']);
    passed++;
}
assert.equal(context.trackingDraftWarning(2), ''); passed++;
assert.match(context.trackingDraftWarning(1), /只有1个子组.*完整保留2个/); passed++;
for (const count of [3, 4, 20]) { assert.match(context.trackingDraftWarning(count), new RegExp('旧待配置拆分：' + count + '个子组')); passed++; }
const parent = {...group, id: 2, has_active_children: 1, has_draft_children: 0};
const children = [3, 4].map(id => ({id, parent_id: 2, status: 'ACTIVE', has_active_children: 0, has_draft_children: 0}));
assert.equal(context.trackingCanUndo(parent, children), true); passed++;
assert.equal(context.trackingCanUndo(parent, [children[0]]), false); passed++;
assert.equal(context.trackingCanUndo(parent, [{...children[0], has_active_children: 1}, children[1]]), false); passed++;
assert.equal(context.trackingCanUndo(parent, [{...children[0], has_draft_children: 1}, children[1]]), false); passed++;
assert.equal(context.trackingCanUndo({...parent, has_draft_children: 1}, children), false); passed++;
assert.equal(context.trackingCanUndo({...parent, status: 'DRAFT'}, children), false); passed++;
assert.equal(context.trackingCanUndo(parent, [...children, {id: 5, parent_id: 2, status: 'ARCHIVED', has_active_children: 1}]), true); passed++;
assert.ok(!script.includes("field('子组数量'")); passed++;
assert.ok(!script.includes('2-20')); passed++;
for (const filled of [1, 4, 5]) { assert.equal(context.trackingMappingState({...group, mapping_filled_count: filled}).usable, true); passed++; }
assert.equal(context.trackingMappingState({...group, mapping_filled_count: 0}).usable, false); passed++;
for (const [state, text] of [['CURRENT','当前'],['SUSPECT','疑似失效'],['INACTIVE','已失效'],['UNSEEN','手动添加 · 当前未检测']]) {
    assert.equal(context.trackingSourceState({state, in_latest: 0}), text); passed++;
}
assert.ok(!script.includes('DELETED')); passed++;
assert.ok(!script.includes('恢复原入口') && !script.includes('/restore')); passed++;
assert.equal(context.trackingSplitTime({...parent, split_at: 123}), 123); passed++;
assert.equal(context.trackingSplitTime({...parent, has_active_children: 0, split_at: 123}), null); passed++;
assert.ok(script.includes('fmtTime(trackingSplitTime(g))')); passed++;
assert.ok(script.includes('原入口管理') && script.includes('+ 添加原入口')); passed++;
assert.ok(script.includes('当前最新订阅未检测到此入口，仍可保存')); passed++;
assert.ok(script.includes('对应节点会过滤')); passed++;
assert.ok(!/\b(?:prompt|confirm|alert)\s*\(/.test(script)); passed++;
const catalog = ['CURRENT','SUSPECT','INACTIVE','UNSEEN'].map((state, i) => ({source_host: `source${i}`, state, in_latest: i === 0 ? 1 : 0}));
catalog.push({source_host: 'stale-current', state: 'CURRENT', in_latest: 0});
const sourceGroup = {mappings: [...catalog.map(s => ({source_host: s.source_host, target_host: 'target'})), {source_host: 'absent', target_host: 'target'}]};
assert.deepEqual(Array.from(context.trackingCurrentMappings(sourceGroup, catalog), r => r.source_host), ['source0']); passed++;
for (const host of ['source1','source2','source3','stale-current','absent']) {
    assert.ok(!context.trackingCurrentMappings(sourceGroup, catalog).some(r => r.source_host === host)); passed++;
}
assert.equal(context.trackingCurrentMappings(sourceGroup, []).length, 0); passed++;
assert.equal(context.trackingCurrentMappings({mappings: []}, catalog).length, 0); passed++;
assert.equal(context.trackingCurrentMappings(sourceGroup, [{...catalog[0], in_latest: '1'}]).length, 1); passed++;
assert.equal(context.trackingMappingState({...group, mapping_count: 1, mapping_filled_count: 1}).text, '1/1 已完成'); passed++;
assert.ok(script.includes('mappings:inputs.map(')); passed++;
assert.ok(script.includes('各组映射将被清理')); passed++;
assert.ok(script.includes('作为新入口重新加入，target为空')); passed++;
assert.ok(script.includes('历史及备用映射保持原样')); passed++;
for(const text of ['入口域名','检测并申请证书','Cloudflare API Token','留空保留原值','新建 Cloudflare 凭据','domainPoll=setTimeout','cloudflare/','domains/']){
    assert.ok(script.includes(text));passed++;
}
vm.runInContext(script.slice(script.indexOf('function domainStatus('),script.indexOf('function cfFields(')),context);
assert.equal(context.domainStatus({status:'PENDING'}),'正在申请证书…');passed++;
assert.equal(context.domainStatus({status:'ACTIVE'}),'正常');passed++;
assert.equal(context.domainStatus({status:'ERROR'}),'证书申请失败');passed++;
assert.equal(context.domainStatus({status:'REMOVING'}),'正在删除…');passed++;

// Execute the real page/poll functions with a small DOM and cancellable fake clock.
// No browser dependency or real three-second waits are required for async race coverage.
const domainCode = script.slice(script.indexOf('let domainPoll'), script.indexOf('async function settings('));
const pollCode = domainCode.slice(0, domainCode.indexOf('function domainStatus('));
const showCode = script.slice(script.indexOf('async function show(page)'), script.indexOf('function fmtTime('));
const domHelpers = script.slice(script.indexOf('function node('), script.indexOf('async function api('));
const domainData = (...states) => ({
    domains: [{id:1,fqdn:'gateway.test',role:'PRIMARY',status:'ACTIVE'}, ...states.map((status,i)=>({id:i+2,fqdn:`alias${i}.example.net`,role:'ALIAS',status,credential_name:'CF profile',expires_at:12345,last_error:status==='ERROR'?'safe failure':null}))],
    credentials: [{id:7,name:'CF profile',zone_name:'example.net',zone_id:'a'.repeat(32),token_last4:'9876',last_test_ok:1}]
});
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no});return {promise,resolve,reject}}
function domainHarness(management=false){
    const timers=new Map(),responses=[],calls=[],elements=new Map(),copies=[];let timerId=0,peakTimers=0,cleared=0;
    const viewport={scrollX:11,scrollY:270,restores:0,scrollTo(x,y){this.scrollX=x;this.scrollY=y;this.restores++}};
    class Element {
        constructor(tag){this.tagName=tag;this.children=[];this.parent=null;this.text='';this.style={};this.scrollTop=0;this.scrollLeft=0;this.replaceCalls=0;this.classList={toggle(){}}}
        set textContent(value){this.text=String(value);this.children.forEach(c=>c.parent=null);this.children=[]}
        get textContent(){return this.text+this.children.map(c=>c.textContent).join('')}
        append(...children){for(const child of children){child.parent=this;this.children.push(child)}}
        replaceChildren(...children){this.replaceCalls++;this.children.forEach(c=>c.parent=null);this.children=[];this.text='';this.append(...children);this.onReplace?.()}
        get value(){return this._value??(this.tagName==='select'?this.children[0]?.value??'':'')}
        set value(value){this._value=String(value)}
        remove(){if(this.parent)this.parent.children=this.parent.children.filter(child=>child!==this);this.parent=null}
        querySelector(selector){const matches=element=>selector.startsWith('.')?(element.className||'').split(' ').includes(selector.slice(1)):element.tagName===selector;for(const child of this.children){if(matches(child))return child;const nested=child.querySelector(selector);if(nested)return nested}return null}
        get firstElementChild(){return this.children[0]||null}
        get isConnected(){return Boolean(this.root||this.parent?.isConnected)}
        get offsetHeight(){return Math.max(this.height??this.children.length*40,parseInt(this.style.minHeight)||0)}
    }
    for(const id of ['content','message','title','modal']){const element=new Element('div');element.id=id;element.root=true;elements.set(id,element)}
    elements.get('modal').open=false;
    const find=(element,id)=>element.id===id?element:element.children.map(child=>find(child,id)).find(Boolean);
    const document={createElement:tag=>new Element(tag),getElementById:id=>elements.get(id)||find(elements.get('content'),id),querySelectorAll:()=>[]};
    const sandbox=vm.createContext({document,window:viewport,Node:Element,URLSearchParams,fmtTime:v=>v?'time:'+v:'—',copyToken:async token=>copies.push(token),
        openDialog:async options=>{if(options.build)options.build(new Element('div'));return options.submit?await options.submit():true},
        setTimeout(fn,delay){assert.equal(delay,3000);timers.set(++timerId,fn);peakTimers=Math.max(peakTimers,timers.size);return timerId},
        clearTimeout(id){if(timers.delete(id))cleared++},
        async api(path,method='GET',data){calls.push({path,method,data});assert.ok(responses.length,'unexpected API request');const response=responses.shift();return typeof response==='function'?await response():await response}
    });
    const extra=management?script.slice(script.indexOf('const stateLabels='),script.indexOf('function node('))+script.slice(script.indexOf('function tokenView('),script.indexOf('async function overview('))+script.slice(script.indexOf('async function analysis('),script.indexOf('async function rules('))+script.slice(script.indexOf('function publishNotice('),script.indexOf('// One reusable component')):'';
    vm.runInContext("let tokenGroupFilter='',tokenPageNumber=1,currentPage='概览';const content=document.getElementById('content'),msg=document.getElementById('message');\n"+domHelpers+domainCode+showCode+extra+"\nconst render={'入口域名':domainPage,'概览':async()=>content.append(node('p','overview'))"+(management?",'Token':tokenPage,'分析':analysis,'日志':logs":"")+"};",sandbox);
    return {timers,responses,calls,viewport,elements,sandbox,copies,get peakTimers(){return peakTimers},get cleared(){return cleared},
        evaluate:code=>vm.runInContext(code,sandbox),show:page=>vm.runInContext(`show(${JSON.stringify(page)})`,sandbox),
        async mount(data){responses.push(data);await this.show('入口域名');return document.getElementById('domain-table')},
        async tick(){const timer=timers.entries().next().value;if(!timer)return;timers.delete(timer[0]);await timer[1]()},
        get container(){return document.getElementById('domain-table')},get content(){return elements.get('content')},get modal(){return elements.get('modal')}
    };
}
async function domainCheck(name,run){try{await run();passed++}catch(error){error.message=name+': '+error.message;throw error}}
for(const state of ['ACTIVE','ERROR'])await domainCheck(state+'-only is completely idle',async()=>{
    const h=domainHarness();await h.mount(domainData(state));assert.equal(h.timers.size,0);assert.equal(h.evaluate('domainPoll'),undefined);await h.tick();assert.equal(h.calls.length,1);
});
for(const state of ['PENDING','REMOVING'])await domainCheck(state+' starts one timer',async()=>{
    const h=domainHarness();await h.mount(domainData(state));assert.equal(h.timers.size,1);assert.equal(h.peakTimers,1);
});
for(const state of ['ACTIVE','ERROR'])await domainCheck('PENDING to '+state+' updates and stops',async()=>{
    const h=domainHarness();await h.mount(domainData('PENDING'));h.responses.push(domainData(state));await h.tick();assert.equal(h.timers.size,0);
    assert.ok(h.container.textContent.includes(state==='ACTIVE'?'正常':'证书申请失败'));assert.ok(h.container.textContent.includes('time:12345'));
    if(state==='ERROR'){assert.ok(h.container.textContent.includes('重试'));assert.ok(h.container.textContent.includes('删除'))}
});
await domainCheck('REMOVING completes and removes its row',async()=>{
    const h=domainHarness();await h.mount(domainData('REMOVING'));h.responses.push(domainData());await h.tick();assert.equal(h.timers.size,0);assert.ok(!h.container.textContent.includes('alias0.example.net'));
});
await domainCheck('one remaining task keeps polling',async()=>{
    const h=domainHarness();await h.mount(domainData('PENDING','REMOVING'));h.responses.push(domainData('ACTIVE','REMOVING'));await h.tick();assert.equal(h.timers.size,1);h.responses.push(domainData('ACTIVE'));await h.tick();assert.equal(h.timers.size,0);
});
for(const [name,pattern] of [['no automatic show',/\bshow\s*\(/],['no whole content replacement',/content\.replaceChildren/],['no whole page render',/\bdomainPage\s*\(/],['no permanent interval',/\bsetInterval\s*\(/]])await domainCheck(name,()=>{
    assert.ok(!pattern.test(pollCode));
    if(name==='no permanent interval')assert.ok(!pattern.test(domainCode));
});
await domainCheck('poll replaces only the domain table and preserves positions',async()=>{
    const h=domainHarness(),container=await h.mount(domainData('PENDING')),pageChildren=[...h.content.children],message=h.elements.get('message');
    message.textContent='keep this notice';container.height=400;container.firstElementChild.scrollTop=37;container.firstElementChild.scrollLeft=21;
    h.responses.push(domainData('PENDING'));await h.tick();assert.deepEqual(h.content.children,pageChildren);assert.equal(h.content.replaceCalls,1);assert.equal(container.replaceCalls,2);
    assert.equal(message.textContent,'keep this notice');assert.equal(h.viewport.scrollY,270);assert.equal(h.viewport.scrollX,11);assert.equal(container.style.minHeight,'400px');assert.equal(container.firstElementChild.scrollTop,37);assert.equal(container.firstElementChild.scrollLeft,21);
});
await domainCheck('credential region is not redrawn by repeated polls',async()=>{
    const h=domainHarness();await h.mount(domainData('PENDING'));const credentials=h.content.children.at(-1),heading=h.content.children[4];
    for(let i=0;i<3;i++){h.responses.push(domainData('PENDING'));await h.tick();assert.equal(h.content.children.at(-1),credentials);assert.equal(h.content.children[4],heading)}
    assert.equal(h.peakTimers,1);assert.equal(h.content.replaceCalls,1);
});
await domainCheck('table layout scroll displacement is restored',async()=>{
    const h=domainHarness(),container=await h.mount(domainData('REMOVING'));container.onReplace=()=>{h.viewport.scrollY=0;h.viewport.scrollX=0};h.responses.push(domainData());await h.tick();assert.equal(h.viewport.scrollY,270);assert.equal(h.viewport.scrollX,11);assert.equal(h.viewport.restores,1);
});
await domainCheck('open modal skips GET and DOM on every tick',async()=>{
    const h=domainHarness(),container=await h.mount(domainData('PENDING'));h.modal.open=true;
    for(let i=0;i<3;i++){await h.tick();assert.equal(h.calls.length,1);assert.equal(container.replaceCalls,1);assert.equal(h.content.replaceCalls,1);assert.equal(h.modal.open,true);assert.equal(h.timers.size,1)}
    h.modal.open=false;h.responses.push(domainData('ACTIVE'));await h.tick();assert.equal(h.timers.size,0);assert.equal(container.replaceCalls,2);
});
await domainCheck('modal opened during GET defers completion DOM until closed',async()=>{
    const h=domainHarness(),container=await h.mount(domainData('PENDING')),request=deferred();h.responses.push(request.promise);const polling=h.tick();h.modal.open=true;request.resolve(domainData('ACTIVE'));await polling;
    assert.equal(container.replaceCalls,1);assert.equal(h.timers.size,1);assert.equal(h.modal.open,true);assert.equal(h.content.replaceCalls,1);
    h.modal.open=false;h.responses.push(domainData('ACTIVE'));await h.tick();assert.equal(container.replaceCalls,2);assert.equal(h.timers.size,0);
});
await domainCheck('navigation cancels scheduled polling',async()=>{
    const h=domainHarness();await h.mount(domainData('PENDING'));await h.show('概览');assert.equal(h.timers.size,0);assert.equal(h.evaluate('domainPoll'),undefined);assert.equal(h.cleared,1);await h.tick();assert.equal(h.calls.length,1);
});
await domainCheck('late poll response does not touch another page',async()=>{
    const h=domainHarness(),container=await h.mount(domainData('PENDING')),request=deferred();h.responses.push(request.promise);const polling=h.tick();await h.show('概览');request.resolve(domainData('ACTIVE'));await polling;
    assert.equal(container.replaceCalls,1);assert.equal(h.content.textContent,'overview');assert.equal(h.timers.size,0);
});
for(const fail of [false,true])await domainCheck('stale '+(fail?'failed':'successful')+' poll cannot overwrite reentered page or timer',async()=>{
    const h=domainHarness();await h.mount(domainData('PENDING'));const request=deferred();h.responses.push(request.promise);const polling=h.tick();await h.show('概览');const current=await h.mount(domainData('REMOVING')),timer=h.evaluate('domainPoll');
    if(fail)request.reject(Error('old request failed'));else request.resolve(domainData('ACTIVE'));await polling;
    assert.equal(current.replaceCalls,1);assert.equal(h.evaluate('domainPoll'),timer);assert.equal(h.timers.size,1);assert.ok(current.textContent.includes('正在删除…'));
});
await domainCheck('stale initial GET cannot append duplicate domain page',async()=>{
    const h=domainHarness(),request=deferred();h.responses.push(request.promise);const old=h.show('入口域名');await h.show('概览');const current=await h.mount(domainData('PENDING'));request.resolve(domainData('ACTIVE'));await old;
    assert.equal(h.container,current);assert.equal(h.content.children.length,7);assert.equal(h.timers.size,1);assert.equal(current.replaceCalls,1);
});
await domainCheck('stale initial GET error does not overwrite another page message',async()=>{
    const h=domainHarness(),request=deferred();h.responses.push(request.promise);const old=h.show('入口域名');await h.show('概览');h.elements.get('message').textContent='new page message';request.reject(Error('旧请求失败'));await old;assert.equal(h.elements.get('message').textContent,'new page message');
});
await domainCheck('repeated manual show never accumulates timers',async()=>{
    const h=domainHarness();for(let i=0;i<4;i++){await h.mount(domainData('PENDING'));assert.equal(h.timers.size,1)}assert.equal(h.peakTimers,1);assert.equal(h.cleared,3);
});
await domainCheck('already queued stale callback cannot start another GET',async()=>{
    const h=domainHarness();await h.mount(domainData('PENDING'));const oldCallback=[...h.timers.values()][0];await h.mount(domainData('REMOVING'));const timer=h.evaluate('domainPoll');await oldCallback();assert.equal(h.calls.length,2);assert.equal(h.evaluate('domainPoll'),timer);assert.equal(h.timers.size,1);
});
await domainCheck('slow GET never overlaps the next poll',async()=>{
    const h=domainHarness();await h.mount(domainData('PENDING'));const request=deferred();h.responses.push(request.promise);const polling=h.tick();assert.equal(h.timers.size,0);await h.tick();assert.equal(h.calls.length,2);request.resolve(domainData('PENDING'));await polling;assert.equal(h.timers.size,1);assert.equal(h.peakTimers,1);
});
await domainCheck('GET failure preserves the table/message and retries a known pending task',async()=>{
    const h=domainHarness(),container=await h.mount(domainData('PENDING'));h.elements.get('message').textContent='keep notice';h.responses.push(()=>{throw Error('network failure')});await h.tick();assert.equal(container.replaceCalls,1);assert.equal(h.elements.get('message').textContent,'keep notice');assert.equal(h.timers.size,1);h.responses.push(domainData('ACTIVE'));await h.tick();assert.equal(h.timers.size,0);
});
const managementTracking={tracking:{groups:[
    {id:9,path:'3.10',status:'ACTIVE',has_active_children:0},
    {id:8,path:'3.1.2',status:'ACTIVE',has_active_children:0},
    {id:3,path:'3',status:'ACTIVE',has_active_children:1},
    {id:7,path:'3.1',status:'ACTIVE',has_active_children:1},
    {id:6,path:'3.1.1',status:'ACTIVE',has_active_children:0},
    {id:4,path:'3.2',status:'ACTIVE',has_active_children:0},
    {id:10,path:'3.3',status:'DRAFT',has_active_children:0}
]}};
function tokenResult(page=1,has_next=false,count=1){return {page,has_next,rows:Array.from({length:count},(_,i)=>({
    id:(page-1)*50+i+1,token:((page-1)*50+i+1).toString(16).padStart(32,'0'),health:100,labels:[],
    tracking_group_path:'3.1.2',requests_1m:1,requests_5m:2,requests_1h:3,requests_24h:4,ips_24h:1,uas_24h:1,errors_24h:0,last_ip:'192.0.2.2',last_ua:'Client/1',last_seen:12345,state:'NORMAL'
}))}}
function walk(element){return [element,...element.children.flatMap(walk)]}
function tagged(h,tag){return walk(h.content).filter(element=>element.tagName===tag)}
function button(h,text){const found=tagged(h,'button').find(element=>element.textContent===text);assert.ok(found,'missing button '+text);return found}
function tokenQuery(h){return new URLSearchParams(h.calls.filter(call=>call.path.startsWith('analysis/tokens?')).at(-1).path.split('?')[1])}
function logQuery(h){return new URLSearchParams(h.calls.filter(call=>call.path.startsWith('logs?')).at(-1).path.split('?')[1])}
async function mountTokens(h,page=1,next=false,count=1){h.evaluate(`tokenPageNumber=${page}`);h.responses.push(managementTracking,tokenResult(page,next,count));await h.show('Token')}
await domainCheck('Token first-page controls and original layout/actions',async()=>{
    const h=domainHarness(true);await mountTokens(h,1,true,50);assert.equal(button(h,'上一页').disabled,true);assert.equal(button(h,'下一页').disabled,false);assert.equal(tokenQuery(h).get('limit'),'50');assert.equal(tokenQuery(h).get('page'),'1');
    assert.equal(tagged(h,'tbody')[0].children.length,50);
    for(const text of ['完整 Token','手动添加','入口组筛选：','健康度','1m','5m','1h','24h','最后IP','最后UA','风险','操作','临时封禁','永久封禁','白名单','详情','解封'])assert.ok(h.content.textContent.includes(text),text);
});
await domainCheck('Token last-page next is disabled and cannot request empty next page',async()=>{
    const h=domainHarness(true);await mountTokens(h,3,false);assert.equal(button(h,'上一页').disabled,false);assert.equal(button(h,'下一页').disabled,true);const calls=h.calls.length;await button(h,'下一页').onclick();assert.equal(h.calls.length,calls);
});
await domainCheck('Token next-page click keeps group filter',async()=>{
    const h=domainHarness(true);h.evaluate("tokenGroupFilter='8'");await mountTokens(h,1,true);h.responses.push(managementTracking,tokenResult(2,true));await button(h,'下一页').onclick();assert.equal(tokenQuery(h).get('page'),'2');assert.equal(tokenQuery(h).get('group_id'),'8');assert.equal(tagged(h,'select').at(-1).value,'8');
});
await domainCheck('Token previous-page click keeps group filter',async()=>{
    const h=domainHarness(true);h.evaluate("tokenGroupFilter='8'");await mountTokens(h,2,true);h.responses.push(managementTracking,tokenResult(1,true));await button(h,'上一页').onclick();assert.equal(tokenQuery(h).get('page'),'1');assert.equal(tokenQuery(h).get('group_id'),'8');assert.equal(button(h,'上一页').disabled,true);
});
await domainCheck('Changing Token group resets to first page',async()=>{
    const h=domainHarness(true);h.evaluate("tokenGroupFilter='8'");await mountTokens(h,3,false);const select=tagged(h,'select').at(-1);select.value='6';h.responses.push(managementTracking,tokenResult(1,true));await select.onchange();assert.equal(tokenQuery(h).get('page'),'1');assert.equal(tokenQuery(h).get('group_id'),'6');assert.equal(h.evaluate('tokenPageNumber'),1);
});
for(const [label,state] of [['白名单','WHITELIST'],['永久封禁','BLOCKED'],['临时封禁','TEMP_BLOCKED'],['解封','NORMAL']])await domainCheck('Token '+state+' action keeps current page/group',async()=>{
    const h=domainHarness(true);h.evaluate("tokenGroupFilter='8'");await mountTokens(h,2,true);h.responses.push({ok:true,publish:{applied:true}},managementTracking,tokenResult(2,true));await button(h,label).onclick();const mutation=h.calls.find(call=>call.method==='PATCH');assert.equal(mutation.path,'tokens/51/state');assert.equal(mutation.data.state,state);if(state==='TEMP_BLOCKED')assert.ok(mutation.data.expires_at>Date.now()/1000);assert.equal(tokenQuery(h).get('page'),'2');assert.equal(tokenQuery(h).get('group_id'),'8');
});
await domainCheck('Manual Token addition resets first page without changing group',async()=>{
    const h=domainHarness(true);h.evaluate("tokenGroupFilter='8'");await mountTokens(h,2,true);tagged(h,'input')[0].value='0123456789abcdef0123456789abcdef';h.responses.push({ok:true,publish:{applied:true}},managementTracking,tokenResult(1,true));await button(h,'手动添加').onclick();assert.equal(tokenQuery(h).get('page'),'1');assert.equal(tokenQuery(h).get('group_id'),'8');assert.equal(h.calls.find(call=>call.method==='POST').data.token,'0123456789abcdef0123456789abcdef');
});
await domainCheck('Empty current Token page falls back to previous page',async()=>{
    const h=domainHarness(true);h.evaluate("tokenGroupFilter='8';tokenPageNumber=2");h.responses.push(managementTracking,tokenResult(2,false,0),tokenResult(1,false,2));await h.show('Token');assert.equal(tokenQuery(h).get('page'),'1');assert.equal(tokenQuery(h).get('group_id'),'8');assert.equal(h.calls.filter(call=>call.path.startsWith('analysis/')).length,2);assert.equal(h.evaluate('tokenPageNumber'),1);
});
await domainCheck('Disappeared Token group has bounded fallback instead of infinite empty pages',async()=>{
    const h=domainHarness(true);h.evaluate("tokenGroupFilter='8';tokenPageNumber=8");h.responses.push(managementTracking,tokenResult(8,false,0),tokenResult(7,false,0),tokenResult(1,false,0));await h.show('Token');assert.equal(h.calls.filter(call=>call.path.startsWith('analysis/')).length,3);assert.equal(h.evaluate('tokenPageNumber'),1);assert.equal(button(h,'下一页').disabled,true);
});
await domainCheck('Analysis stays first-page recent-50 view without pagination UI',async()=>{
    const h=domainHarness(true);h.evaluate('tokenPageNumber=5');h.responses.push(tokenResult(1,true));await h.show('分析');assert.equal(tokenQuery(h).get('limit'),'50');assert.equal(tokenQuery(h).has('page'),false);assert.ok(h.content.textContent.includes('最近50个 Token'));assert.ok(!tagged(h,'button').some(element=>['上一页','下一页'].includes(element.textContent)));assert.equal(h.content.children.length,2);
});
await domainCheck('Token complete-value double-click copy is unchanged',async()=>{
    const h=domainHarness(true);await mountTokens(h);const token=walk(h.content).find(element=>element.className==='token-full');await token.ondblclick();assert.equal(token.textContent,'1'.padStart(32,'0'));assert.deepEqual(h.copies,['1'.padStart(32,'0')]);
});
const logResult=page=>({result:{page,rows:[{created_at:12345,token:'1'.padStart(32,'0'),tracking_group_path:'3.1.2',client_ip:'192.0.2.2',user_agent:'Client/1',status_code:403,decision:'TOKEN_BLOCKED',request_path:'/api/v1/test/subscribe'}]}});
async function mountLogs(h){h.responses.push(managementTracking,logResult(1));await h.show('日志')}
await domainCheck('Log group dropdown includes parents in natural path order',async()=>{
    const h=domainHarness(true);await mountLogs(h);assert.deepEqual(tagged(h,'select').at(-1).children.map(option=>option.textContent),['全部入口组','3','3.1','3.1.1','3.1.2','3.2','3.10']);assert.equal(logQuery(h).has('group_id'),false);assert.ok(tagged(h,'th').some(element=>element.textContent==='入口组'));assert.ok(h.content.textContent.includes('3.1.2'));
});
await domainCheck('Log group query combines all existing filters',async()=>{
    const h=domainHarness(true);await mountLogs(h);const inputs=tagged(h,'input'),selects=tagged(h,'select');inputs[0].value='1'.padStart(32,'0');inputs[1].value='192.0.2.2';inputs[2].value='Client/1';selects[0].value='7d';selects[1].value='403';selects[2].value='TOKEN_BLOCKED';selects[3].value='7';h.responses.push(logResult(1));await button(h,'查询').onclick();const query=logQuery(h);
    for(const [key,value] of Object.entries({group_id:'7',token:'1'.padStart(32,'0'),ip:'192.0.2.2',ua:'Client/1',window:'7d',status:'403',decision:'TOKEN_BLOCKED',page:'1'}))assert.equal(query.get(key),value);
});
await domainCheck('Log next and previous pages preserve selected group and filters',async()=>{
    const h=domainHarness(true);await mountLogs(h);tagged(h,'select').at(-1).value='7';tagged(h,'input')[1].value='192.0.2.2';h.responses.push(logResult(2));await button(h,'下一页').onclick();assert.equal(logQuery(h).get('page'),'2');assert.equal(logQuery(h).get('group_id'),'7');assert.equal(logQuery(h).get('ip'),'192.0.2.2');h.responses.push(logResult(1));await button(h,'上一页').onclick();assert.equal(logQuery(h).get('page'),'1');assert.equal(logQuery(h).get('group_id'),'7');
});
await domainCheck('Log query after group change starts first page',async()=>{
    const h=domainHarness(true);await mountLogs(h);h.responses.push(logResult(2));await button(h,'下一页').onclick();h.responses.push(logResult(3));await button(h,'下一页').onclick();tagged(h,'select').at(-1).value='6';h.responses.push(logResult(1));await button(h,'查询').onclick();assert.equal(logQuery(h).get('page'),'1');assert.equal(logQuery(h).get('group_id'),'6');
});
await domainCheck('Late Token page response cannot append onto another page',async()=>{
    const h=domainHarness(true),request=deferred();h.responses.push(managementTracking,request.promise);const old=h.show('Token');await Promise.resolve();await h.show('概览');request.resolve(tokenResult(1,true));await old;assert.equal(h.content.textContent,'overview');
});
console.log(`PASS: ${passed} tracking/domain UI JavaScript checks`);
