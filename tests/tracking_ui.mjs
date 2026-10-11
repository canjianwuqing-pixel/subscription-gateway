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
console.log(`PASS: ${passed} tracking/domain UI JavaScript checks`);
