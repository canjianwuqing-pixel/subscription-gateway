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
for (const [filled, text, className] of [[6, '6/6 已完成', 'mapping-done'], [4, '4/6 未完成', 'mapping-partial'], [0, '0/6 未配置', 'mapping-missing']]) {
    const result = context.trackingMappingState({...group, mapping_filled_count: filled});
    assert.equal(result.text, text);
    assert.ok(result.className.includes(className));
    assert.equal(result.complete, filled === 6);
    passed++;
}
assert.equal(context.trackingMappingState({...group, has_active_children: 1, mapping_filled_count: 0}).text, '已拆分'); passed++;
assert.equal(context.trackingMappingState({...group, status: 'DRAFT', mapping_filled_count: 0}).text, '0/6 未配置 · 待配置'); passed++;
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
console.log(`PASS: ${passed} tracking UI JavaScript checks`);
