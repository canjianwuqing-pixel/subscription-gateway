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
for (const count of [2, 3, 4, 20]) {
    const paths = Array.from(context.trackingSplitPreview('1.2', count));
    assert.equal(paths.length, count);
    assert.equal(paths[0], '1.2.1');
    assert.equal(paths.at(-1), '1.2.' + count);
    passed++;
}
for (const count of [1, 21, 3.5, NaN]) { assert.equal(context.trackingSplitPreview('1.2', count).length, 0); passed++; }
console.log(`PASS: ${passed} tracking UI JavaScript checks`);
