/**
 * Shadow-only tests for `src/lib/activeCdp.ts`.
 *
 * Covers all five states, the two "only with corroboration" rules (second client +
 * elevated name getter => active inspection; docked devtools => developer_tools true
 * only), flag values, reason tokens, thresholds, hostile-input safety, purity, and the
 * "never bad bot" invariant.
 *
 *   npx tsx scripts/test-active-cdp.ts
 *
 * Exits non-zero when any assertion fails. Nothing here writes state or schedules work.
 */
import {
  resolveActiveCdp,
  ELEVATED_NAME_GETTER_COUNT,
  ELEVATED_PREPARE_STACK_COUNT,
  type ActiveCdpInput,
  type ActiveCdpResult,
  type ActiveCdpState,
} from '../src/lib/activeCdp';

let assertions = 0;
let failures = 0;

function check(name: string, condition: boolean, detail?: unknown): void {
  assertions += 1;
  if (condition) {
    console.log(`ok   ${name}`);
    return;
  }
  failures += 1;
  console.error(`FAIL ${name}`);
  if (detail !== undefined) console.error('     ', detail);
}

/** Assert that a thunk returns without throwing. */
function doesNotThrow(name: string, fn: () => unknown): void {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  check(name, !threw);
}

const ALL_STATES: ReadonlySet<string> = new Set<ActiveCdpState>([
  'none',
  'automation_protocol_attached',
  'automation_protocol_inspection_active',
  'docked_devtools',
  'corroborated',
]);

/* -------------------------------------------------------------------------- */
/* 1. none                                                                    */
/* -------------------------------------------------------------------------- */

const empty = resolveActiveCdp({});
check('N1 empty input → none', empty.state === 'none', empty);
check('N2 none has cdp_attached false', empty.cdp_attached === false, empty);
check('N3 none has developer_tools false', empty.developer_tools === false, empty);
check('N4 none has a non-empty reason', empty.reasons.length > 0, empty);

const zeroCounts = resolveActiveCdp({
  runtimeEnableCount: 0,
  nameGetterCount: 0,
  prepareStackTraceCount: 0,
  secondClientAttached: false,
  devtoolsAttached: false,
});
check('N5 zero counters → none', zeroCounts.state === 'none', zeroCounts);

/* -------------------------------------------------------------------------- */
/* 2. automation_protocol_attached                                            */
/* -------------------------------------------------------------------------- */

const runtimeOnly = resolveActiveCdp({ runtimeEnableCount: 1 });
check('A1 Runtime.enable alone → automation_protocol_attached', runtimeOnly.state === 'automation_protocol_attached', runtimeOnly);
check('A2 attached state has cdp_attached true', runtimeOnly.cdp_attached === true, runtimeOnly);
check('A3 attached state has developer_tools false', runtimeOnly.developer_tools === false, runtimeOnly);
check('A4 attached reason includes runtime_domain_enabled', runtimeOnly.reasons.includes('runtime_domain_enabled'), runtimeOnly);

const secondOnly = resolveActiveCdp({ secondClientAttached: true });
check('A5 second client alone (no elevated getter) → automation_protocol_attached', secondOnly.state === 'automation_protocol_attached', secondOnly);
check('A6 second-client attachment sets cdp_attached true', secondOnly.cdp_attached === true, secondOnly);

const getterAlone = resolveActiveCdp({ nameGetterCount: ELEVATED_NAME_GETTER_COUNT });
check('A7 elevated getter without a second client is NOT active inspection', getterAlone.state === 'none', getterAlone);

/* -------------------------------------------------------------------------- */
/* 3. automation_protocol_inspection_active                                   */
/* -------------------------------------------------------------------------- */

const inspecting = resolveActiveCdp({
  runtimeEnableCount: 2,
  nameGetterCount: ELEVATED_NAME_GETTER_COUNT,
  secondClientAttached: true,
});
check('I1 second client + elevated getter → automation_protocol_inspection_active', inspecting.state === 'automation_protocol_inspection_active', inspecting);
check('I2 inspection state has cdp_attached true', inspecting.cdp_attached === true, inspecting);
check('I3 inspection state has developer_tools false', inspecting.developer_tools === false, inspecting);
check('I4 inspection reason includes name_getter_elevated', inspecting.reasons.includes('name_getter_elevated'), inspecting);

const inspectingMinimal = resolveActiveCdp({
  nameGetterCount: ELEVATED_NAME_GETTER_COUNT,
  secondClientAttached: true,
});
check('I5 inspection does not require Runtime.enable count', inspectingMinimal.state === 'automation_protocol_inspection_active', inspectingMinimal);

const belowThreshold = resolveActiveCdp({
  nameGetterCount: ELEVATED_NAME_GETTER_COUNT - 1,
  secondClientAttached: true,
});
check('I6 getter below elevated threshold with second client → attached, not inspection', belowThreshold.state === 'automation_protocol_attached', belowThreshold);

/* -------------------------------------------------------------------------- */
/* 4. docked_devtools                                                         */
/* -------------------------------------------------------------------------- */

const docked = resolveActiveCdp({ devtoolsAttached: true });
check('D1 docked devtools → docked_devtools', docked.state === 'docked_devtools', docked);
check('D2 docked devtools has developer_tools true', docked.developer_tools === true, docked);
check('D3 docked devtools has cdp_attached false (developer_tools true ONLY)', docked.cdp_attached === false, docked);
check('D4 docked reason includes devtools_attached', docked.reasons.includes('devtools_attached'), docked);

const stackInspect = resolveActiveCdp({ prepareStackTraceCount: ELEVATED_PREPARE_STACK_COUNT });
check('D5 elevated prepareStackTrace alone → docked_devtools', stackInspect.state === 'docked_devtools', stackInspect);
check('D6 elevated prepareStackTrace has developer_tools true', stackInspect.developer_tools === true, stackInspect);
check('D7 prepareStackTrace below threshold → none', resolveActiveCdp({ prepareStackTraceCount: ELEVATED_PREPARE_STACK_COUNT - 1 }).state === 'none');

const devtoolsOverridesRuntime = resolveActiveCdp({
  runtimeEnableCount: 3,
  devtoolsAttached: true,
});
check('D8 docked devtools outweighs a bare Runtime.enable client', devtoolsOverridesRuntime.state === 'docked_devtools' && devtoolsOverridesRuntime.developer_tools === true && devtoolsOverridesRuntime.cdp_attached === false, devtoolsOverridesRuntime);

const devtoolsWithGetterButNoSecondClient = resolveActiveCdp({
  devtoolsAttached: true,
  nameGetterCount: ELEVATED_NAME_GETTER_COUNT,
});
check('D9 devtools + elevated getter without second client stays docked_devtools', devtoolsWithGetterButNoSecondClient.state === 'docked_devtools', devtoolsWithGetterButNoSecondClient);

/* -------------------------------------------------------------------------- */
/* 5. corroborated                                                            */
/* -------------------------------------------------------------------------- */

const corroborated = resolveActiveCdp({
  runtimeEnableCount: 2,
  nameGetterCount: ELEVATED_NAME_GETTER_COUNT,
  secondClientAttached: true,
  devtoolsAttached: true,
});
check('C1 inspection + devtools → corroborated', corroborated.state === 'corroborated', corroborated);
check('C2 corroborated has cdp_attached true', corroborated.cdp_attached === true, corroborated);
check('C3 corroborated has developer_tools true', corroborated.developer_tools === true, corroborated);
check('C4 corroborated reason includes both evidence families', corroborated.reasons.includes('name_getter_elevated') && corroborated.reasons.includes('devtools_attached'), corroborated);

const corroboratedViaStack = resolveActiveCdp({
  nameGetterCount: ELEVATED_NAME_GETTER_COUNT,
  secondClientAttached: true,
  prepareStackTraceCount: ELEVATED_PREPARE_STACK_COUNT,
});
check('C5 active inspection + stack introspection → corroborated', corroboratedViaStack.state === 'corroborated', corroboratedViaStack);

/* -------------------------------------------------------------------------- */
/* 6. reason tokens & state invariants                                        */
/* -------------------------------------------------------------------------- */

const samples: ActiveCdpResult[] = [
  empty,
  runtimeOnly,
  inspecting,
  docked,
  corroborated,
];
check('R1 every sample state is one of the five allowed states', samples.every((r) => ALL_STATES.has(r.state)), samples.map((r) => r.state));
check('R2 every sample ends its reasons with its state token', samples.every((r) => r.reasons[r.reasons.length - 1] === r.state), samples);
check('R3 every sample has at least one reason', samples.every((r) => r.reasons.length >= 1), samples);
check('R4 all five states are reachable', new Set(samples.map((r) => r.state)).size === 5, samples.map((r) => r.state));
check('R5 none outcome token equals state', empty.reasons[empty.reasons.length - 1] === 'none', empty);

/* -------------------------------------------------------------------------- */
/* 7. never bad bot                                                           */
/* -------------------------------------------------------------------------- */

check('B1 result exposes exactly the four declared fields (no verdict field)', samples.every((r) => {
  const keys = Object.keys(r).sort();
  return JSON.stringify(keys) === JSON.stringify(['cdp_attached', 'developer_tools', 'reasons', 'state']);
}), samples.map((r) => Object.keys(r)));
check('B2 no reason token contains a bad-bot verdict', samples.every((r) => r.reasons.every((why) => !/bot|automated-runtime|verdict/i.test(why))), samples.map((r) => r.reasons));

/* -------------------------------------------------------------------------- */
/* 8. hostile input safety                                                    */
/* -------------------------------------------------------------------------- */

doesNotThrow('H1 null input does not throw', () => resolveActiveCdp(null as unknown as ActiveCdpInput));
doesNotThrow('H2 string input does not throw', () => resolveActiveCdp('garbage' as unknown as ActiveCdpInput));
doesNotThrow('H3 number input does not throw', () => resolveActiveCdp(42 as unknown as ActiveCdpInput));
doesNotThrow('H4 undefined input does not throw', () => resolveActiveCdp(undefined as unknown as ActiveCdpInput));

const throwingGetters: ActiveCdpInput = {
  get runtimeEnableCount(): unknown { throw new Error('boom'); },
  get nameGetterCount(): unknown { throw new Error('boom'); },
  get prepareStackTraceCount(): unknown { throw new Error('boom'); },
  get secondClientAttached(): unknown { throw new Error('boom'); },
  get devtoolsAttached(): unknown { throw new Error('boom'); },
};
doesNotThrow('H5 getters that throw do not throw', () => resolveActiveCdp(throwingGetters));
check('H6 throwing getters fail closed to none', resolveActiveCdp(throwingGetters).state === 'none');

const hostileProxy = new Proxy({}, { get(): unknown { throw new Error('no read'); } });
doesNotThrow('H7 hostile proxy does not throw', () => resolveActiveCdp(hostileProxy as ActiveCdpInput));
check('H8 hostile proxy fails closed to none', resolveActiveCdp(hostileProxy as ActiveCdpInput).state === 'none');

const poisoned = resolveActiveCdp({
  runtimeEnableCount: Number.NaN,
  nameGetterCount: -5,
  prepareStackTraceCount: Infinity,
  secondClientAttached: 'true',
  devtoolsAttached: 1,
});
check('H9 poisoned values fail closed to none', poisoned.state === 'none', poisoned);

const floored = resolveActiveCdp({
  nameGetterCount: ELEVATED_NAME_GETTER_COUNT + 0.9,
  secondClientAttached: true,
});
check('H10 fractional elevated count is floored but still elevated', floored.state === 'automation_protocol_inspection_active', floored);

/* -------------------------------------------------------------------------- */
/* 9. purity & determinism                                                    */
/* -------------------------------------------------------------------------- */

const pureInput: ActiveCdpInput = {
  runtimeEnableCount: 1,
  nameGetterCount: ELEVATED_NAME_GETTER_COUNT,
  prepareStackTraceCount: 1,
  secondClientAttached: true,
  devtoolsAttached: false,
};
const inputSnapshot = JSON.stringify(pureInput);
resolveActiveCdp(pureInput);
check('P1 input is not mutated', JSON.stringify(pureInput) === inputSnapshot, pureInput);
const repeatA = resolveActiveCdp(pureInput);
const repeatB = resolveActiveCdp(pureInput);
check('P2 identical inputs yield identical results', JSON.stringify(repeatA) === JSON.stringify(repeatB), { repeatA, repeatB });

/* -------------------------------------------------------------------------- */

console.log(
  `\nactive cdp: ${assertions - failures}/${assertions} assertions passed` +
    (failures ? `, ${failures} FAILED` : '')
);
if (failures > 0) process.exitCode = 1;
