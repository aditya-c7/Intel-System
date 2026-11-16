/**
 * ASN enrichment matrix (registry / cache tiers; no network required).
 *
 *   npx tsx scripts/test-asn-enricher.ts
 *
 * Exercises the bundled registry, the `AS<number>` degradation path and the
 * Cymru AS-name cleaner. DNS tiers are skipped here because the sandbox may
 * block them; the function still has to answer from the registry.
 */
import {
  cleanCymruAsName,
  enrichNetwork,
  registryEntryForAsn,
  registryEntryForIp,
  resolveAsnOrganization,
  subnetOf,
} from '../src/server/network/asnEnricher';

let failures = 0;

function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`ok   ${name}`);
    return;
  }
  failures += 1;
  console.error(`FAIL ${name}`);
  if (detail !== undefined) console.error('     ', detail);
}

async function main(): Promise<void> {
  /* Registry tier ----------------------------------------------------------- */
  const required: Array<[number, string]> = [
    [55836, 'Reliance Jio Infocomm Limited'],
    [24560, 'Bharti Airtel Ltd., Telemedia Services'],
    [13335, 'Cloudflare, Inc.'],
    [15169, 'Google LLC'],
    [16509, 'Amazon.com, Inc.'],
    [14618, 'Amazon.com, Inc.'],
    [8075, 'Microsoft Corporation'],
    [12076, 'Microsoft Corporation'],
    [14061, 'DigitalOcean, LLC'],
    [32934, 'Meta Platforms, Inc.'],
    [399358, 'Anthropic, PBC'],
    [400645, 'OpenAI'],
    [212949, 'Mistral AI'],
    [396986, 'ByteDance'],
    [714, 'Apple Inc.'],
    [6185, 'Apple Inc.'],
  ];
  for (const [asn, name] of required) {
    const entry = registryEntryForAsn(asn);
    check(`registry AS${asn} → ${name}`, entry?.asn_name === name, entry?.asn_name);
  }

  check('registry AS16509 is a datacenter', registryEntryForAsn(16509)?.datacenter_result === true);
  check('registry AS55836 is an isp', registryEntryForAsn(55836)?.asn_type === 'isp');

  const prefix = registryEntryForIp('49.44.63.9');
  check('prefix containment 49.44.63.9 → AS55836', prefix?.entry.asn === 55836, prefix?.prefix);

  /* ASN-only resolver ------------------------------------------------------- */
  const jio = await resolveAsnOrganization(55836);
  check('resolveAsnOrganization(55836) is registry-sourced', jio.source === 'registry', jio);
  check('resolveAsnOrganization(55836) names Jio', jio.asn_name === 'Reliance Jio Infocomm Limited', jio);

  const byString = await resolveAsnOrganization('AS55836');
  check('AS-prefixed strings are accepted', byString.asn === '55836', byString);

  const unknown = await resolveAsnOrganization(64512);
  check('unknown ASN resolves to source none', unknown.source === 'none', unknown);
  check('unknown ASN still reports its number', unknown.asn === '64512', unknown);

  /* enrichNetwork registry tier -------------------------------------------- */
  const network = await enrichNetwork('49.44.63.9');
  check('enrichNetwork registry prefix match', network.asn === '55836', network);
  check('enrichNetwork keeps the ISP name', network.asn_name === 'Reliance Jio Infocomm Limited', network);

  const byEdge = await enrichNetwork('198.51.100.7', { asn: 55836 });
  check('enrichNetwork resolves an edge ASN from the registry', byEdge.asn_name === 'Reliance Jio Infocomm Limited', byEdge);

  const unresolved = await enrichNetwork('203.0.113.7');
  check('unresolved network never fabricates a name', unresolved.asn_name === '', unresolved);

  /* Cymru AS-name cleaning -------------------------------------------------- */
  check(
    'cleanCymruAsName strips handle + , IN',
    cleanCymruAsName('RELIANCEJIO-IN - Reliance Jio Infocomm Limited, IN') ===
      'Reliance Jio Infocomm Limited',
    cleanCymruAsName('RELIANCEJIO-IN - Reliance Jio Infocomm Limited, IN'),
  );
  check(
    'cleanCymruAsName keeps the operator name',
    cleanCymruAsName('GOOGLE - Google LLC, US') === 'Google LLC',
    cleanCymruAsName('GOOGLE - Google LLC, US'),
  );
  check(
    'cleanCymruAsName strips a mixed-case handle',
    cleanCymruAsName('docomo - NTT DOCOMO, INC., JP') === 'NTT DOCOMO, INC.',
    cleanCymruAsName('docomo - NTT DOCOMO, INC., JP'),
  );
  check(
    'cleanCymruAsName leaves a plain name alone',
    cleanCymruAsName('Bharti Airtel Ltd., Telemedia Services') ===
      'Bharti Airtel Ltd., Telemedia Services',
    cleanCymruAsName('Bharti Airtel Ltd., Telemedia Services'),
  );

  /* Subnet bucketing (unchanged behaviour) ---------------------------------- */
  check('subnetOf IPv4 /24', subnetOf('49.44.63.9') === '49.44.63/24', subnetOf('49.44.63.9'));
  check('subnetOf IPv6 /64', subnetOf('2600:1700:12f0::1') === '2600:1700:12f0:0::/64', subnetOf('2600:1700:12f0::1'));

  if (failures > 0) {
    console.error(`\n${failures} expectation(s) failed`);
    process.exit(1);
  }
  console.log('\nAll ASN enricher expectations passed');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
