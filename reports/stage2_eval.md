# Stage 2 evaluation (certificate check, v1 points table)

Generated 2026-10-17 20:28 UTC on s390x 3.12.3 by `python -m model.stage2 eval`. Era-stable features only (names on the certificate; no issuer, no dates). Names below are plain text: do not open them.

## Points table

| feature | at least | points |
|---|---:|---:|
| `distinct_brands_on_cert` | 2 | +0.30 |
| `distinct_brands_on_cert` | 3 | +0.15 |
| `brand_registered_domains` | 3 | +0.15 |
| `kit_names_with_brand` | 2 | +0.10 |

Capped at 0.6. A certificate that also covers an official site (labels/official.txt) gets 0. Stage 2 can only raise a score: `final = 1 - (1 - s1) * (1 - boost)`.

## Live certificates (the false-boost check)

Recording `data/recordings/ct-20261017-153717.jsonl.gz`: **1,174,161 unique certificates**, 1,617,290 names. **7,199 certificates** (8,751 names, 0.54% of names) pass the brand gate; only these reach Stage 2. Almost all of them are ordinary sites, so a good table boosts ~none.

| | v1 table (this PR) | spec §7 example table |
|---|---:|---:|
| gated live certs boosted | **0 (0.00%)** | 3,068 (42.62%) |
| boost histogram | 0.00: 7,199 | 0.00: 4,131, 0.05: 2,141, 0.10: 467, 0.15: 1, 0.25: 248, 0.30: 161, 0.40: 32, 0.45: 18 |

Rule fires on gated live certs: -

Why live names pass the brand gate (input for `gate_rate`, MODEL_SPEC §6.2):

| reason | names | share |
|---|---:|---:|
| misspelled brand | 6,580 | 75.2% |
| fake pattern 'us-'/'net-'/'org-' prefix | 1,688 | 19.3% |
| brand word | 412 | 4.7% |
| '.com-'/'gov-' trick | 71 | 0.8% |

## Known scam certificates (crt.sh)

Brand-tagged toll/delivery/gov scams from `labels.db` (outside feeds only). 16 registered domains queried on crt.sh: 7 had certificates, 8 had none logged, 2 errors. **12 certificates** (delivery: 7, gov: 5).

| | v1 table | spec example |
|---|---:|---:|
| scam certs boosted | **0 (0.0%)** | 6 (50.0%) |
| boost histogram | 0.00: 12 | 0.00: 6, 0.05: 4, 0.40: 2 |

Rule fires: -

Names per scam certificate (p50/p90/p99/max): 1/1/7/7

## How kit-like are known scams? (labels.db)

Of 3,512 registered domains with toll/delivery/gov scams, 73 have 2+ listed names and 24 have 2+ different brands. The multi-brand ones are mostly shared hosting, not kits: surge.sh (32 names: ipass/violation), weebly.com (26 names: dhl/epass/irs), codeanyapp.com (17 names: dhl/fedex/ipass/parcel/redeliver), 000webhostapp.com (16 names: dhl/epass/parcel), swtest.ru (10 names: dhl/fedex/parcel), easywp.com (6 names: dhl/fedex/parcel), appdomain.cloud (4 names: dhl/epass/parcel), blogspot.ba (3 names: dhl/usps). So most real scams are one name on one throwaway domain: Stage 2 rarely fires, and when it can't tell, it adds nothing (a plain certificate is neutral).

## Speed

`boost()`: 55.5 µs for a new certificate, 3.83 µs for the next name on the same certificate (cached), one core. Only gated names reach it (8,751 in the whole recording).

## Examples (plain text)

Live certificates boosted by v1:

- none

Live certificates the spec example table would boost but v1 does not (first few):

- 0.45: polina-epics-dev-667-new-plans-apimock.wfolio.work, polina-epics-dev-667-new-plans-com.wfolio.work, polina-epics-dev-667-new-plans-micro.wfolio.work, polina-epics-dev-667-new-plans.wfolio.work
- 0.45: ext.redriver-098c9054.newzealandnorth.azurecontainerapps.io, internal.redriver-098c9054.newzealandnorth.azurecontainerapps.io, redriver-098c9054.newzealandnorth.azurecontainerapps.io, scm.redriver-098c9054.newzealandnorth.azurecontainerapps.io
- 0.45: 3.subarumerrillville.com, adaptivemind.com, analitik.entis.io, api.entis.io, api.savraai.club, app.entis.io
- 0.45: ext.redriver-237f5978.westus2.azurecontainerapps.io, internal.redriver-237f5978.westus2.azurecontainerapps.io, redriver-237f5978.westus2.azurecontainerapps.io, scm.redriver-237f5978.westus2.azurecontainerapps.io
- 0.45: access.tlen.org, adm.paturnpike.co, admin.paturnpike.co, alpha.paturnpike.co, app.paturnpike.co, appgyver.paturnpike.co
- 0.45: 1000.pornotribune.net, 10141.pornotribune.net, 1125.pornotribune.net, 1591da92-a45a-463b-87ab-34a8ae7266c3.spokanimal.com, 16.mirreryeshiva.com, 1647.pornotribune.net
- 0.45: ext.redriver-4a1eac65.eastus.azurecontainerapps.io, internal.redriver-4a1eac65.eastus.azurecontainerapps.io, redriver-4a1eac65.eastus.azurecontainerapps.io, scm.redriver-4a1eac65.eastus.azurecontainerapps.io
- 0.45: ext.redriver-db4d8d37.northcentralusstage.azurecontainerapps.io, internal.redriver-db4d8d37.northcentralusstage.azurecontainerapps.io, redriver-db4d8d37.northcentralusstage.azurecontainerapps.io, scm.redriver-db4d8d37.northcentralusstage.azurecontainerapps.io
- 0.45: admin.happy-grass.com, happy-grass.com, m.happy-grass.com, mail.happy-grass.com
- 0.45: apps.fdsex-137c05c9-4d31-4fc7-8a3c-174c4416639b.azurehdinsight.net, fdsex-137c05c9-4d31-4fc7-8a3c-174c4416639b-int.azurehdinsight.net, fdsex-137c05c9-4d31-4fc7-8a3c-174c4416639b-kafkarest.azurehdinsight.net, fdsex-137c05c9-4d31-4fc7-8a3c-174c4416639b.azurehdinsight.net
- 0.45: apps.fdsex-f95acdc9-8876-4664-815d-92a4bf16c794.azurehdinsight.net, fdsex-f95acdc9-8876-4664-815d-92a4bf16c794-int.azurehdinsight.net, fdsex-f95acdc9-8876-4664-815d-92a4bf16c794-kafkarest.azurehdinsight.net, fdsex-f95acdc9-8876-4664-815d-92a4bf16c794.azurehdinsight.net
- 0.45: ext.redriver-68f48811.germanywestcentral.azurecontainerapps.io, internal.redriver-68f48811.germanywestcentral.azurecontainerapps.io, redriver-68f48811.germanywestcentral.azurecontainerapps.io, scm.redriver-68f48811.germanywestcentral.azurecontainerapps.io

Known scam certificates:

- 0.00 [delivery]: cpanel.postoffice-redeliveritem.com, cpcalendars.postoffice-redeliveritem.com, cpcontacts.postoffice-redeliveritem.com, mail.postoffice-redeliveritem.com, postoffice-redeliveritem.com, webdisk.postoffice-redeliveritem.com, webmail.postoffice-redeliveritem.com
- 0.00 [gov]: finance91-exercitationem57.pro
- 0.00 [gov]: finance91-exercitationem57.pro
- 0.00 [delivery]: usps-informedo.top
- 0.00 [delivery]: usps-informedo.top
- 0.00 [gov]: 1715669140-staging.surge.sh
- 0.00 [gov]: main.tmtg.surge.sh
- 0.00 [delivery]: prod.us-east4.jibeapply.com
- 0.00 [delivery]: jibeapply.com
- 0.00 [gov]: cpanel.irsdepartement-gov.com, cpcalendars.irsdepartement-gov.com, cpcontacts.irsdepartement-gov.com, irsdepartement-gov.com, mail.irsdepartement-gov.com, webdisk.irsdepartement-gov.com, webmail.irsdepartement-gov.com
- 0.00 [delivery]: dhl.smolfryz.com
- 0.00 [delivery]: smolfryz.com
