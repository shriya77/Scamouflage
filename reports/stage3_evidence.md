# Stage 3 Domain Verifier Evidence Report

**Generated:** 2026-10-17T20:53:07Z by `python -m model.stage3_stats` (cached, rate-limited RDAP via rdap.org; registry metadata only, no site is contacted).  
**Scam sample:** 150 registered domains, picked in a stable hash order from 3,053 brand-tagged toll/delivery/gov registered domains in `labels.db` (3,914 label rows; 459 names on shared hosting left out because RDAP would describe the platform). Categories: toll 23, delivery 99, gov 28.  
**Normal sample:** 67 brand-word sites from Tranco (`negatives`) plus `labels/official.txt`.

## 1. Key findings (computed, for the slides)

- **Age when we first saw it on a feed:** median **306.4 days** (N=24); **0 of 24** (0.0%) were under 3 days old, 0 (0.0%) under 30 days.
- **Normal brand-word sites:** median age **17.52 years** (N=60); 5 of 60 are under a year old.
- **Registrars:** 9.0% of our scam domains (N=22) use the three Unit 42 registrars (Dominet, NameSilo, Gname), against 87.85% in Unit 42's Smishing Triad data. Our sample covers all toll/delivery/gov phishing in the feeds, not only that one group, so it is far more spread out.
- **Lookups that failed:** not_found: 99, rate_limited: 27 (of 150). They are counted, not dropped. Top TLDs per error: not_found: .top 25, .com 25, .ml 10, .cc 8, .xin 7; rate_limited: .top 27. `rate_limited` means the TLD's own registry refused (rdap.org redirects to it); `not_found` means the registry has no record (typically deleted or suspended).

Note: `first_seen` is when OUR feeds loop first saw the name on a list. The loop started on 2026-10-17, so for names that were already listed before then this is an upper bound on the age at listing, not the age at first listing.

## 2. Domain age

| | Scam domains | Normal brand-word sites |
|---|---:|---:|
| RDAP answered | 24 of 150 | 60 of 67 |
| Median age today | 306.6 days | 17.52 years |
| Median age when first seen on a feed | 306.4 days | - |
| Under 3 days when first seen | 0 (0.0%) | - |
| Under 7 days when first seen | 0 (0.0%) | - |
| Under 30 days when first seen | 0 (0.0%) | - |
| Under 365 days when first seen | 13 (54.2%) | - |
| Under 365 days today | - | 5 (8.3%) |
| Failed lookups | not_found: 99, rate_limited: 27 | not_found: 7 |

## 3. Registrar distribution vs Unit 42

| Registrar group | Scamouflage measured (N=22) | Unit 42 Smishing Triad |
|---|---:|---:|
| Dominet (HK) | 4.5% (1) | 68.06% |
| NameSilo | 0.0% (0) | 11.85% |
| Gname | 4.5% (1) | 7.94% |
| Others | 90.9% (20) | 12.15% |

Risky registrar (labels/risky_registrars.txt) among answered scam domains: 2 of 24 (8.3%); among normal sites: 1 of 60.

## 4. Live alerts

HIGH removed / MAYBE rescued counts need live alerts from the engine; not available yet.

## 5. Sample (plain text, do not open)

| Registered domain | Brand | First seen | Registered | Age when first seen | Registrar |
|---|---|---|---|---:|---|
| com-ioiakil.top | ezdrive | 2026-10-17 | not_found | - | - |
| postoffice-redeliveritem.com | redeliver | 2026-10-17 | not_found | - | - |
| 315kq.vip | dhl | 2026-10-17 | not_found | - | - |
| com-ohte.xin | ezdrive | 2026-10-17 | not_found | - | - |
| com-ndqf.xin | ezdrive | 2026-10-17 | not_found | - | - |
| finance91-exercitationem57.pro | citation | 2026-10-17 | 2026-04-29 | 171.6 days | NameCheap, Inc. |
| usps-informedo.top | usps | 2026-10-17 | not_found | - | - |
| surge.sh | violation | 2026-10-17 | not_found | - | - |
| com-trackgcs.top | usps | 2026-10-17 | not_found | - | - |
| jibeapply.com | fedex | 2026-10-17 | 2012-01-12 | 5,392.4 days | MarkMonitor Inc. |
| facebook-checkpoint-policy-violation-social-network184.ml | violation | 2026-10-17 | not_found | - | - |
| irsdepartement-gov.com | irs | 2026-10-17 | not_found | - | - |
| smolfryz.com | dhl | 2026-10-17 | not_found | - | - |
| parcel-deliver.com | parcel | 2026-10-17 | not_found | - | - |
| reconfirm-redelivery.com | redeliver | 2026-10-17 | not_found | - | - |
| finlab5-exercitationem89.sbs | citation | 2026-10-17 | 2026-08-10 | 68.3 days | NameCheap, Inc. |
| com-trackigz.top | usps | 2026-10-17 | not_found | - | - |
| com-trackhtw.top | usps | 2026-10-17 | not_found | - | - |
| redeliver-payment.com | redeliver | 2026-10-17 | not_found | - | - |
| com-trackemr.top | usps | 2026-10-17 | not_found | - | - |
