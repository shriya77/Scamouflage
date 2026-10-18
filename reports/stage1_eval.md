# Stage 1 evaluation — stage1-20261018T0011

Trained and scored on IBM LinuxONE (`s390x`). Thresholds: T_high **0.9**, T_low **0.3**. Flagged = passes brand gate AND Stage 1 ≥ T_high (no Stage 0, no certificates, no Stage 3 — those only add on top).

## test.csv — 107,574 names (28,410 scam / 79,164 normal)

| | precision | recall |
|---|---|---|
| **Scamouflage (gate + Stage 1)** | 99.3% | 2.1% |
| Baseline: brand word → scam | 94.6% | 2.3% |

- **Toll / delivery / gov scams caught:** 88.9% at T_high, 99.8% including the MAYBE zone (n = 414)
- Normal sites flagged: 0.00505% of all, 10.8108% of brand-word normals → ~2473.5 false alarms/day before Stage 3
- Speed: 11,485 names/s

- PR-AUC 0.8077, ROC-AUC 0.9066

| category | n | recall at T_high | incl. MAYBE |
|---|---|---|---|
| delivery | 237 | 90.7% | 100.0% |
| gov | 119 | 90.8% | 100.0% |
| other | 27,996 | 0.8% | 0.9% |
| toll | 58 | 77.6% | 98.3% |

<details><summary>caught (20 examples, plain text)</summary>

```
1.000  com-parceltrack.top  (delivery)
1.000  com-tracking-helpcc.cc  (other)
1.000  com-tracking-helpsaz.cc  (other)
1.000  usps.paymhbl.vip  (delivery)
1.000  usps.paymhbk.vip  (delivery)
1.000  usps.paymhbd.vip  (delivery)
1.000  cox.com-6159368de39251d7a-login.id-107sbtd9cbhsbtd5d80a13c0db1f546757jnq9j5754675720349293.kylelierman.com  (other)
1.000  usps-esf.shop  (delivery)
1.000  confirm-package-redelivery-dhll.vercel.app  (delivery)
1.000  usps.paymhbc.vip  (delivery)
1.000  usps.paymhbb.vip  (delivery)
1.000  com-trackkstk.top  (other)
1.000  com-trackkxw.top  (other)
1.000  com-trackkzw.top  (other)
1.000  com-trackvvk.top  (other)
1.000  usps-yju.shop  (delivery)
1.000  usps-xlx.shop  (delivery)
1.000  usps-qyu.shop  (delivery)
1.000  usps-pzn.shop  (delivery)
1.000  usps-pbo.shop  (delivery)
```
</details>

<details><summary>false_alarm (4 examples, plain text)</summary>

```
0.996  fedex.bdjwpp.shop  (legit)
0.979  outlook.com-9.kl.com.ua  (legit)
0.963  i-securedeliver.jp  (legit)
0.950  com-x.life  (legit)
```
</details>

<details><summary>missed_toll_delivery_gov (20 examples, plain text)</summary>

```
0.897  savepassword.ourhobby.com  (toll)
0.894  news.tollsol.info  (toll)
0.885  irs-myprofile.com  (gov)
0.884  irs-confirm.net  (gov)
0.881  ezpass.paysnst.vip  (toll)
0.880  parcel-update.co.uk  (delivery)
0.880  irsaltdprojecthub.egregiousolv.com  (gov)
0.880  irsusa-government.com  (gov)
0.874  irscenter-data.com  (gov)
0.865  myauparcel-scheduling.com  (delivery)
0.865  usps.avaturefed.net  (delivery)
0.865  dhl-suisse.gotdns.ch  (delivery)
0.865  dhl-suisse2.gotdns.ch  (delivery)
0.842  app.dhl.international.express.au.gorengo.com  (delivery)
0.839  e-dhl-iexpress.net  (delivery)
0.836  irs.gov.filing.brewcoffeecompanypty.com  (gov)
0.836  secure.dhlguestmanagement.com  (delivery)
0.836  demo.dmv-driversed.com  (gov)
0.810  agricolepass.calamitata.com  (toll)
0.806  hermes.trackparcels-uk.com  (delivery)
```
</details>
