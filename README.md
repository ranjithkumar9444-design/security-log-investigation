# Security Log Investigation

Defensive investigation of a synthetic authentication log: normalize the data, apply written detection rules, rebuild the incident timeline, and keep **evidence** separate from **assumptions**.

> Synthetic data only. All IPs are RFC 5737 documentation addresses. No real systems were touched.

## Headline findings

| ID | Finding | Severity | Confidence |
|----|---------|----------|------------|
| F-03 | **Password spray** from `203.0.113.42`: one failure each against stu-209, stu-311, stu-415, stu-502 in 12 s. Rate limit fired. | High | High |
| F-04 / F-06 | **Possible compromise of `stu-311`**: sprayed at 09:21Z, then logged in at 11:47Z from a new IP (`192.0.2.99`) and new device (ios). Not proven; could be the real user. | High | Medium |
| F-01 | **Brute force** on `stu-117` from `198.51.100.27`: 3 failures in 34 s, then account lock. No success followed. | Medium | Medium |
| F-02, F-05 | Account lock and rate limit fired (controls worked). | Info | High |

Top action: treat `stu-311` as potentially compromised (revoke sessions, reset password, confirm with the user).

## Deliverables

| What | File |
|------|------|
| Investigation notebook (executed, renders on GitHub) | [`notebook/security_log_investigation.ipynb`](notebook/security_log_investigation.ipynb) |
| Investigation spreadsheet (summary formulas, rules, findings, timeline, evidence vs assumptions, actions) | [`outputs/investigation_workbook.xlsx`](outputs/investigation_workbook.xlsx) |
| **Incident report (PDF)** | [`report/incident_report.pdf`](report/incident_report.pdf) |
| Normalized events, findings, timeline (CSV) | [`outputs/`](outputs/) |
| Source log | [`data/authentication-log-sample.csv`](data/authentication-log-sample.csv) |

## Detection rules (thresholds are in `analysis/investigate.py`)

| ID | Rule | Logic |
|----|------|-------|
| R1 | Brute force | >= 3 failed logins, same user and same IP, within 5 min |
| R2 | Password spraying | >= 3 distinct users failing from one IP within 5 min, <= 2 failures per user |
| R3 | Control fired | any `account_lock` or `rate_limit` |
| R4 | Unusual access | successful login where neither IP nor device appears in that user's earlier events |
| R5 | Success after targeting | success within 24 h after the user was a spray target, from a different IP |

Thresholds are judgement calls for a 12-row sample, not industry standards.

## Reproduce

```bash
pip install pandas openpyxl reportlab matplotlib
python analysis/investigate.py        # findings + CSVs + chart
python analysis/build_workbook.py     # outputs/investigation_workbook.xlsx
python analysis/build_notebook.py     # notebook/security_log_investigation.ipynb
python analysis/build_report.py       # report/incident_report.pdf
```

## Limitations

12 events from one day is a sample, not a baseline. The log has no MFA result, user-agent, geolocation, session id or application name. Conclusions about `stu-311` need confirmation from the user and session data.

## Structure

```
data/       source log
analysis/   investigate.py (all logic) + builders for notebook, workbook, PDF
notebook/   executed Jupyter notebook
outputs/    workbook, CSVs, timeline chart
report/     incident_report.pdf
```
