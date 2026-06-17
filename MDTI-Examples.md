# MDTI PowerShell Examples

SOC-focused examples for using Microsoft Defender Threat Intelligence (MDTI) with native Microsoft Graph PowerShell cmdlets. Use these workflows to enrich alerts, pivot from suspicious infrastructure, collect threat indicators, and prepare hunting or watchlist outputs.

These examples complement `MDTI-API.md`, which remains the API and cmdlet reference.

## Prerequisites

Install or import the Microsoft Graph Security module and connect to Microsoft Graph with the required MDTI permission.

```powershell
Import-Module Microsoft.Graph.Security
Connect-MgGraph -Scopes ThreatIntelligence.Read.All
```

The examples assume that you are already connected and that your tenant has the required Microsoft Defender Threat Intelligence licensing and API access.

## SOC Workflow Plan

Use MDTI as enrichment and pivot context during an investigation. Do not treat threat intelligence as a final verdict by itself; validate relevant indicators against internal telemetry before containment or blocking decisions.

| Step | Analyst action | Result |
| --- | --- | --- |
| 1 | Start from an incident entity such as a domain, IP address, hostname, CVE, article, or intelligence profile. | Defines the investigation seed. |
| 2 | Enrich the primary entity with MDTI host, reputation, WHOIS, article, profile, or vulnerability context. | Adds external threat intelligence context. |
| 3 | Decide whether pivoting is justified based on confidence, relevance, and internal evidence. | Avoids unnecessary over-scoping. |
| 4 | Expand related infrastructure through passive DNS, subdomains, SSL certificates, trackers, cookies, or host pairs. | Identifies related entities to hunt or review. |
| 5 | Cross-check original and related indicators against SIEM, EDR, DNS, proxy, firewall, email, and identity telemetry. | Confirms whether the environment is affected. |
| 6 | Produce response outputs such as case notes, hunting seeds, watchlists, or block recommendations. | Converts enrichment into response action. |
| 7 | Document the source, confidence, and reason for each indicator. | Keeps the incident record defensible. |

## Use Cases

| Use case | Analyst question | Starting point | Outcome | Cmdlets |
| --- | --- | --- | --- | --- |
| Recent threat reporting | What Microsoft threat intelligence is available right now? | None, or article filters | Identify articles for triage or hunting. | `Get-MgSecurityThreatIntelligenceArticle` |
| Article indicator extraction | What indicators are associated with this threat report? | Article ID | Build a hunting or blocking seed list. | `Get-MgSecurityThreatIntelligenceArticleIndicator` |
| Alert host enrichment | Is this domain, host, or IP known to MDTI? | Host indicator from alert | Add context to incident triage. | `Get-MgSecurityThreatIntelligenceHost`, `Get-MgSecurityThreatIntelligenceHostReputation` |
| Infrastructure expansion | What related infrastructure should I investigate? | Suspicious host | Find related subdomains, DNS, certs, trackers, and host pairs. | Host relationship cmdlets |
| WHOIS investigation | Who registered or operates this infrastructure? | Host or WHOIS search | Add ownership and registration context. | `Get-MgSecurityThreatIntelligenceHostWhoi`, `Get-MgSecurityThreatIntelligenceWhoisRecord` |
| Vulnerability enrichment | What does MDTI know about this CVE? | CVE ID | Understand affected components and response priority. | `Get-MgSecurityThreatIntelligenceVulnerability`, `Get-MgSecurityThreatIntelligenceVulnerabilityComponent` |
| Threat profile hunting | What indicators are tied to this actor or campaign? | Intelligence profile | Create a campaign-focused hunting package. | `Get-MgSecurityThreatIntelligenceIntelProfile`, `Get-MgSecurityThreatIntelligenceIntelProfileIndicator` |
| Watchlist export | Which indicators should be exported for hunting? | Article or profile indicators | Produce CSV output for SIEM or watchlists. | Article/profile indicator cmdlets |

## 1. List Recent MDTI Articles

Use this when starting from recent Microsoft threat reporting or when looking for proactive hunting topics.

```powershell
Get-MgSecurityThreatIntelligenceArticle -Top 10 |
    Select-Object Id, Title, CreatedDateTime, LastUpdatedDateTime
```

Analyst outcome: identify a relevant article that may explain current alerts, threat activity, or hunting priorities.

## 2. Get One Article

Use this when an article ID is already known from a previous query, report, case note, or shared investigation context.

```powershell
$articleId = "fcd7d327"

Get-MgSecurityThreatIntelligenceArticle -ArticleId $articleId
```

Analyst outcome: review the article metadata and context before extracting indicators or writing case notes.

## 3. Extract Indicators From an Article

Use this to turn an MDTI article into investigation or hunting seeds.

```powershell
$articleId = "fcd7d327"

Get-MgSecurityThreatIntelligenceArticleIndicator -ArticleId $articleId |
    Select-Object Id, Source, Artifact
```

Analyst outcome: collect article-linked indicators that can be reviewed, enriched, or searched in internal telemetry.

## 4. Extract Host Values From Article Indicators

Use this when article indicators include host artifacts such as domains or hostnames.

```powershell
$articleId = "fcd7d327"

Get-MgSecurityThreatIntelligenceArticleIndicator -ArticleId $articleId |
    Where-Object { $_.Artifact.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.security.hostname' } |
    Select-Object @{Name = 'HostId'; Expression = { $_.Artifact.Id } }, Source
```

Analyst outcome: produce host values that can be used as input for host enrichment, SIEM searches, or DNS/proxy hunting.

## 5. Enrich a Host From an Alert

Use this when an alert contains a suspicious domain, hostname, or IP address.

```powershell
$hostId = "fake-malicious.site"

Get-MgSecurityThreatIntelligenceHost -HostId $hostId
Get-MgSecurityThreatIntelligenceHostReputation -HostId $hostId
Get-MgSecurityThreatIntelligenceHostWhoi -HostId $hostId
```

Analyst outcome: understand whether the host is known to MDTI, whether it has reputation context, and what WHOIS information may support triage.

## 6. Expand Related Host Infrastructure

Use this to scope related infrastructure during incident investigation. Keep result limits reasonable and pivot only when the original entity is relevant to the case.

```powershell
$hostId = "fake-malicious.site"

Get-MgSecurityThreatIntelligenceHostSubdomain -HostId $hostId -Top 20
Get-MgSecurityThreatIntelligenceHostPassiveDns -HostId $hostId -Top 20
Get-MgSecurityThreatIntelligenceHostPassiveDnsReverse -HostId $hostId -Top 20
Get-MgSecurityThreatIntelligenceHostSslCertificate -HostId $hostId -Top 20
```

Analyst outcome: identify related infrastructure that may need hunting, blocking review, or incident scoping.

## 7. Pivot Across Host Relationships

Use this when you need parent and child host relationships for infrastructure mapping.

```powershell
$hostId = "fake-malicious.site"

Get-MgSecurityThreatIntelligenceHostPair -HostId $hostId -Top 20
Get-MgSecurityThreatIntelligenceHostParentHostPair -HostId $hostId -Top 20
Get-MgSecurityThreatIntelligenceHostChildHostPair -HostId $hostId -Top 20
```

Analyst outcome: map related host relationships and decide which connected entities are worth checking in internal telemetry.

## 8. Search WHOIS Records

Use this when investigating registration details, domains, email addresses, registrars, or repeated infrastructure patterns.

```powershell
$search = "fake-malicious.site"

Get-MgSecurityThreatIntelligenceWhoisRecord -Search $search -Top 10 |
    Select-Object Id, DomainStatus, Registrar, CreatedDateTime, ExpirationDateTime
```

Analyst outcome: add registration context to the case and identify useful pivots such as registrar, registrant, or related domain patterns.

## 9. Investigate a Vulnerability

Use this when an incident, alert, or vulnerability management case includes a CVE.

```powershell
$vulnerabilityId = "CVE-2021-44228"

Get-MgSecurityThreatIntelligenceVulnerability -VulnerabilityId $vulnerabilityId
Get-MgSecurityThreatIntelligenceVulnerabilityComponent -VulnerabilityId $vulnerabilityId
```

Analyst outcome: understand what MDTI knows about the CVE and which components may be affected.

## 10. Browse Intelligence Profiles

Use this to discover threat actor, campaign, or activity group profiles that may support proactive hunting or incident context.

```powershell
Get-MgSecurityThreatIntelligenceIntelProfile -Top 10 |
    Select-Object Id, Title, Summary
```

Analyst outcome: identify relevant profiles that can guide hunting, reporting, or campaign tracking.

## 11. Collect Indicators From an Intelligence Profile

Use this to build a campaign-specific hunt package.

```powershell
$profileId = "<intelligenceProfileId>"

Get-MgSecurityThreatIntelligenceIntelProfileIndicator -IntelligenceProfileId $profileId |
    Select-Object Id, Source, Artifact
```

Analyst outcome: collect profile-linked indicators and decide which are suitable for hunting, watchlists, or response recommendations.

## 12. Export Article Indicators For Hunting

Use this to prepare indicators for review, hunting, or watchlist import. Add review dates and ownership before operationalizing large lists.

```powershell
$articleId = "fcd7d327"

Get-MgSecurityThreatIntelligenceArticleIndicator -ArticleId $articleId |
    Select-Object `
        Id,
        Source,
        @{Name = 'ArtifactType'; Expression = { $_.Artifact.AdditionalProperties.'@odata.type' } },
        @{Name = 'ArtifactValue'; Expression = { $_.Artifact.Id } } |
    Export-Csv -Path ".\MDTI-ArticleIndicators.csv" -NoTypeInformation
```

Analyst outcome: create a CSV file that can be reviewed and transformed into hunting queries, watchlists, or incident attachments.

## Analyst Notes

- MDTI enriches investigation context; it should be combined with internal telemetry before containment or blocking.
- Avoid broad pivots from low-confidence indicators. Scope related infrastructure based on relevance to the alert or incident.
- Record indicator source, confidence, collection time, and reason for use in the incident notes.
- Use `-Top` during exploration to keep results readable and avoid unnecessary noise.
- Review exported indicators before importing them into watchlists or enforcement controls.
