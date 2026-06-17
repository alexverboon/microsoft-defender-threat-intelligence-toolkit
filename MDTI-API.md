# MDTI API

Microsoft Defender Threat Intelligence (MDTI) API reference for Microsoft Graph Security. This document maps common MDTI resource operations to their Microsoft Learn documentation, REST endpoints, and native Microsoft Graph PowerShell cmdlets where available.

| Reference | Link |
| --- | --- |
| Microsoft Graph MDTI overview | https://learn.microsoft.com/en-us/graph/api/resources/security-threatintelligence-overview?view=graph-rest-1.0 |
| PowerShell module | https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.security/ |
| Module name | `Microsoft.Graph.Security` |

## Article

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-article?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| List articles | https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-articles?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/articles` | `Get-MgSecurityThreatIntelligenceArticle` |
| Get article | https://learn.microsoft.com/en-us/graph/api/security-article-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/articles/{articleId}` | `Get-MgSecurityThreatIntelligenceArticle -ArticleId $articleId` |
| List indicators | https://learn.microsoft.com/en-us/graph/api/security-article-list-indicators?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/articles/{articleId}/indicators` | ` Get-MgSecurityThreatIntelligenceArticleIndicator` |

## Host

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-host?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| Get host | https://learn.microsoft.com/en-us/graph/api/security-host-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}` | `Get-MgSecurityThreatIntelligenceHost -HostId $hostId` |
| Get whoisRecord | https://learn.microsoft.com/en-us/graph/api/resources/security-host?view=graph-rest-1.0#methods | `GET /security/threatIntelligence/hosts/{hostId}/whois` | `Get-MgSecurityThreatIntelligenceHostWhoi -HostId $hostId` |
| List childHostPairs for a host as parent | https://learn.microsoft.com/en-us/graph/api/security-host-list-childhostpairs?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/childHostPairs` | `Get-MgSecurityThreatIntelligenceHostChildHostPair -HostId $hostId` |
| List hostPairs for a host | https://learn.microsoft.com/en-us/graph/api/security-host-list-hostpairs?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/hostPairs` | `Get-MgSecurityThreatIntelligenceHostPair -HostId $hostId` |
| List components | https://learn.microsoft.com/en-us/graph/api/security-host-list-components?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/components` | `Get-MgSecurityThreatIntelligenceHostComponent -HostId $hostId` |
| List cookies | https://learn.microsoft.com/en-us/graph/api/security-host-list-cookies?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/cookies` | `Get-MgSecurityThreatIntelligenceHostCookie -HostId $hostId` |
| List parentHostPairs for a host as child | https://learn.microsoft.com/en-us/graph/api/security-host-list-parenthostpairs?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/parentHostPairs` | `Get-MgSecurityThreatIntelligenceHostParentHostPair -HostId $hostId` |
| List passiveDns | https://learn.microsoft.com/en-us/graph/api/security-host-list-passivedns?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/passiveDns` | `Get-MgSecurityThreatIntelligenceHostPassiveDns -HostId $hostId` |
| List passiveDnsReverse | https://learn.microsoft.com/en-us/graph/api/security-host-list-passivednsreverse?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/passiveDnsReverse` | `Get-MgSecurityThreatIntelligenceHostPassiveDnsReverse -HostId $hostId` |
| List ports | https://learn.microsoft.com/en-us/graph/api/security-host-list-ports?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/ports` | `Get-MgSecurityThreatIntelligenceHostPort -HostId $hostId` |
| Get reputation | https://learn.microsoft.com/en-us/graph/api/security-host-get-reputation?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/reputation` | `Get-MgSecurityThreatIntelligenceHostReputation -HostId $hostId` |
| List subdomains | https://learn.microsoft.com/en-us/graph/api/security-host-list-subdomains?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/subdomains` | `Get-MgSecurityThreatIntelligenceHostSubdomain -HostId $hostId` |
| List trackers | https://learn.microsoft.com/en-us/graph/api/security-host-list-trackers?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/trackers` | `Get-MgSecurityThreatIntelligenceHostTracker -HostId $hostId` |
| List hostSslCertificates | https://learn.microsoft.com/en-us/graph/api/security-host-list-sslcertificates?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/sslCertificates` | `Get-MgSecurityThreatIntelligenceHostSslCertificate -HostId $hostId` |

## WhoisRecord

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-whoisrecord?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| List whoisRecords | https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-whoisrecords?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/whoisRecords?$search="{value}"` | `Get-MgSecurityThreatIntelligenceWhoisRecord -Search $search` |
| Get whoisRecord | https://learn.microsoft.com/en-us/graph/api/security-whoisrecord-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/whoisRecords/{whoisRecordId}` | `Get-MgSecurityThreatIntelligenceWhoisRecord -WhoisRecordId $whoisRecordId` |

## Vulnerability

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-vulnerability?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| Get vulnerability | https://learn.microsoft.com/en-us/graph/api/security-vulnerability-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/vulnerabilities/{vulnerabilityId}` | `Get-MgSecurityThreatIntelligenceVulnerability -VulnerabilityId $vulnerabilityId` |
| List components | https://learn.microsoft.com/en-us/graph/api/security-vulnerability-list-components?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/vulnerabilities/{vulnerabilityId}/components` | `Get-MgSecurityThreatIntelligenceVulnerabilityComponent -VulnerabilityId $vulnerabilityId` |

## VulnerabilityComponent

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-vulnerabilitycomponent?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| List vulnerabilityComponents | https://learn.microsoft.com/en-us/graph/api/security-vulnerability-list-components?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/vulnerabilities/{vulnerabilityId}/components` | `Get-MgSecurityThreatIntelligenceVulnerabilityComponent -VulnerabilityId $vulnerabilityId` |
| Get vulnerabilityComponent | https://learn.microsoft.com/en-us/graph/api/security-vulnerabilitycomponent-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/vulnerabilities/{vulnerabilityId}/components/{vulnerabilityComponentId}` | `Get-MgSecurityThreatIntelligenceVulnerabilityComponent -VulnerabilityId $vulnerabilityId -VulnerabilityComponentId $vulnerabilityComponentId` |


## Subdomain

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-subdomain?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| Get subdomain | https://learn.microsoft.com/en-us/graph/api/security-subdomain-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/subdomains/{subdomainId}` | `Get-MgSecurityThreatIntelligenceSubdomain -SubdomainId $subdomainId` |
| List subdomains | https://learn.microsoft.com/en-us/graph/api/security-host-list-subdomains?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/subdomains` | `Get-MgSecurityThreatIntelligenceHostSubdomain -HostId $hostId` |

## SslCertificate

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-sslcertificate?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| List sslCertificates | https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-sslcertificates?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/sslCertificates?$search="{property_name}:{property_value}"` | `Get-MgSecurityThreatIntelligenceSslCertificate -Search $search` |
| Get sslCertificate | https://learn.microsoft.com/en-us/graph/api/security-sslcertificate-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/sslCertificates/{sslCertificateId}` | `Get-MgSecurityThreatIntelligenceSslCertificate -SslCertificateId $sslCertificateId` |
| List related hosts | https://learn.microsoft.com/en-us/graph/api/security-sslcertificate-list-relatedhosts?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/sslCertificates/{sslCertificateId}/relatedHosts` | `Get-MgSecurityThreatIntelligenceSslCertificateRelatedHost -SslCertificateId $sslCertificateId` |

## PassiveDnsRecord

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-passivednsrecord?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| Get passiveDnsRecord | https://learn.microsoft.com/en-us/graph/api/security-passivednsrecord-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/passiveDnsRecords/{passiveDnsRecordId}` | `Get-MgSecurityThreatIntelligencePassiveDnsRecord -PassiveDnsRecordId $passiveDnsRecordId` |

## IntelligenceProfile

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-intelligenceprofile?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| List intelligence profiles | https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-intelprofiles?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/intelProfiles` | `Get-MgSecurityThreatIntelligenceIntelProfile` |
| Get intelligence profile | https://learn.microsoft.com/en-us/graph/api/security-intelligenceprofile-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/intelProfiles/{intelligenceProfileId}` | `Get-MgSecurityThreatIntelligenceIntelProfile -IntelligenceProfileId $intelligenceProfileId` |
| List indicators | https://learn.microsoft.com/en-us/graph/api/security-intelligenceprofile-list-indicators?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/intelProfiles/{intelligenceProfileId}/indicators` | `Get-MgSecurityThreatIntelligenceIntelProfileIndicator -IntelligenceProfileId $intelligenceProfileId` |

## IntelligenceProfileIndicator

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-intelligenceprofileindicator?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| Get intelligenceProfileIndicator | https://learn.microsoft.com/en-us/graph/api/security-intelligenceprofileindicator-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/intelligenceProfileIndicators/{intelligenceProfileIndicatorId}` | `Get-MgSecurityThreatIntelligenceProfileIndicator -IntelligenceProfileIndicatorId $intelligenceProfileIndicatorId` |

## HostTracker

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-hosttracker?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| Get hostTracker | https://learn.microsoft.com/en-us/graph/api/security-hosttracker-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hostTrackers/{hostTrackerId}` | `Get-MgSecurityThreatIntelligenceHostTracker -HostTrackerId $hostTrackerId` |

## HostSslCertificate

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-hostsslcertificate?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| List hostSslCertificates | https://learn.microsoft.com/en-us/graph/api/security-host-list-sslcertificates?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/sslCertificates` | `Get-MgSecurityThreatIntelligenceHostSslCertificate -HostId $hostId` |
| Get hostSslCertificate | https://learn.microsoft.com/en-us/graph/api/security-hostsslcertificate-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hostSslCertificates/{hostSslCertificateId}` | `Get-MgSecurityThreatIntelligenceHostSslCertificate -HostSslCertificateId $hostSslCertificateId` |

## HostPair

Resource: https://learn.microsoft.com/en-us/graph/api/resources/security-hostpair?view=graph-rest-1.0

| Operation | Docs | HTTP | PowerShell |
| --- | --- | --- | --- |
| Get hostPair | https://learn.microsoft.com/en-us/graph/api/security-hostpair-get?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hostPairs/{hostPairId}` | `Get-MgSecurityThreatIntelligenceHostPair -HostPairId $hostPairId` |
| List for a host | https://learn.microsoft.com/en-us/graph/api/security-host-list-hostpairs?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/hostPairs` | `Get-MgSecurityThreatIntelligenceHostPair -HostId $hostId` |
| List for a host as child | https://learn.microsoft.com/en-us/graph/api/security-host-list-parenthostpairs?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/parentHostPairs` | `Get-MgSecurityThreatIntelligenceHostParentHostPair -HostId $hostId` |
| List for a host as parent | https://learn.microsoft.com/en-us/graph/api/security-host-list-childhostpairs?view=graph-rest-1.0&tabs=http | `GET /security/threatIntelligence/hosts/{hostId}/childHostPairs` | `Get-MgSecurityThreatIntelligenceHostChildHostPair -HostId $hostId` |



