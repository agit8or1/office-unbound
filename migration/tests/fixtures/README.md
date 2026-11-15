# Recorded-shape fixtures

No live calls were made. Each fixture is AUTHORED by hand to mirror the response example/schema of the official reference page
named below (field names, nesting, paging markers, status codes); values are invented (contoso.example style) and bodies are
abbreviated where the doc says "response object may be shortened". `{base}` is replaced with the fake server URL at load time.

| fixture | mirrors |
|---|---|
| graph/organization.json | https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0 (200 example: id, displayName, assignedPlans, verifiedDomains, onPremisesSyncEnabled) |
| graph/domains.json | https://learn.microsoft.com/en-us/graph/api/domain-list?view=graph-rest-1.0 (id, isVerified, isDefault, supportedServices) |
| graph/users_p1.json, users_p2.json | https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0 (value[], @odata.nextLink paging; $select adds proxyAddresses/assignedLicenses/accountEnabled/userType) |
| graph/groups.json | https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0 (groupTypes, mailEnabled, securityEnabled, resourceProvisioningOptions) |
| graph/mailbox_usage.csv | https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagedetail?view=graph-rest-1.0 (column list from the doc; the doc's 302 + Location pattern is reproduced by the fake server) |
| graph/onedrive_usage.csv | https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountdetail?view=graph-rest-1.0 |
| graph/sharepoint_usage.csv | https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-1.0 |
| graph/throttle_429.json | https://learn.microsoft.com/en-us/graph/throttling ("Sample response": 429, Retry-After, TooManyRequests) |
| google/*.json | Directory API users.list / groups.list / domains.list / customers.get and Reports API usage (userUsageReport) resource representations from https://developers.google.com/workspace/admin/directory/v1/reference and https://developers.google.com/workspace/admin/reports/v1/reference/usage/users/get ; Gmail users.getProfile and Drive files.list (fields mask) from the Gmail/Drive v3 references. Parameter names `accounts:*_used_quota_in_mb` were checked against https://developers.google.com/workspace/admin/reports/v1/reference/usage-ref-appendix-a/users-accounts |
| google/throttle_403.json | https://developers.google.com/workspace/admin/directory/v1/limits (403 rateLimitExceeded / userRateLimitExceeded error body) |

Caveat: Google reference pages were not re-fetched field-by-field for every resource in this session; google/* shapes are from the
documented resource representations as recalled and must be re-validated against a real tenant (see docs/status/migration-assessment.md).
