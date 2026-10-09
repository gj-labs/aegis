# Incident 13ace1de: 203.0.113.0/24

## Incident Report
### Summary
The system is currently under a reconnaissance attack from multiple IPs within the 203.0.113.0/24 entity. The attacker is sending a large number of HTTP requests to different paths, resulting in 404 errors.
### Evidence
* 526 HTTP 404 errors
* 8 distinct paths accessed
### Mitigation
A CIDR block rule has been applied to block traffic from the 203.0.113.0/24 entity for 1 hour.
### Recommendations
* Monitor system logs for further suspicious activity
* Consider implementing additional security measures to prevent future reconnaissance attacks

## Measured facts (computed by code, not written by the model)
- Rules applied: 1 (cidr:203.0.113.0/24)
- Time from attack start to rule applied: 14.874 s
- Traffic is synthetic. Block is enforced by the simulated generator via the blocklist table.
