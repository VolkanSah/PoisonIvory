Example config file:

```json
{
  "domain": "example.com",
  "onion_address": "exampleonion12345.onion",
  "tor_control_port": 9051,
  "output_dir": "security_reports",
  "alert_threshold": 5,
  "malicious_relays": [
    "ABCD1234EFGH5678", 
    "IJKL91011MNOP1213"
  ],
  "monitoring_enabled": true,
  "scan_interval": 3600
}
```

---

| Key                  | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `domain`             | The target domain to monitor (without `http://` or `https://`) |
| `onion_address`      | Optional: The `.onion` address for Tor monitoring              |
| `tor_control_port`   | Port for Tor control connection (default: `9051`)              |
| `output_dir`         | Directory for saving reports and logs                          |
| `alert_threshold`    | Number of suspicious events before emergency scan triggers     |
| `malicious_relays`   | List of Tor relay fingerprints to blacklist                    |
| `monitoring_enabled` | Enables continuous monitoring (true/false)                     |
| `scan_interval`      | Interval for periodic checks in seconds (default: `3600`)      |
