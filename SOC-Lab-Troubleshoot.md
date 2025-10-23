# SOC Lab Troubleshoot Guide

> Note: This is my lab troubleshoot guide. May miss something at the end.
> Reference lab setup: https://github.com/0xarun/Blueteam-C2-Detection

---

## 1. ELK Stack (Elasticsearch, Logstash, Kibana)

### Setup

* Install **Elasticsearch**, **Logstash**, and **Kibana**.
* **Logstash** is optional for lab setups.

### Forwarding Logs

**Windows (Winlogbeat):**

1. Install **Winlogbeat** on the Windows endpoint.
2. Configure `winlogbeat.yml`:

   * Set **Elasticsearch output** with the correct IP.
   * Use `https` or `http` depending on setup.
   * If SSL errors occur, add:

     ```yaml
     ssl.verification_mode: "none"
     ```
   * Add authentication if needed.
3. Test connection:

   ```bash
   winlogbeat test output
   ```

   * Should show **OK** if connection works.

**Linux (Filebeat):**

1. Install **Filebeat** on Linux endpoint.
2. Configure `filebeat.yml`:

   * Ensure **inputs** are enabled (`true`) to send logs.
   * Update Elasticsearch output as needed.
3. Start Filebeat and verify logs are reaching Elasticsearch.

### Verification

* Check indices in Elasticsearch:

  ```bash
  https://<ELASTIC_IP>:9200/_cat/indices?v
  ```
* In **Kibana**:

  1. Go to **Discover** tab → **Data View** → **Create Data View**.
  2. Select the correct **Filebeat/Winlogbeat** index name.

---

## 2. Wazuh

### Setup

* For labs, download the **Wazuh OVA** (pre-configured Wazuh Manager).
* To forward logs from endpoints:

  * Install **Wazuh Agent** on the endpoint machines.

### Troubleshooting

```bash
/var/ossec/bin/manage_agents -l
```

* Lists agents connected to the Wazuh manager.

---

## 3. Kibana & Permissions / Encryption Issues

* Common issue: **Detection engine / rules permissions** fail due to missing encryption keys.

### Fix

1. Check `kibana.yml` for `xpack.encryptedSavedObjects.encryptionKey`.
2. If missing, generate a key:

   ```bash
   /usr/share/kibana/bin/kibana-encryption-keys generate
   ```
3. Copy generated key into `kibana.yml`.
4. Restart Kibana to apply changes.
