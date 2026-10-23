from app import app

client = app.test_client()

# Test 1: Threat Intel IP
r1 = client.get('/api/v1/threat-intel/ip/185.220.101.5')
print('[+] Threat Intel IP:', r1.status_code, r1.json)

# Test 2: Threat Intel CVE
r2 = client.get('/api/v1/threat-intel/cve/CVE-2023-34362')
print('[+] Threat Intel CVE:', r2.status_code, r2.json)

# Test 3: Chain Verify
r3 = client.get('/api/v1/chain-verify/1')
print('[+] Chain Integrity Verification:', r3.status_code, r3.json)

# Test 4: RESTful Analyze API
payload = {'filename': 'test_attack.log', 'content': 'Detected mimikatz sekurlsa::logonpasswords dumping LSASS memory to 185.220.101.5'}
r4 = client.post('/api/v1/analyze', json=payload)
print('[+] Direct REST Ingestion API:', r4.status_code, r4.json)
