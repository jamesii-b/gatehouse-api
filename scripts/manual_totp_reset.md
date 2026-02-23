# Manual TOTP Reset for Testing

Since Bob has TOTP enabled, you have two options to run the full test:

## Option 1: Restart Flask Server (Easiest)
The Flask server running on port 8888 uses an in-memory SQLite database.
Simply restart it to clear all data:

```bash
# Stop the server (Ctrl+C in the terminal)
# Then restart it
cd gatehouse-api
.venv/bin/flask run --debug --port 8888
```

Then run the test:
```bash
.venv/bin/python test_totp_full.py
```

## Option 2: Use the TOTP Secret

If you have the secret from the previous enrollment (check `.totp_test_data.json` if it exists):

1. Edit `test_totp_full.py`
2. Update the `test_data` initialization:
```python
test_data = {
    "secret": "YOUR_SECRET_HERE",  # From previous enrollment
    "backup_codes": ["CODE1", "CODE2", ...],  # From previous enrollment
    "last_run": None
}
```

3. Run the test

## Option 3: Database Direct Access (if file-based DB)

If using PostgreSQL or file-based SQLite:

```sql
DELETE FROM authentication_methods 
WHERE user_id = (SELECT id FROM users WHERE email = 'bob@acme-corp.com') 
  AND method_type = 'totp';
```

The test will then run through the complete flow and save the new secret/codes to `.totp_test_data.json` for subsequent runs.
