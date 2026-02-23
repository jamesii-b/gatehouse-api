#!/usr/bin/env python3
"""
COMPREHENSIVE TOTP END-TO-END FUNCTIONAL TEST
Tests all aspects of TOTP functionality regardless of current state.

Based on approved proposal in TOTP_TEST_PROPOSAL.md
"""
import requests
import pyotp
import json
import sys
import os
from datetime import datetime, timezone

# Configuration
BASE_URL = "http://localhost:8888/api/v1"
CREDENTIALS = {
    "email": "bob@acme-corp.com",
    "password": "UserPass123!"
}
DATA_FILE = ".totp_test_data.json"

# Test state
test_data = {
    "secret": None,
    "backup_codes": [],
    "last_run": None
}

def load_test_data():
    """Load test data from previous run."""
    global test_data
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            test_data = json.load(f)
        print(f"📂 Loaded test data from {DATA_FILE}")
        print(f"   Secret: {test_data['secret'][:20] if test_data['secret'] else 'None'}...")
        print(f"   Backup codes: {len(test_data.get('backup_codes', []))}")
    else:
        print(f"📂 No previous test data found")

def save_test_data():
    """Save test data for next run."""
    test_data['last_run'] = datetime.now(timezone.utc).isoformat()
    with open(DATA_FILE, 'w') as f:
        json.dump(test_data, f, indent=2)
    print(f"\n💾 Saved test data to {DATA_FILE}")

def print_section(step, title):
    """Print test section header."""
    print(f"\n{'='*70}")
    print(f"[STEP {step}] {title}")
    print('='*70)

def main():
    """Run comprehensive TOTP test."""
    
    print("\n" + "="*70)
    print("COMPREHENSIVE TOTP END-TO-END TEST")
    print(f"User: {CREDENTIALS['email']}")
    print(f"Server: {BASE_URL}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("="*70)
    
    load_test_data()
    
    session = requests.Session()
    auth_token = None
    totp = None
    step = 0
    
    try:
        # ==================== PHASE 1: INITIAL LOGIN ====================
        
        step += 1
        print_section(step, "Initial Login")
        
        login_response = session.post(f"{BASE_URL}/auth/login", json=CREDENTIALS)
        
        if login_response.status_code != 200:
            print(f"❌ Login failed: {login_response.status_code}")
            print(json.dumps(login_response.json(), indent=2))
            return False
        
        login_data = login_response.json()
        
        # Check if TOTP is required
        totp_required = login_data.get("data", {}).get("requires_totp", False)
        
        if totp_required:
            print("⚠️  TOTP is ENABLED - login requires verification")
            
            # We need either saved secret or backup code
            if test_data.get('secret'):
                print("ℹ️  Using saved secret to generate TOTP code")
                totp = pyotp.TOTP(test_data['secret'])
                utc_now = datetime.now(timezone.utc)
                code = totp.at(utc_now)
                print(f"   Generated code: {code}")
                print(f"   At time: {utc_now.isoformat()}")
                
                verify_response = session.post(
                    f"{BASE_URL}/auth/totp/verify",
                    json={"code": code}
                )
                
                if verify_response.status_code != 200:
                    print("❌ TOTP code verification failed")
                    print("   Trying backup code...")
                    
                    if test_data.get('backup_codes'):
                        # Try first unused backup code
                        for backup_code in test_data['backup_codes']:
                            verify_response = session.post(
                                f"{BASE_URL}/auth/totp/verify",
                                json={"code": backup_code, "is_backup_code": True}
                            )
                            if verify_response.status_code == 200:
                                print(f"✅ Authenticated with backup code: {backup_code}")
                                # Remove used code
                                test_data['backup_codes'].remove(backup_code)
                                break
                        else:
                            print("❌ All backup codes failed")
                            print("\nPlease manually delete Bob's TOTP from database:")
                            print("DELETE FROM authentication_methods WHERE user_id = (SELECT id FROM users WHERE email = 'bob@acme-corp.com') AND method_type = 'totp';")
                            return False
                    else:
                        print("❌ No backup codes available")
                        return False
                
                auth_token = verify_response.json()["data"]["token"]
                print("✅ Logged in with TOTP verification")
                
            elif test_data.get('backup_codes'):
                print("ℹ️  Using backup code to authenticate")
                
                for backup_code in test_data['backup_codes']:
                    verify_response = session.post(
                        f"{BASE_URL}/auth/totp/verify",
                        json={"code": backup_code, "is_backup_code": True}
                    )
                    if verify_response.status_code == 200:
                        auth_token = verify_response.json()["data"]["token"]
                        print(f"✅ Authenticated with backup code: {backup_code}")
                        test_data['backup_codes'].remove(backup_code)
                        break
                else:
                    print("❌ No valid backup codes")
                    return False
            else:
                print("❌ TOTP enabled but no secret or backup codes available")
                print("\nPlease manually delete Bob's TOTP from database:")
                print("DELETE FROM authentication_methods WHERE user_id = (SELECT id FROM users WHERE email = 'bob@acme-corp.com') AND method_type = 'totp';")
                return False
        else:
            auth_token = login_data["data"]["token"]
            print("✅ Logged in (TOTP not required)")
        
        # ==================== PHASE 2: CHECK STATUS AND DISABLE IF ENABLED ====================
        
        step += 1
        print_section(step, "Check TOTP Status")
        
        status_response = session.get(
            f"{BASE_URL}/auth/totp/status",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if status_response.status_code != 200:
            print("❌ Failed to get TOTP status")
            return False
        
        status_data = status_response.json()["data"]
        print(f"TOTP Enabled: {status_data['totp_enabled']}")
        print(f"Verified At: {status_data.get('verified_at', 'N/A')}")
        print(f"Backup Codes Remaining: {status_data['backup_codes_remaining']}")
        
        # If TOTP is enabled, disable it
        if status_data['totp_enabled']:
            step += 1
            print_section(step, "Disable TOTP")
            
            disable_response = session.delete(
                f"{BASE_URL}/auth/totp/disable",
                headers={"Authorization": f"Bearer {auth_token}"},
                json={"password": CREDENTIALS["password"]}
            )
            
            if disable_response.status_code != 200:
                print("❌ Failed to disable TOTP")
                print(json.dumps(disable_response.json(), indent=2))
                return False
            
            print("✅ TOTP disabled")
            
            # Clear saved secret/codes since we're starting fresh
            test_data['secret'] = None
            test_data['backup_codes'] = []
        else:
            print("ℹ️  TOTP already disabled, skipping disable step")
        
        # ==================== PHASE 3: LOGOUT AND RE-LOGIN ====================
        
        step += 1
        print_section(step, "Logout")
        
        logout_response = session.post(
            f"{BASE_URL}/auth/logout",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        print(f"✅ Logged out (status: {logout_response.status_code})")
        
        step += 1
        print_section(step, "Re-login (TOTP should NOT be required)")
        
        session = requests.Session()  # Fresh session
        login2_response = session.post(f"{BASE_URL}/auth/login", json=CREDENTIALS)
        
        if login2_response.status_code != 200:
            print("❌ Re-login failed")
            return False
        
        login2_data = login2_response.json()
        if login2_data.get("data", {}).get("requires_totp"):
            print("❌ Login still requires TOTP (should not after disabling)")
            return False
        
        auth_token = login2_data["data"]["token"]
        print("✅ Logged in successfully (no TOTP required)")
        
        # ==================== PHASE 4: ENROLL IN TOTP ====================
        
        step += 1
        print_section(step, "Enroll in TOTP")
        
        enroll_response = session.post(
            f"{BASE_URL}/auth/totp/enroll",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if enroll_response.status_code != 201:
            print(f"❌ Enrollment failed: {enroll_response.status_code}")
            print(json.dumps(enroll_response.json(), indent=2))
            return False
        
        enroll_data = enroll_response.json()["data"]
        new_secret = enroll_data["secret"]
        new_backup_codes = enroll_data["backup_codes"]
        provisioning_uri = enroll_data["provisioning_uri"]
        qr_code = enroll_data.get("qr_code", "")
        
        print(f"✅ Enrollment initiated")
        print(f"   Secret: {new_secret}")
        print(f"   Provisioning URI: {provisioning_uri}")
        print(f"   QR Code: {'Present (%d bytes)' % len(qr_code) if qr_code else 'Missing'}")
        print(f"   Backup Codes: {len(new_backup_codes)}")
        
        # Save for later use
        test_data['secret'] = new_secret
        test_data['backup_codes'] = new_backup_codes.copy()
        
        # ==================== PHASE 5: VERIFY ENROLLMENT ====================
        
        step += 1
        print_section(step, "Verify TOTP Enrollment")
        
        totp = pyotp.TOTP(new_secret)
        utc_now = datetime.now(timezone.utc)
        code = totp.at(utc_now)
        
        print(f"Generated TOTP code: {code}")
        print(f"At UTC time: {utc_now.isoformat()}")
        print(f"Timestamp: {utc_now.timestamp()}")
        
        verify_enrollment_response = session.post(
            f"{BASE_URL}/auth/totp/verify-enrollment",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"code": code}
        )
        
        if verify_enrollment_response.status_code != 200:
            print(f"❌ Verification failed: {verify_enrollment_response.status_code}")
            print(json.dumps(verify_enrollment_response.json(), indent=2))
            return False
        
        print("✅ TOTP enrollment verified successfully!")
        
        # ==================== PHASE 6: CONFIRM ENROLLMENT ====================
        
        step += 1
        print_section(step, "Confirm TOTP is Enabled")
        
        final_status_response = session.get(
            f"{BASE_URL}/auth/totp/status",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        final_status = final_status_response.json()["data"]
        if not final_status["totp_enabled"]:
            print("❌ TOTP not enabled after verification!")
            return False
        
        print(f"✅ TOTP is enabled")
        print(f"   Verified at: {final_status['verified_at']}")
        print(f"   Backup codes remaining: {final_status['backup_codes_remaining']}")
        
        # ==================== PHASE 7: TEST LOGIN WITH TOTP ====================
        
        step += 1
        print_section(step, "Logout")
        
        session.post(f"{BASE_URL}/auth/logout", headers={"Authorization": f"Bearer {auth_token}"})
        print("✅ Logged out")
        
        step += 1
        print_section(step, "Login (should REQUIRE TOTP)")
        
        session2 = requests.Session()
        login3_response = session2.post(f"{BASE_URL}/auth/login", json=CREDENTIALS)
        
        if login3_response.status_code != 200:
            print("❌ Login failed")
            return False
        
        login3_data = login3_response.json()
        if not login3_data.get("data", {}).get("requires_totp"):
            print("❌ Login did NOT require TOTP (it should!)") 
            return False
        
        print("✅ Login correctly requires TOTP")
        
        # ==================== PHASE 8: VERIFY TOTP DURING LOGIN ====================
        
        step += 1
        print_section(step, "Verify TOTP Code During Login")
        
        utc_now = datetime.now(timezone.utc)
        login_code = totp.at(utc_now)
        
        print(f"Generated TOTP code: {login_code}")
        print(f"At UTC time: {utc_now.isoformat()}")
        
        verify_login_response = session2.post(
            f"{BASE_URL}/auth/totp/verify",
            json={"code": login_code}
        )
        
        if verify_login_response.status_code != 200:
            print(f"❌ TOTP login verification failed: {verify_login_response.status_code}")
            print(json.dumps(verify_login_response.json(), indent=2))
            return False
        
        final_token = verify_login_response.json()["data"]["token"]
        print("✅ Successfully logged in with TOTP!")
        print(f"   Token: {final_token[:30]}...")
        
        # ==================== PHASE 9: TEST /auth/me ====================
        
        step += 1
        print_section(step, "Confirm Logged In (/auth/me)")
        
        me_response = session2.get(
            f"{BASE_URL}/auth/me",
            headers={"Authorization": f"Bearer {final_token}"}
        )
        
        if me_response.status_code != 200:
            print("❌ /auth/me failed")
            return False
        
        me_data = me_response.json()["data"]
        print(f"✅ Confirmed logged in as: {me_data['user']['email']}")
        print(f"   User ID: {me_data['user']['id']}")
        
        # ==================== PHASE 10: TEST BACKUP CODE ====================
        
        step += 1
        print_section(step, "Test Backup Code Login")
        
        # Logout
        session2.post(f"{BASE_URL}/auth/logout", headers={"Authorization": f"Bearer {final_token}"})
        
        # Fresh login
        session3 = requests.Session()
        login4_response = session3.post(f"{BASE_URL}/auth/login", json=CREDENTIALS)
        
        if not login4_response.json().get("data", {}).get("requires_totp"):
            print("❌ Login should require TOTP")
            return False
        
        print(f"ℹ️  Using backup code: {test_data['backup_codes'][0]}")
        
        backup_verify_response = session3.post(
            f"{BASE_URL}/auth/totp/verify",
            json={"code": test_data['backup_codes'][0], "is_backup_code": True}
        )
        
        if backup_verify_response.status_code != 200:
            print("❌ Backup code login failed")
            print(json.dumps(backup_verify_response.json(), indent=2))
            return False
        
        backup_token = backup_verify_response.json()["data"]["token"]
        print(f"✅ Logged in with backup code!")
        
        # Remove used code
        used_code = test_data['backup_codes'].pop(0)
        
        # ==================== PHASE 11: CHECK BACKUP CODES REMAINING ====================
        
        step += 1
        print_section(step, "Check Backup Codes Remaining")
        
        status3_response = session3.get(
            f"{BASE_URL}/auth/totp/status",
            headers={"Authorization": f"Bearer {backup_token}"}
        )
        
        status3_data = status3_response.json()["data"]
        if status3_data['backup_codes_remaining'] != 9:
            print(f"❌ Expected 9 backup codes, got {status3_data['backup_codes_remaining']}")
            return False
        
        print(f"✅ Backup codes remaining: {status3_data['backup_codes_remaining']} (was 10, now 9)")
        
        # ==================== PHASE 12: REGENERATE BACKUP CODES ====================
        
        step += 1
        print_section(step, "Regenerate Backup Codes")
        
        regen_response = session3.post(
            f"{BASE_URL}/auth/totp/regenerate-backup-codes",
            headers={"Authorization": f"Bearer {backup_token}"},
            json={"password": CREDENTIALS["password"]}
        )
        
        if regen_response.status_code != 200:
            print("❌ Failed to regenerate backup codes")
            print(json.dumps(regen_response.json(), indent=2))
            return False
        
        regenerated_codes = regen_response.json()["data"]["backup_codes"]
        print(f"✅ Regenerated {len(regenerated_codes)} backup codes")
        
        # Update saved codes
        test_data['backup_codes'] = regenerated_codes.copy()
        
        # ==================== SUCCESS ====================
        
        save_test_data()
        
        print("\n" + "="*70)
        print("🎉 ALL TESTS PASSED!")
        print("="*70)
        
        print("\n✅ TEST SUMMARY:")
        print(f"   1. ✅ Initial login (with/without TOTP)")
        print(f"   2. ✅ Check TOTP status")
        print(f"   3. ✅ Disable TOTP")
        print(f"   4. ✅ Logout")
        print(f"   5. ✅ Re-login without TOTP")
        print(f"   6. ✅ Enroll in TOTP")
        print(f"   7. ✅ Verify enrollment")
        print(f"   8. ✅ Confirm TOTP enabled")
        print(f"   9. ✅ Logout")
        print(f"  10. ✅ Login with TOTP required")
        print(f"  11. ✅ Verify TOTP during login")
        print(f"  12. ✅ Confirm logged in (/auth/me)")
        print(f"  13. ✅ Login with backup code")
        print(f"  14. ✅ Check backup codes decremented")
        print(f"  15. ✅ Regenerate backup codes")
        
        print(f"\n📱 Current TOTP Secret:")
        print(f"   {test_data['secret']}")
        
        print(f"\n🔑 Current Backup Codes ({len(test_data['backup_codes'])}):")
        for i, code in enumerate(test_data['backup_codes'], 1):
            print(f"   {i:2d}. {code}")
        
        print("\n" + "="*70)
        
        return True
        
    except requests.exceptions.ConnectionError:
        print(f"\n❌ CONNECTION ERROR - Server not running at {BASE_URL}")
        return False
    except KeyError as e:
        print(f"\n❌ UNEXPECTED RESPONSE STRUCTURE: Missing key {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
