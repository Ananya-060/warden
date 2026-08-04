import sys
import os

# Ensure the local packages directory is in python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "packages", "sdk-python")))

from warden_sdk import Warden

def main():
    print("🚀 Running CI/CD Tool Verification Gate...")
    
    # List of tools configured in this project
    manifests_to_deploy = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "samples", "mcp-filesystem-server", "manifest.json")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "untrusted_manifest.json"))  # This is the untrusted tool
    ]
    
    # If a command line arg is provided, verify only that file
    if len(sys.argv) > 1:
        manifests_to_deploy = sys.argv[1:]
        
    warden = Warden(api_key="warden-test-key-123", base_url="http://localhost:3000")
    
    all_passed = True
    
    for manifest_path in manifests_to_deploy:
        print(f"\nScanning manifest: {manifest_path}")
        try:
            res = warden.verify(manifest_path)
            print(f"Outcome: {res.decision.upper()} - {res.reason}")
            if res.decision != "allow":
                print(f"❌ Verification failed for {manifest_path}!")
                all_passed = False
            else:
                print(f"✅ {manifest_path} is certified and allowed.")
        except Exception as e:
            print(f"💥 Verification error for {manifest_path}: {str(e)}")
            all_passed = False
            
    if not all_passed:
        print("\n❌ CI/CD GATE FAILED: One or more tools did not pass Warden verification.")
        print("Pipeline aborted. Deployment blocked.")
        sys.exit(1)
        
    print("\n✅ CI/CD GATE PASSED: All tools verified successfully. Safe to deploy.")
    sys.exit(0)

if __name__ == "__main__":
    main()
