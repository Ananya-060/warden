import sys
import os

# Ensure the local packages directory is in python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "packages", "sdk-python")))

from warden_sdk import Warden, ToolNotTrustedError

def run_agent():
    print("[AGENT] Starting AI Agent Loop...")
    
    # Initialize the Warden SDK
    warden = Warden(api_key="warden-test-key-123", base_url="http://localhost:3000")
    
    # Define tool paths
    trusted_tool = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples", "mcp-filesystem-server", "manifest.json"))
    untrusted_tool = os.path.abspath(os.path.join(os.path.dirname(__file__), "untrusted_manifest.json"))
    
    # Case 1: Load a trusted tool
    print("\n--- CASE 1: Loading Trusted Tool ---")
    print(f"Agent attempting to load: {trusted_tool}")
    try:
        res = warden.verify(trusted_tool)
        print(f"Warden decision: {res.decision.upper()}")
        print(f"Warden reason: {res.reason}")
        print(f"Warden cert: {res.certificate_id}")
        
        if res.decision == "allow":
            print("[SUCCESS] Agent verified tool. Connecting to filesystem server...")
            # Simulate connecting
            print(f"Capabilities approved: {res.approved_capabilities}")
        else:
            raise ToolNotTrustedError(res.reason)
            
    except Exception as e:
        print(f"[FAILED] Error loading trusted tool: {str(e)}")
        
    # Case 2: Load an untrusted tool (malicious payload)
    print("\n--- CASE 2: Loading Untrusted Tool ---")
    print(f"Agent attempting to load: {untrusted_tool}")
    try:
        res = warden.verify(untrusted_tool)
        print(f"Warden decision: {res.decision.upper()}")
        print(f"Warden reason: {res.reason}")
        
        if res.decision == "allow":
            print("[WARNING] Malicious tool allowed! Connecting...")
        else:
            raise ToolNotTrustedError(res.reason)
            
    except ToolNotTrustedError as e:
        print(f"[SAFETY BLOCK] Connection blocked! Reason: {str(e)}")
    except Exception as e:
        print(f"[FAILED] Verification error: {str(e)}")

if __name__ == "__main__":
    run_agent()
