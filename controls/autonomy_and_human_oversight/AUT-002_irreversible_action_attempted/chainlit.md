# AUT-002 Irreversible Action Gate

The Foundry agent can request an irreversible action. ACS permits execution
only after an authenticated Ops Manager approves the exact pending call.

## What happens

1. **Attempt irreversible action**: Foundry returns a request for the synthetic
   `permanently_delete_demo_record` function. The webapp passes it to ACS.
2. **Blocked by ACS**: the `pre_tool_call` policy escalates, the tool does
   not run, and metadata-only evidence is written.
3. **Approve exact action**: only an authenticated `OpsManager` can approve
   the stored call, with a short-lived ticket bound to its ACS action identity.
4. **Action executed and verified**: ACS allows the call, the synthetic store
   confirms the record is absent, and the approved evidence is written.

The record is synthetic. Sessions and approvals expire after five minutes.
**Clean up this demo** removes this session's evidence and Foundry responses.
Local policy tests and the real cloud block are verified; approved cloud
execution and destructive resource cleanup are still awaiting live validation.
