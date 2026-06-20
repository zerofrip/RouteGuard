use routeguard_core::policy::PolicySnapshot;

pub struct WfpPolicyCompiler;

impl WfpPolicyCompiler {
    pub fn compile(snapshot: &PolicySnapshot) -> PolicySnapshot {
        snapshot.clone()
    }
}
