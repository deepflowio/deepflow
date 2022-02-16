type ActionFlag = u16;
type NpbAction = u64;

pub struct NpbActions {
    npb_action: NpbAction,
    acl_gids: Vec<u16>,
}

pub struct PolicyData {
    npb_actions: Vec<NpbActions>,
    acl_id: u32,
    action_flags: ActionFlag,
}
