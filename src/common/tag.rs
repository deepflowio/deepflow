use super::policy::PolicyData;

#[derive(Debug, Default, Clone)]
pub struct Tag {
    pub policy_data: [PolicyData; 2],
}

impl Tag {
    pub fn reverse(&mut self) {
        self.policy_data.swap(0, 1);
    }
}
