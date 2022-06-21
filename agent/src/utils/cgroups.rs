use std::fs;

use cgroups_rs::cgroup_builder::*;
use cgroups_rs::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cgroup is not supported: {0}")]
    CgroupNotSupported(String),
    #[error("set cpu controller failed: {0}")]
    CpuControllerSetFailed(String),
    #[error("set mem controller failed: {0}")]
    MemControllerSetFailed(String),
    #[error("apply resources failed: {0}")]
    ApplyResourcesFailed(String),
    #[error("delete cgroup failed: {0}")]
    DeleteCgroupFailed(String),
}

#[derive(Clone)]
pub struct Cgroups {
    pub cgroup: Option<Cgroup>,
}

impl Cgroups {
    /// 创建cgroup hierarchy
    pub fn new() -> Result<Self, Error> {
        let mut cgroups = Cgroups { cgroup: None };
        let contents = match fs::read_to_string("/proc/filesystems") {
            Ok(file_contents) => file_contents,
            Err(e) => {
                return Err(Error::CgroupNotSupported(e.to_string()));
            }
        };
        let mut cgroup_supported = false;
        for line in contents.lines() {
            // 检查系统是否支持cgroup
            if line.to_lowercase().contains("cgroup") {
                cgroup_supported = true;
                break;
            }
        }
        if !cgroup_supported {
            return Err(Error::CgroupNotSupported(format!(
                "cgroup v1 or v2 is not found."
            )));
        }
        let hier = hierarchies::auto();
        let cg: Cgroup = CgroupBuilder::new("metaflow-agent").build(hier);
        cgroups.cgroup = Some(cg);
        Ok(cgroups)
    }

    /// 初始化cgroup，将pid写入cgroup的tasks中
    pub fn init(&self, pid: u64) -> Result<Self, Error> {
        if let Some(ref cg) = self.cgroup {
            let cpus: &cpu::CpuController = cg.controller_of().unwrap();
            match cpus.add_task(&CgroupPid::from(pid)) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::CpuControllerSetFailed(e.to_string()));
                }
            }
            let mem: &memory::MemController = cg.controller_of().unwrap();
            match mem.add_task(&CgroupPid::from(pid)) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::MemControllerSetFailed(e.to_string()));
                }
            }
        };
        Ok(self.clone())
    }

    /// 更改资源限制
    pub fn apply(&self, resources: &Resources) -> Result<(), Error> {
        if let Some(c) = &self.cgroup {
            match c.apply(resources) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::ApplyResourcesFailed(e.to_string()));
                }
            }
        }
        Ok(())
    }

    /// 结束cgroup资源限制
    pub fn stop(&self) -> Result<(), Error> {
        if let Some(c) = &self.cgroup {
            match c.delete() {
                Ok(_) => {}
                Err(e) => return Err(Error::DeleteCgroupFailed(e.to_string())),
            }
        }
        Ok(())
    }
}
