use std::error::Error;
use std::fs;

use cgroups_rs::cgroup_builder::*;
use cgroups_rs::*;

#[derive(Clone)]
pub struct Cgroups {
    pub cgroup: Option<Cgroup>,
}

impl Cgroups {
    /// 创建cgroup hierarchy
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let mut cgroups = Cgroups { cgroup: None };
        let contents = fs::read_to_string("/proc/filesystems")?;
        let mut cgroup_supported = false;
        for line in contents.lines() {
            // 检查系统是否支持cgroup
            if line.to_lowercase().contains("cgroup") {
                cgroup_supported = true;
                break;
            }
        }
        if !cgroup_supported {}
        let hier = hierarchies::auto();
        let cg: Cgroup = CgroupBuilder::new("metaflow-agent").build(hier);
        cgroups.cgroup = Some(cg);
        Ok(cgroups)
    }

    /// 初始化cgroup，将pid写入cgroup的tasks中
    pub fn init(&self, pid: u64) -> Result<Self, Box<dyn Error>> {
        if let Some(ref cg) = self.cgroup {
            let cpus: &cpu::CpuController = cg.controller_of().unwrap();
            match cpus.add_task(&CgroupPid::from(pid)) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Box::new(e));
                }
            }
            let mem: &memory::MemController = cg.controller_of().unwrap();
            match mem.add_task(&CgroupPid::from(pid)) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Box::new(e));
                }
            }
        };
        Ok(self.clone())
    }

    /// 更改资源限制
    pub fn apply(&self, resources: &Resources) -> Result<(), Box<dyn Error>> {
        if let Some(c) = &self.cgroup {
            match c.apply(resources) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Box::new(e));
                }
            }
        }
        Ok(())
    }

    /// 结束cgroup资源限制
    pub fn stop(&self) -> Result<(), Box<dyn Error>> {
        if let Some(c) = &self.cgroup {
            match c.delete() {
                Ok(_) => {}
                Err(e) => return Err(Box::new(e)),
            }
        }
        Ok(())
    }
}
