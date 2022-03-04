use std::time::Duration;

// 每次获取统计数据后此结构体都会被清零，不能在其中保存Flow级别的信息避免被清空
#[derive(Debug, Default, PartialEq)]
pub struct PerfStats {
    pub req_count: u32,
    pub resp_count: u32,
    pub req_err_count: u32,
    pub resp_err_count: u32,
    pub rrt_count: u32,
    pub rrt_max: Duration,
    pub rrt_last: Duration,
    pub rrt_sum: Duration,
}
