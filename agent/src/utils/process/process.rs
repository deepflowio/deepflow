use std::{cmp::Ordering, fs, io, path::Path, time::SystemTime};

pub struct FileAndSizeSum {
    pub file_infos: Vec<FileInfo>, // 文件信息
    pub file_sizes_sum: u64,       // 文件体积总和，单位：B
}

impl FileAndSizeSum {
    pub fn new() -> Self {
        FileAndSizeSum {
            file_infos: vec![],
            file_sizes_sum: 0,
        }
    }
}

#[derive(Debug)]
pub struct FileInfo {
    pub file_path: String,
    pub file_size: u64,
    pub file_modified_time: SystemTime,
}

impl FileInfo {
    pub fn new(file_path: String, file_size: u64, file_modified_time: SystemTime) -> Self {
        FileInfo {
            file_path,
            file_size,
            file_modified_time,
        }
    }
}

impl Eq for FileInfo {}

impl PartialEq<Self> for FileInfo {
    fn eq(&self, other: &Self) -> bool {
        self.file_modified_time == other.file_modified_time
    }
}

impl PartialOrd<Self> for FileInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.file_modified_time.cmp(&other.file_modified_time)) // 根据文件的modified时间进行排序
    }
}

impl Ord for FileInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.file_modified_time.cmp(&other.file_modified_time)
    }
}

/// 获取指定路径下的所有文件的信息及文件大小总和（单位：B）
pub fn get_file_and_size_sum(dir: String) -> io::Result<FileAndSizeSum> {
    let mut file_and_size_sum = FileAndSizeSum::new();
    let mut file_infos = Vec::new();
    let dir = Path::new(dir.as_str());
    for item in fs::read_dir(dir)? {
        let file = match item {
            Ok(f) => f,
            Err(_) => continue,
        };
        let file_path = file.path().as_path().to_str().unwrap().to_string();
        let file = match file.metadata() {
            Ok(fm) => fm,
            Err(_) => continue,
        };
        if file.is_dir() {
            continue;
        }
        let file_size = file.len();
        file_and_size_sum.file_sizes_sum += file_size;
        let file_info = FileInfo::new(file_path, file_size, file.modified().unwrap());
        file_infos.push(file_info);
    }
    file_infos.sort();
    file_and_size_sum.file_infos = file_infos;
    Ok(file_and_size_sum)
}
