use regex::Regex;

use public::netns::{NetNs, NsFile};

fn main() {
    flexi_logger::Logger::try_with_env()
        .unwrap()
        .start()
        .unwrap();
    let re = Regex::new("").unwrap();
    let mut files = vec![NsFile::Root];
    files.extend(NetNs::find_ns_files_by_regex(&re));
    println!("{:?}", NetNs::interfaces_linked_with(&files));
}
