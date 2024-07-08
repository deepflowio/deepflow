pub mod remote_exec {
    use std::fmt::{self, Write};

    #[derive(Clone, Copy)]
    pub enum OutputFormat {
        Text,
        Binary,
    }

    #[derive(Clone, Copy, PartialEq)]
    pub enum KubeCmd {
        DescribePod,
        Log,
        LogPrevious,
    }

    #[derive(Clone, Copy, PartialEq)]
    pub enum CommandType {
        System,
        Kubernetes(KubeCmd),
        Enterprise(&'static str),
    }

    impl fmt::Display for CommandType {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::System => write!(f, "system"),
                Self::Kubernetes(_) => write!(f, "kubernetes"),
                Self::Enterprise(t) => write!(f, "{}", t),
            }
        }
    }

    #[derive(Clone, Copy)]
    pub struct Parameter {
        pub name: &'static str,
        pub charset: &'static str,
        pub max_length: usize,
    }

    #[derive(Clone)]
    pub struct Command {
        pub id: String,
        pub cmdline: &'static str,
        pub output_format: OutputFormat,
        pub desc: &'static str,
        pub command_type: CommandType,
        pub params: Vec<Parameter>,
    }

    impl Default for Command {
        fn default() -> Self {
            Self {
                id: String::new(),
                cmdline: "",
                output_format: OutputFormat::Text,
                desc: "",
                command_type: CommandType::System,
                params: Vec::new(),
            }
        }
    }

    impl Command {
        pub fn gen_id(&self) -> String {
            let mut id = String::new();
            let _ = write!(&mut id, "{}", self.command_type);
            for arg in self.cmdline.split_whitespace() {
                let (prefix, word) = if arg.starts_with("--") {
                    (&arg[0..2], &arg[2..])
                } else if arg.starts_with("-") || arg.starts_with("$") {
                    (&arg[0..1], &arg[1..])
                } else {
                    ("", &arg[..])
                };
                let wl = word.len();
                if wl <= 3 {
                    let _ = write!(&mut id, "_{}{}", prefix, word);
                } else {
                    let _ = write!(
                        &mut id,
                        "_{}{}{}{}",
                        prefix,
                        &word[0..1],
                        wl - 2,
                        &word[wl - 1..wl]
                    );
                }
            }
            id
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn command_gen_id() {
            assert_eq!(
                "kubernetes_k5l_-n_$ns_d6e_pod_$pod",
                &Command {
                    cmdline: "kubectl -n $ns describe pod $pod",
                    command_type: CommandType::Kubernetes(KubeCmd::DescribePod),
                    ..Default::default()
                }
                .gen_id()
            );
            assert_eq!(
                "kubernetes_k5l_-n_$ns_l2s_--t80_-p_$pod",
                &Command {
                    cmdline: "kubectl -n $ns logs --tail=10000 -p $pod",
                    command_type: CommandType::Kubernetes(KubeCmd::LogPrevious),
                    ..Default::default()
                }
                .gen_id(),
            );
        }
    }
}
