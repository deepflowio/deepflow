#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod remote_exec {
    use std::fmt::{self, Write};
    use std::process::Output;

    use futures::future::BoxFuture;
    use thiserror::Error;

    use crate::proto::trident as pb;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("command execution failed with {0}")]
        CmdExecFailed(#[from] std::io::Error),
        #[error("param `{0}` not found")]
        ParamNotFound(String),
        #[error("kubernetes failed with {0}")]
        KubeError(#[from] kube::Error),
        #[error("serialize failed with {0}")]
        SerializeError(#[from] serde_json::Error),
        #[error("transparent")]
        SyscallFailed(String),
    }

    type Result<T> = std::result::Result<T, Error>;

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

    #[derive(Clone, Copy)]
    pub struct Parameter {
        pub name: &'static str,
        pub regex: &'static str,
    }

    #[derive(Clone)]
    pub struct Command {
        pub id: String,
        pub cmdline: &'static str,
        pub output_format: OutputFormat,
        pub desc: &'static str,
        pub command_type: &'static str,
        pub params: Vec<Parameter>,
        pub override_cmdline: Option<fn(&Params) -> BoxFuture<'static, Result<Output>>>,
    }

    impl Default for Command {
        fn default() -> Self {
            Self {
                id: String::new(),
                cmdline: "",
                output_format: OutputFormat::Text,
                desc: "",
                command_type: "",
                params: Vec::new(),
                override_cmdline: None,
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

        pub fn check_params(&self, call_params: &Params) -> Result<()> {
            for p in self.params.iter() {
                if call_params.get(p.name).is_none() {
                    return Err(Error::ParamNotFound(p.name.to_owned()));
                }
            }
            Ok(())
        }
    }

    pub struct Params<'a>(pub &'a [pb::Parameter]);

    impl Params<'_> {
        pub fn is_valid(&self) -> bool {
            for p in self.0.iter() {
                if p.key.is_none() {
                    return false;
                }
                let Some(value) = p.value.as_ref() else {
                    return false;
                };
                for c in value.as_bytes() {
                    match c {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => (),
                        _ => return false,
                    }
                }
            }
            true
        }

        pub fn get(&self, key: &str) -> Option<&str> {
            for p in self.0.iter() {
                match &p.key {
                    Some(k) if k == key => return p.value.as_ref().map(|s| s.as_str()),
                    _ => (),
                }
            }
            None
        }
    }

    impl fmt::Debug for Params<'_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{{")?;
            let mut empty = true;
            for p in self.0.iter() {
                let Some(key) = p.key.as_ref() else {
                    continue;
                };
                if empty {
                    write!(f, " ")?;
                } else {
                    write!(f, ", ")?;
                }
                if let Some(value) = p.value.as_ref() {
                    write!(f, "{}: \"{}\"", key, value)?;
                } else {
                    write!(f, "{}: null", key)?;
                }
                empty = false;
            }
            if !empty {
                write!(f, " ")?;
            }
            write!(f, "}}")
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
                    command_type: "kubernetes",
                    ..Default::default()
                }
                .gen_id()
            );
            assert_eq!(
                "kubernetes_k5l_-n_$ns_l2s_--t80_-p_$pod",
                &Command {
                    cmdline: "kubectl -n $ns logs --tail=10000 -p $pod",
                    command_type: "kubernetes",
                    ..Default::default()
                }
                .gen_id(),
            );
        }
    }
}
