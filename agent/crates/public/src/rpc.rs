#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod remote_exec {
    use std::fmt::{self, Write};
    use std::process::Output;

    use futures::future::BoxFuture;
    use thiserror::Error;

    use crate::proto::agent as pb;

    pub const DEFAULT_PARAM_REGEX: &'static str = "^[A-Za-z0-9-_]+$";

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("command execution failed with {0}")]
        CmdExecFailed(#[from] std::io::Error),
        #[error("param `{0}` not found")]
        ParamNotFound(String),
        #[error("param `{0}` is invalid")]
        ParamInvalid(String),
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
    pub enum ParamType {
        Text,
        Boolean,
    }

    #[derive(Clone, Copy)]
    pub struct Parameter {
        pub name: &'static str,
        pub regex: Option<&'static str>,
        pub required: bool,
        pub param_type: ParamType,
        pub description: &'static str,
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
                let value = match call_params.get(p.name) {
                    Some(v) if v.is_empty() && p.required => {
                        return Err(Error::ParamInvalid(p.name.to_owned()));
                    }
                    Some(v) => v,
                    None if p.required => {
                        return Err(Error::ParamNotFound(p.name.to_owned()));
                    }
                    _ => continue,
                };
                if !value.is_empty()
                    && !regex::Regex::new(&p.regex.unwrap_or(DEFAULT_PARAM_REGEX))
                        .unwrap()
                        .is_match(value)
                {
                    return Err(Error::ParamInvalid(p.name.to_owned()));
                }
            }
            Ok(())
        }
    }

    pub struct Params<'a>(pub &'a [pb::Parameter]);

    impl Params<'_> {
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

        #[test]
        fn test_check_params() {
            let required_param = Parameter {
                name: "required",
                regex: Some("^[0-9]+$"),
                required: true,
                param_type: ParamType::Text,
                description: "",
            };
            let required_param2 = Parameter {
                name: "required2",
                regex: Some("^[0-9]+$"),
                required: true,
                param_type: ParamType::Text,
                description: "",
            };
            let no_required_param = Parameter {
                name: "no_required",
                regex: Some("^[0-9]+$"),
                required: false,
                param_type: ParamType::Text,
                description: "",
            };
            let no_required_param2 = Parameter {
                name: "no_required",
                regex: Some("^[0-9]+$"),
                required: false,
                param_type: ParamType::Text,
                description: "",
            };
            let default_regex_param = Parameter {
                name: "required",
                regex: None,
                required: true,
                param_type: ParamType::Text,
                description: "",
            };
            let required_cmd = Command {
                cmdline: "test $required",
                params: vec![required_param, required_param2],
                ..Default::default()
            };
            let no_required_cmd = Command {
                cmdline: "test $required",
                params: vec![no_required_param, no_required_param2],
                ..Default::default()
            };
            let default_regex_cmd = Command {
                cmdline: "test $required",
                params: vec![default_regex_param],
                ..Default::default()
            };
            let params = vec![
                pb::Parameter {
                    key: Some("required".to_string()),
                    value: Some("123".to_string()),
                },
                pb::Parameter {
                    key: Some("required2".to_string()),
                    value: Some("456".to_string()),
                },
            ];
            let params = Params(&params);
            let not_found_params = vec![pb::Parameter {
                key: Some("not_found".to_string()),
                value: Some("not_found".to_string()),
            }];
            let not_found_params = Params(&not_found_params);
            let empty_params = vec![pb::Parameter {
                key: Some("required".to_string()),
                value: Some("".to_string()),
            }];
            let empty_params = Params(&empty_params);
            let valid_regex_params = vec![
                pb::Parameter {
                    key: Some("required".to_string()),
                    value: Some("123".to_string()),
                },
                pb::Parameter {
                    key: Some("required2".to_string()),
                    value: Some("456".to_string()),
                },
            ];
            let valid_regex_params = Params(&valid_regex_params);
            let invalid_regex_params = vec![
                pb::Parameter {
                    key: Some("required".to_string()),
                    value: Some("123".to_string()),
                },
                pb::Parameter {
                    key: Some("required2".to_string()),
                    value: Some("abc".to_string()),
                },
            ];
            let invalid_regex_params = Params(&invalid_regex_params);
            let valid_default_regex_params = vec![pb::Parameter {
                key: Some("required".to_string()),
                value: Some("123abc-_".to_string()),
            }];
            let valid_default_regex_params = Params(&valid_default_regex_params);
            let invalid_default_regex_params = vec![pb::Parameter {
                key: Some("required".to_string()),
                value: Some("123abc-_$".to_string()), // invaild char: $
            }];
            let invalid_default_regex_params = Params(&invalid_default_regex_params);

            assert!(required_cmd.check_params(&params).is_ok());
            assert!(required_cmd.check_params(&not_found_params).is_err());
            assert!(required_cmd.check_params(&empty_params).is_err());
            assert!(required_cmd.check_params(&valid_regex_params).is_ok());
            assert!(required_cmd.check_params(&invalid_regex_params).is_err());
            assert!(no_required_cmd.check_params(&params).is_ok());
            assert!(no_required_cmd.check_params(&not_found_params).is_ok());
            assert!(no_required_cmd.check_params(&empty_params).is_ok());
            assert!(no_required_cmd.check_params(&valid_regex_params).is_ok());
            assert!(no_required_cmd.check_params(&invalid_regex_params).is_ok());
            assert!(default_regex_cmd
                .check_params(&valid_default_regex_params)
                .is_ok());
            assert!(default_regex_cmd
                .check_params(&invalid_default_regex_params)
                .is_err());
        }
    }
}
