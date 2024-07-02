pub mod remote_exec {
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
        Linux,
        Kubernetes(KubeCmd),
    }

    #[derive(Clone, Copy)]
    pub struct Command {
        pub cmdline: &'static str,
        pub output_format: OutputFormat,
        pub desc: &'static str,
        pub command_type: CommandType,
    }
}
