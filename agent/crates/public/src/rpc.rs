pub mod remote_exec {
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub enum CmdId {
        Community(u32),
        Enterprise(u32),
        Temporary(u32),
    }

    impl CmdId {
        const ID_BITS: u32 = 24;
    }

    impl From<CmdId> for u32 {
        fn from(cmd_id: CmdId) -> u32 {
            let (type_id, inner_id) = match cmd_id {
                CmdId::Community(id) => (0, id),
                CmdId::Enterprise(id) => (1 << CmdId::ID_BITS, id),
                CmdId::Temporary(id) => (2 << CmdId::ID_BITS, id),
            };
            let mask = u32::MAX << CmdId::ID_BITS;
            assert_eq!(inner_id & mask, 0);
            type_id | (inner_id & !mask)
        }
    }

    impl TryFrom<u32> for CmdId {
        type Error = &'static str;

        fn try_from(id: u32) -> Result<Self, Self::Error> {
            let mask = u32::MAX << CmdId::ID_BITS;
            let inner_id = id & !mask;
            match id & mask {
                0 => Ok(Self::Community(inner_id)),
                1 => Ok(Self::Enterprise(inner_id)),
                2 => Ok(Self::Temporary(inner_id)),
                _ => Err("invalid mask for id"),
            }
        }
    }

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
        pub id: CmdId,
        pub cmdline: &'static str,
        pub output_format: OutputFormat,
        pub desc: &'static str,
        pub command_type: CommandType,
    }
}
