pub mod remote_exec {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
            match id >> CmdId::ID_BITS {
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

    #[cfg(test)]
    mod tests {
        use super::CmdId;

        #[test]
        fn id_conversion() {
            let ids = vec![
                CmdId::Community(0),
                CmdId::Community(435),
                CmdId::Community(!(u32::MAX << CmdId::ID_BITS)),
                CmdId::Enterprise(0),
                CmdId::Enterprise(3451),
                CmdId::Enterprise(341),
                CmdId::Enterprise(!(u32::MAX << CmdId::ID_BITS)),
                CmdId::Temporary(0),
                CmdId::Temporary(342),
                CmdId::Temporary(34),
                CmdId::Temporary(!(u32::MAX << CmdId::ID_BITS)),
            ];

            for id in ids.iter() {
                let id_u32: u32 = (*id).into();
                assert_eq!(*id, CmdId::try_from(id_u32).unwrap());
            }
        }
    }
}
