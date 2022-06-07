use std::{
    collections::HashSet,
    fmt,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use bincode::{config, decode_from_std_read};
use clap::{ArgEnum, Parser, Subcommand};

use metaflow_agent::debug::{
    Beacon, Client, Message, Module, PlatformMessage, QueueMessage, RpcMessage, BEACON_PORT,
    METAFLOW_AGENT_BEACON, SESSION_TIMEOUT,
};

const ERR_PORT_MSG: &str = "error: The following required arguments were not provided:
    \t--port <PORT> required arguments were not provided";

#[derive(Parser)]
#[clap(name = "metaflow-agent-ctl")]
struct Cmd {
    #[clap(subcommand)]
    command: ControllerCmd,
    /// remote metaflow-agent listening port
    #[clap(short, long, parse(try_from_str))]
    port: Option<u16>,
    /// remote metaflow-agent host ip
    ///
    /// ipv6 format is 'fe80::5054:ff:fe95:c839', ipv4 format is '127.0.0.1'
    #[clap(short, long, parse(try_from_str), default_value_t=IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))]
    address: IpAddr,
}

#[derive(Subcommand)]
enum ControllerCmd {
    /// get information about the rpc synchronizer
    Rpc(RpcCmd),
    /// get information about the k8s platform
    Platform(PlatformCmd),
    /// monitor various queues of the selected metaflow-agent
    Queue(QueueCmd),
    /// get connection information of all metaflow-agents managed under this controller
    List,
}

#[derive(Parser)]
struct QueueCmd {
    /// monitor module
    ///
    /// eg: monitor 1-tagged-flow-to-quadruple-generator queue with 60s
    ///
    /// metaflow-agent-ctl queue --on 1-tagged-flow-to-quadruple-generator --duration 60
    #[clap(long, requires = "monitor")]
    on: Option<String>,
    /// monitoring duration in seconds
    #[clap(long, group = "monitor")]
    duration: Option<u64>,
    /// turn off monitor
    ///
    /// eg: turn off 1-tagged-flow-to-quadruple-generator queue monitor
    ///
    /// metaflow-agent-ctl queue --off 1-tagged-flow-to-quadruple-generator queue
    #[clap(long)]
    off: Option<String>,
    /// show queue list
    ///
    /// eg: metaflow-agent-ctl queue --show
    #[clap(long)]
    show: bool,
    /// turn off all queue
    ///
    /// eg: metaflow-agent-ctl queue --clear
    #[clap(long)]
    clear: bool,
}

#[derive(Parser)]
struct PlatformCmd {
    /// get resources with k8s api
    ///
    /// eg: metaflow-agent-ctl platform --k8s_get node
    #[clap(short, long, arg_enum)]
    k8s_get: Option<Resource>,
    /// show k8s container mac to global interface index mappings
    ///
    /// eg: metaflow-agent-ctl platform --mac_mappings
    #[clap(short, long)]
    mac_mappings: bool,
}

#[derive(Clone, Copy, ArgEnum, Debug)]
enum Resource {
    Version,
    No,
    Node,
    Nodes,
    Ns,
    Namespace,
    Namespaces,
    Ing,
    Ingress,
    Ingresses,
    Svc,
    Service,
    Services,
    Deploy,
    Deployment,
    Deployments,
    Po,
    Pod,
    Pods,
    St,
    Statefulset,
    Statefulsets,
    Ds,
    Daemonset,
    Daemonsets,
    Rc,
    Replicationcontroller,
    Replicationcontrollers,
    Rs,
    Replicaset,
    Replicasets,
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Resource::No | Resource::Node | Resource::Nodes => write!(f, "nodes"),
            Resource::Ns | Resource::Namespace | Resource::Namespaces => write!(f, "namespaces"),
            Resource::Svc | Resource::Service | Resource::Services => write!(f, "namespaces"),
            Resource::Deploy | Resource::Deployment | Resource::Deployments => {
                write!(f, "deployments")
            }
            Resource::Po | Resource::Pod | Resource::Pods => write!(f, "pods"),
            Resource::St | Resource::Statefulset | Resource::Statefulsets => {
                write!(f, "statefulsets")
            }
            Resource::Ds | Resource::Daemonset | Resource::Daemonsets => write!(f, "daemonsets"),
            Resource::Rc | Resource::Replicationcontroller | Resource::Replicationcontrollers => {
                write!(f, "replicationcontrollers")
            }
            Resource::Rs | Resource::Replicaset | Resource::Replicasets => {
                write!(f, "replicasets")
            }
            Resource::Ing | Resource::Ingress | Resource::Ingresses => write!(f, "ingresses"),
            Resource::Version => write!(f, "version"),
        }
    }
}

#[derive(Parser)]
struct RpcCmd {
    /// Get data from RPC
    ///
    /// eg: get rpc config data
    /// metaflow-agent-ctl rpc --get config
    ///
    #[clap(long, arg_enum)]
    get: RpcData,
}

#[derive(Clone, Copy, ArgEnum, Debug)]
enum RpcData {
    Config,
    Platform,
    TapTypes,
    Cidr,
    Groups,
    Acls,
    Segments,
    Version,
}

struct Controller {
    cmd: Option<Cmd>,
    addr: IpAddr,
    port: Option<u16>,
}

impl Controller {
    pub fn new() -> Self {
        let cmd = Cmd::parse();
        Self {
            addr: cmd.address,
            port: cmd.port,
            cmd: Some(cmd),
        }
    }

    fn dispatch(&mut self) -> Result<()> {
        match self.cmd.take().unwrap().command {
            ControllerCmd::Platform(c) => self.platform(c),
            ControllerCmd::Rpc(c) => self.rpc(c),
            ControllerCmd::List => self.list(),
            ControllerCmd::Queue(c) => self.queue(c),
        }
    }

    fn new_client(&self) -> Result<Client> {
        let client = Client::new(
            (
                self.addr,
                self.port.expect("need input a port to connect debugger"),
            )
                .into(),
        )?;
        Ok(client)
    }

    /*
    $ metaflow-agent-ctl list
    metaflow-agent-ctl listening udp port 20035 to find metaflow-agent

    -----------------------------------------------------------------------------------------------------
    VTAP ID        HOSTNAME                     IP                                            PORT
    -----------------------------------------------------------------------------------------------------
    1              ubuntu                       ::ffff:127.0.0.1                              42700
    */
    fn list(&self) -> Result<()> {
        let server = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, BEACON_PORT))?;
        server.set_read_timeout(Some(SESSION_TIMEOUT))?;
        let mut vtap_map = HashSet::new();

        println!(
            "metaflow-agent-ctl listening udp port {} to find metaflow-agent\n",
            BEACON_PORT
        );
        println!("{:-<100}", "");
        println!(
            "{:<14} {:<28} {:45} {}",
            "VTAP ID", "HOSTNAME", "IP", "PORT"
        );
        println!("{:-<100}", "");
        loop {
            let mut buf = [0u8; 1024];
            let start = Instant::now();
            match server.recv_from(&mut buf) {
                Ok((n, a)) => {
                    if n == 0 {
                        continue;
                    }

                    // 过滤trident的beacon包
                    let length = METAFLOW_AGENT_BEACON.as_bytes().len();
                    if buf
                        .get(..length)
                        .filter(|&s| s == METAFLOW_AGENT_BEACON.as_bytes())
                        .is_none()
                    {
                        continue;
                    }

                    let beacon: Beacon =
                        decode_from_std_read(&mut &buf[length..n], config::standard())?;
                    if !vtap_map.contains(&beacon.vtap_id) {
                        println!(
                            "{:<14} {:<28} {:<45} {}",
                            beacon.vtap_id,
                            beacon.hostname,
                            a.ip(),
                            a.port()
                        );
                        vtap_map.insert(beacon.vtap_id);
                    }
                }
                Err(e)
                    if start.elapsed() >= SESSION_TIMEOUT
                        && (cfg!(target_os = "windows") && e.kind() == ErrorKind::TimedOut
                            || cfg!(target_os = "linux") && e.kind() == ErrorKind::WouldBlock) =>
                {
                    // normal timeout, Window=TimedOut UNIX=WouldBlock
                    continue;
                }
                Err(e) => return Err(anyhow!("{}", e)),
            };
        }
    }

    fn rpc(&self, c: RpcCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }
        let mut client = self.new_client()?;

        let payload = match c.get {
            RpcData::Acls => RpcMessage::Acls(None),
            RpcData::Config => RpcMessage::Config(None),
            RpcData::Platform => RpcMessage::PlatformData(None),
            RpcData::TapTypes => RpcMessage::TapTypes(None),
            RpcData::Cidr => RpcMessage::Cidr(None),
            RpcData::Groups => RpcMessage::Groups(None),
            RpcData::Segments => RpcMessage::Segments(None),
            RpcData::Version => RpcMessage::Version(None),
        };

        let msg = Message {
            module: Module::Rpc,
            msg: payload,
        };
        client.send_to(msg)?;

        loop {
            let resp = client.recv::<RpcMessage>()?;
            match resp {
                RpcMessage::Acls(v)
                | RpcMessage::PlatformData(v)
                | RpcMessage::TapTypes(v)
                | RpcMessage::Cidr(v)
                | RpcMessage::Groups(v)
                | RpcMessage::Segments(v) => match v {
                    Some(v) => println!("{}", v),
                    None => return Err(anyhow!(format!("{:?} data is empty", c.get))),
                },
                RpcMessage::Config(s) | RpcMessage::Version(s) => match s {
                    Some(s) => println!("{}", s),
                    None => return Err(anyhow!(format!("{:?} is empty", c.get))),
                },
                RpcMessage::Fin => return Ok(()),
                RpcMessage::Err(e) => return Err(anyhow!(e)),
            }
        }
    }

    fn queue(&self, c: QueueCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }
        if c.on.is_some() && c.off.is_some() {
            return Err(anyhow!("error: --on and --off cannot set at the same time"));
        }

        let mut client = self.new_client()?;
        if c.show {
            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::Names(None),
            };
            client.send_to(msg)?;

            println!("available queues: ");

            loop {
                let res = client.recv::<QueueMessage>()?;
                match res {
                    QueueMessage::Names(e) => match e {
                        Some(e) => {
                            for (i, (s, e)) in e.into_iter().enumerate() {
                                println!(
                                    "{:<5} {:<45} {}",
                                    i,
                                    s,
                                    if e { "enabled" } else { "disabled" }
                                );
                            }
                        }
                        None => return Err(anyhow!("cannot get queue names")),
                    },
                    QueueMessage::Fin => return Ok(()),
                    QueueMessage::Err(e) => return Err(anyhow!(e)),
                    _ => unreachable!(),
                }
            }
        }

        if c.clear {
            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::Clear,
            };
            client.send_to(msg)?;

            let res = client.recv::<QueueMessage>()?;
            match res {
                QueueMessage::Fin => {
                    println!("turn off all queues successful");
                    return Ok(());
                }
                QueueMessage::Err(e) => return Err(anyhow!(e)),
                _ => unreachable!(),
            }
        }

        if let Some(s) = c.off {
            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::Off(s.clone()),
            };
            client.send_to(msg)?;
            let res = client.recv::<QueueMessage>()?;
            match res {
                QueueMessage::Fin => {
                    println!("turn off queue={} successful", s);
                    return Ok(());
                }
                QueueMessage::Err(e) => return Err(anyhow!(e)),
                _ => unreachable!(),
            }
        }

        if let Some((s, d)) = c.on.zip(c.duration) {
            if d == 0 {
                return Err(anyhow!("zero duration isn't allowed"));
            }

            let dur = Duration::from_secs(d);

            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::On((s, dur)),
            };
            client.send_to(msg)?;

            let res = client.recv::<QueueMessage>()?;
            if let QueueMessage::Err(e) = res {
                return Err(anyhow!(e));
            }
            println!("loading queue item...");
            let mut seq = 0;
            loop {
                let res = client.recv::<QueueMessage>()?;
                match res {
                    QueueMessage::Send(e) => {
                        println!("MSG-{} {}", seq, e);
                        seq += 1;
                    }
                    QueueMessage::Continue => {
                        println!("message in preparation");
                        continue;
                    }
                    QueueMessage::Fin => return Ok(()),
                    QueueMessage::Err(e) => return Err(anyhow!(e)),
                    _ => unreachable!(),
                }
            }
        }

        Ok(())
    }

    fn platform(&self, c: PlatformCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }
        let mut client = self.new_client()?;
        if c.mac_mappings {
            let msg = Message {
                module: Module::Platform,
                msg: PlatformMessage::MacMappings(None),
            };
            client.send_to(msg)?;
            println!("Interface Index \t MAC address");

            loop {
                let res = client.recv::<PlatformMessage>()?;
                match res {
                    PlatformMessage::MacMappings(e) => {
                        match e {
                            /*
                            $ metaflow-agent-ctl -p 42700 platform --mac-mappings
                            Interface Index          MAC address
                            12                       01:02:03:04:05:06
                            13                       01:02:03:04:05:06
                            14                       01:02:03:04:05:06
                            */
                            Some(e) => {
                                for (idx, m) in e {
                                    println!("{:<15} \t {}", idx, m);
                                }
                            }
                            None => return Err(anyhow!("mac mappings is empty")),
                        }
                    }
                    PlatformMessage::Fin => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }

        if let Some(r) = c.k8s_get {
            if let Resource::Version = r {
                let msg = Message {
                    module: Module::Platform,
                    msg: PlatformMessage::Version(None),
                };
                client.send_to(msg)?;
                loop {
                    let res = client.recv::<PlatformMessage>()?;
                    match res {
                        PlatformMessage::Version(v) => {
                            /*
                            $ metaflow-agent-ctl -p 54911 platform --k8s-get version
                            k8s-api-watcher-version xxx
                            */
                            match v {
                                Some(v) => println!("{}", v),
                                None => return Err(anyhow!("server version is empty")),
                            }
                        }
                        PlatformMessage::Fin => return Ok(()),
                        _ => unreachable!(),
                    }
                }
            }

            let msg = Message {
                module: Module::Platform,
                msg: PlatformMessage::Watcher(r.to_string()),
            };
            client.send_to(msg)?;
            loop {
                let res = client.recv::<PlatformMessage>()?;
                match res {
                    PlatformMessage::Watcher(v) => {
                        /*
                        $ metaflow-agent-ctl -p 54911 platform --k8s-get node
                        nodes entries...
                        */
                        println!("{}", v);
                    }
                    PlatformMessage::NotFound => return Err(anyhow!("no data")),
                    PlatformMessage::Fin => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }
}

fn main() {
    let mut controller = Controller::new();
    if let Err(e) = controller.dispatch() {
        eprintln!("{}", e);
    }
}
