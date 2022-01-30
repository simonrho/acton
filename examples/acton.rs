use std::net::Ipv4Addr;
use acton::server;
use acton::client;
use structopt::StructOpt;
use std::path::PathBuf;
use std::str::FromStr;
use eui48::{MacAddress, ParseError};
use ipaddress::IPAddress;
`
#[macro_use]
extern crate log;

use env_logger::Env;

#[derive(StructOpt, Debug)]
#[structopt(name = "acton")]
/// Ethernet over TCP tunnel tools
enum Opt {
    /// server listen mode for L2 tunnel requests
    Server {
        #[structopt(short, long, parse(try_from_str), default_value = "0.0.0.0", env = "SERVER_LISTEN_ADDRESS")]
        /// server listen address
        listen: Ipv4Addr,
        #[structopt(short, long, default_value = "8080", env = "SERVER_LISTEN_PORT")]
        /// server listen port
        port: u16,
        #[structopt(short, long, default_value = "server", env = "SERVER_TAP_NAME")]
        /// tap interface name
        tap_name: PathBuf,
        #[structopt(short, long, default_value = "00:00:00:00:00:00", env = "SERVER_TAP_MAC", parse(try_from_str=parse_mac))]
        /// tap mac address (xx:xx:xx:xx:xx:xx)
        mac: MacAddress,
        #[structopt(short, long, default_value = "0.0.0.0/0", env = "CLIENT_TAP_NETWORK", parse(try_from_str=parse_ip))]
        /// tap ip network (a.b.c.d/n)
        address: IPAddress,
    },

    #[structopt(after_help = "Beware `-d`, interoperable with socat command")]
    /// client connect mode for L2 tunnel establishment
    Client {
        #[structopt(parse(try_from_str), env = "CLIENT_SERVER_ADDRESS")]
        /// server destination address
        server: Ipv4Addr,
        #[structopt(short, long, default_value = "8080", env = "CLIENT_SERVER_PORT")]
        /// server destination port
        port: u16,
        #[structopt(short, long, default_value = "client", env = "CLIENT_TAP_NAME")]
        /// tap interface name
        tap_name: PathBuf,
        #[structopt(short, long, default_value = "00:00:00:00:00:00", env = "CLIENT_TAP_MAC", parse(try_from_str=parse_mac))]
        /// tap mac address (xx:xx:xx:xx:xx:xx)
        mac: MacAddress,
        #[structopt(short, long, default_value = "0.0.0.0/0", env = "CLIENT_TAP_NETWORK", parse(try_from_str=parse_ip))]
        /// tap ip network (a.b.c.d/n)
        address: IPAddress,
    },
}

fn parse_ip(ipnetwork: &str) -> Result<IPAddress, String> {
    ipaddress::ipv4::new(ipnetwork)
}

fn parse_mac(mac_address: &str) -> Result<MacAddress, ParseError> {
    MacAddress::from_str(mac_address)
}


fn main() {
    let env = Env::default()
        .filter_or("ACTON_LOG_LEVEL", "info")
        .write_style_or("ACTON_LOG_STYLE", "always");

    env_logger::init_from_env(env);


    let args = Opt::from_args();

    debug!("args: {:?}", args);

    match args {
        Opt::Server { listen, port, tap_name, mac, address } => {
            let listen_addr = format!("{}:{}", listen.to_string(), port);
            server::main(listen_addr.as_str(), tap_name.to_str().unwrap(), mac, address, false);
        }
        Opt::Client { server, port, tap_name, mac,address } => {
            let server = format!("{}:{}", server.to_string(), port);
            client::main(server.as_str(), tap_name.to_str().unwrap(), mac, address, false);
        }
    };
}






