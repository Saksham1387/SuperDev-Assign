use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::net::TcpListener;

use crate::router::router;

pub struct BasicServer;

impl BasicServer {
    pub async fn run() -> Result<(), std::io::Error> {
        // Initialize the tracing subscriber only once at application startup
        tracing_subscriber::fmt::init();

        let ip = Ipv4Addr::new(0, 0, 0, 0);
        let port = 8000;
        let addr = SocketAddrV4::new(ip, port);

        let app = router();
        let listener = TcpListener::bind(addr).await?;
        println!("Server is running on http://{}:{}", ip, port);
        axum::serve(listener, app).await
    }
}