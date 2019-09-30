use hyper::{Request, Body, Response, Server};
use hyper::service::{service_fn, make_service_fn};
use std::net::SocketAddr;
use futures::future::{FutureExt, TryFutureExt};
use futures::compat::Future01CompatExt;

async fn serve_req(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    // Always return successfully with a response containing a body with
    // a friendly greeting ;)
    Ok(Response::new(Body::from("hello, world!")))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Construct our SocketAddr to listen on...
    let addr = ([127, 0, 0, 1], 3000).into();

    // And a MakeService to handle each connection...
    let make_service = make_service_fn(|_| async {
        Ok::<_, hyper::Error>(service_fn(|req|
            serve_req(req)))
    });

    // Then bind and serve...
    let server = Server::bind(&addr)
        .serve(make_service);

    // Finally, spawn `server` onto an Executor...
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}
