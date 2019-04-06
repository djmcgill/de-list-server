use tera::{compile_templates, Context, Tera};
use lazy_static::lazy_static;
use hyper::{Body, Request, Response, Server};
use hyper::rt::{self, Future};
use hyper::service::service_fn;
use futures::future;
use std::env;
use egg_mode;
use env_logger;
use log::{trace, LevelFilter};
use tokio_core::reactor::{Core, Handle};
use env_logger::Builder;
use egg_mode::KeyPair;
use hyper_tls::HttpsConnector;
use hyper::client::{Client, HttpConnector};

mod egg_mode_2;

lazy_static! {
    pub static ref TERA: Tera = {
        let mut tera = compile_templates!("templates/**/*");
        tera.autoescape_on(vec!["html"]);
        tera
    };
}

const CALLBACK_URL: &'static str = "http://localhost:3000/sign-in-with-twitter";

//type BoxFut = Box<Future<Item=Response<Body>, Error=Box<std::error::Error>> + Send>;
//fn hello_world(_req: Request<Body>, consumer_token: &KeyPair, client: &Client<HttpsConnector<HttpConnector>, Body>) -> BoxFut {
//
//
////    let mut runtime = Core::new().unwrap(); // ahhh this is really bad
////
////    let req_token = egg_mode::request_token(
////        consumer_token,
////        CALLBACK_URL,
////        handle).and_then(|res| {
////        trace!("{:?}", req_token);
////
////    });
//
//    // I know I need to move this into the and_then, but I can't even get the above to compile
////    Box::new(future::ok(R))
//}

fn main() -> Result<(), Box<std::error::Error>> {
    let mut builder = Builder::new();
    builder.filter_module("main", LevelFilter::Trace).init();

    let consumer_key = env::var("CONSUMER_KEY")?;
    let consumer_secret = env::var("CONSUMER_SECRET")?;
    let consumer_token = KeyPair::new(consumer_key, consumer_secret);

    let mut core = Core::new().unwrap();

    let addr = ([127, 0, 0, 1], 3000).into();

    let https = HttpsConnector::new(4).unwrap();
    let client = Client::builder()
        .build::<_, hyper::Body>(https);

    let server = Server::bind(&addr)
        .serve(|| {
            service_fn(|req| {
                let key_pair_future = egg_mode_2::request_token(&consumer_token, CALLBACK_URL, &client);
                Box::new(key_pair_future.map(|_|
                    Response::new(Body::from(TERA.render("hello.html", &Context::new()).unwrap()))
                ))
            })
        })
        .map_err(|e| {eprintln!("server error: {}", e); e});

    println!("Listening on http://{}", addr);
    core.run(server)?;
    Ok(())
}
