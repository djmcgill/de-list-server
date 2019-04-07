use tera::{compile_templates, Context, Tera, Value};
use lazy_static::lazy_static;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::rt::{self, Future};
use hyper::service::service_fn;
use std::env;
use egg_mode;
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

    pub static ref CLIENT_POOL: Client<HttpsConnector<HttpConnector>> = {
        let https = HttpsConnector::new(4).unwrap();
        let client = Client::builder()
            .build::<_, hyper::Body>(https);
        client
    };

    pub static ref CONSUMER_TOKEN: KeyPair = {
        let consumer_key = env::var("CONSUMER_KEY").unwrap();
        let consumer_secret = env::var("CONSUMER_SECRET").unwrap();
        KeyPair::new(consumer_key, consumer_secret)
    };
}

const CALLBACK_URL: &'static str = "http://localhost:3000/sign-in-with-twitter";

fn redirect_to_twitter_authenticate(_req: Request<Body>) -> impl Future<Item=Response<Body>, Error=Box<(dyn std::error::Error + Send + Sync + 'static)>> {
    let key_pair_future = egg_mode_2::request_token(&CONSUMER_TOKEN, CALLBACK_URL, &CLIENT_POOL);
    Box::new(key_pair_future.map(|oauth_token| {
        let redirect_url = format!("{}?oauth_token={}", egg_mode_2::AUTHENTICATE, oauth_token.key);

        let mut context = Context::new();
        context.insert("redirect_url", &Value::String(redirect_url.clone()));

        let mut response = Response::new(Body::from(TERA.render("redirect.html", &context).unwrap()));
        *response.status_mut() = StatusCode::from_u16(302).unwrap();
        response.headers_mut().insert(
            hyper::header::LOCATION,
            hyper::header::HeaderValue::from_str(&redirect_url).unwrap()
        );
        response
    }))
}

fn main() -> Result<(), Box<std::error::Error>> {
    env_logger::init();

    let mut core = Core::new().unwrap();

    let addr = ([127, 0, 0, 1], 3000).into();

    let server = Server::bind(&addr)
        .serve(|| {
            service_fn(redirect_to_twitter_authenticate)
        })
        .map_err(|e| {eprintln!("server error: {}", e); e});

    println!("Listening on http://{}", addr);
    core.run(server)?;
    Ok(())
}
