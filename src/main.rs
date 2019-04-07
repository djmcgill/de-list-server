use tera::{compile_templates, Context, Tera, Value};
use lazy_static::lazy_static;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::rt::Future;
use hyper::service::service_fn;
use std::env;
use egg_mode;
use egg_mode::KeyPair;
use hyper_tls::HttpsConnector;
use hyper::client::{Client, HttpConnector};
use tokio_core::reactor::Core;
use futures::future::Either;
use url::form_urlencoded;

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
type Error<'a> = Box<(dyn std::error::Error + Send + Sync + 'a)>;
const CALLBACK_URL: &'static str = "http://localhost:3000/sign-in-with-twitter";

fn routes(req: Request<Body>) -> impl Future<Item=Response<Body>, Error=Error<'static>> {
    match (req.method(), req.uri().path()) {
        // FIXME: make this a macro
        (&Method::GET, "/") => Either::A(Either::A(redirect_to_twitter_authenticate(req))),
        (&Method::GET, "/sign-in-with-twitter") => Either::A(Either::B(accept_twitter_authentication(req))),
        _ => Either::B(not_found(req)),
    }
}

fn not_found(req: Request<Body>) -> impl Future<Item=Response<Body>, Error=Error<'static>> {
    println!("Not found: {}", req.uri().path());
    futures::failed("'not_found' is unimplemented!".to_owned().into())
}

fn redirect_to_twitter_authenticate(_req: Request<Body>) -> impl Future<Item=Response<Body>, Error=Error<'static>> {
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

// http://localhost:3000/sign-in-with-twitter?oauth_token=foo&oauth_verifier=bar
fn accept_twitter_authentication(req: Request<Body>) -> impl Future<Item=Response<Body>, Error=Error<'static>> {
    println!("accept_twitter_authentication");
    let mut oauth_token_option = None;
    let mut oauth_verifier_option = None;

    for query in req.uri().query() {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "oauth_token" => oauth_token_option = Some(value.into_owned()),
                "oauth_verifier" => oauth_verifier_option = Some(value.into_owned()),
                _ => ()
            }
        }
    }

    let oauth_token = oauth_token_option.unwrap();
    let oauth_verifier = oauth_verifier_option.unwrap();

    // FIXME: need to get the keypair from redirect_to_twitter_authenticate
    egg_mode_2::access_token(&CONSUMER_TOKEN, panic!(), oauth_verifier, &CLIENT_POOL).map(|access_token|{
        println!("GOT ACCESS TOKEN");
        let mut response = Response::new(Body::from(TERA.render("logged_in.html", &Context::new()).unwrap()));
        response
    })
}

fn main() -> Result<(), Box<std::error::Error>> {
    env_logger::init();

    let mut core = Core::new().unwrap();

    let addr = ([127, 0, 0, 1], 3000).into();

    let server = Server::bind(&addr)
        .serve(|| {
            service_fn(routes)
        })
        .map_err(|e| {eprintln!("server error: {}", e); e});

    println!("Listening on http://{}", addr);
    core.run(server)?;
    Ok(())
}
