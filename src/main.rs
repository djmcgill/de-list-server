#![feature(futures_api, async_await, await_macro)]

use egg_mode;
use egg_mode::KeyPair;
use failchain::ResultExt;
use futures::compat::Future01CompatExt;
use futures::future::{FutureExt, TryFutureExt};
use futures::Future;
use hyper::client::{Client, HttpConnector};
use hyper::rt::Future as Future01;
use hyper::{Request, Response, StatusCode};
use hyper_tls::HttpsConnector;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;
use tera::{compile_templates, Context, Tera, Value};
use url::form_urlencoded;

mod egg_mode_2;
mod error;

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

    // FIXME: just in memory for now
    // probably shouldn't also have a single lock too
    pub static ref OAUTH_TOKENS: Mutex<HashMap<String, KeyPair>> = {
        Mutex::new(HashMap::new())
    };
}
const CALLBACK_URL: &'static str = "http://localhost:3000/sign-in-with-twitter";

fn save_oauth_token(oauth_token: &KeyPair) {
    let mut map = OAUTH_TOKENS.lock().unwrap();
    map.insert(oauth_token.key.clone().into_owned(), oauth_token.clone());
}

fn redirect_to(redirect_url: &str) -> Result<Response<http_service::Body>, error::Error> {
    let mut response = Response::new(http_service::Body::empty());
    *response.status_mut() = StatusCode::FOUND;

    let header_value = hyper::header::HeaderValue::from_str(&redirect_url).chain_err(|| {
        error::ErrorKind::OtherError("constructing header value from redirect url".to_owned())
    })?;
    response
        .headers_mut()
        .insert(hyper::header::LOCATION, header_value);
    Ok(response)
}

fn redirect_to_twitter_authenticate(
    _context: tide::Context<()>,
) -> impl futures::Future<Output = Result<Response<http_service::Body>, error::Error>> {
    let key_pair_future =
        egg_mode_2::request_token(&CONSUMER_TOKEN, CALLBACK_URL, &CLIENT_POOL).compat();
    key_pair_future.map(|try_oauth_token| {
        try_oauth_token.and_then(|oauth_token| {
            save_oauth_token(&oauth_token);

            let redirect_url = format!(
                "{}?oauth_token={}",
                egg_mode_2::AUTHENTICATE,
                oauth_token.key
            );

            redirect_to(&redirect_url)
        })
    })
}

fn accept_twitter_authentication_3(
    context: tide::Context<()>,
) -> impl futures::Future<Output = Result<Response<http_service::Body>, error::Error>> {
    accept_twitter_authentication(context.request()).compat()
}

// http://localhost:3000/sign-in-with-twitter?oauth_token=foo&oauth_verifier=bar
fn accept_twitter_authentication(
    req: &Request<http_service::Body>,
) -> impl Future01<Item = Response<http_service::Body>, Error = error::Error> {
    println!("accept_twitter_authentication");

    let mut oauth_token_option = None;
    let mut oauth_verifier_option = None;

    for query in req.uri().query() {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "oauth_token" => oauth_token_option = Some(value.into_owned()),
                "oauth_verifier" => oauth_verifier_option = Some(value.into_owned()),
                _ => (),
            }
        }
    }

    let oauth_token = oauth_token_option.unwrap();
    println!("OAUTH_TOKEN: {}", oauth_token);
    let oauth_verifier = oauth_verifier_option.unwrap();

    let oauth_keypair = {
        let map = OAUTH_TOKENS.lock().unwrap();
        map.get(&oauth_token).unwrap().clone()
    };
    println!("OAUTH_KEYPAIR: {:?}", oauth_keypair);

    // FIXME: need to get the keypair from redirect_to_twitter_authenticate
    egg_mode_2::access_token(
        &CONSUMER_TOKEN,
        &oauth_keypair,
        oauth_verifier,
        &CLIENT_POOL,
    )
    .and_then(|(access_token, user_id)| {
        println!("GOT ACCESS TOKEN");

        egg_mode_2::get_owners_of_first_75_lists(
            user_id,
            &CONSUMER_TOKEN,
            &access_token,
            &CLIENT_POOL,
        )
        .map(|lists| {
            let mut context = Context::new();
            context.insert("list_count", &Value::String(lists.len().to_string()));
            context.insert("removal_url", &Value::String("foo.com".to_owned()));
            let response = Response::new(http_service::Body::from(
                TERA.render("logged_in.html", &context).unwrap(),
            ));
            response
        })
    })
}

fn or_internal_service_error<T>(
    fut: impl Future<Output = Result<T, error::Error>>,
) -> impl Future<Output = Result<T, Response<http_service::Body>>> {
    fut.map_err(|e| {
        log::error!("Unhandled error: {:?}", e);
        let mut response = Response::new(http_service::Body::from(
            "Internal Server Error: unhandled exception",
        ));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    })
}

fn main() -> std::io::Result<()> {
    env_logger::init();

    let mut app = tide::App::new(());

    app.at("/")
        .get(|c| or_internal_service_error(redirect_to_twitter_authenticate(c)));
    app.at("/sign-in-with-twitter")
        .get(|c| or_internal_service_error(accept_twitter_authentication_3(c)));

    app.serve("127.0.0.1:3000")
}
