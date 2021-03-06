#![feature(futures_api, async_await, await_macro)]

use egg_mode;
use egg_mode::KeyPair;
use failchain::ResultExt;
use futures::compat::Future01CompatExt;
use futures::future::{FutureExt, TryFutureExt};
use futures::Future;
use http::Uri;
use hyper::client::{Client, HttpConnector};
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

fn redirect_response(redirect_url: &str) -> Result<Response<http_service::Body>, error::Error> {
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

            redirect_response(&redirect_url)
        })
    })
}

fn parse_oauth_token_and_verifier(uri: &Uri) -> Result<(String, String), error::Error> {
    let mut oauth_token_option = None;
    let mut oauth_verifier_option = None;

    for query in uri.query() {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "oauth_token" => oauth_token_option = Some(value.into_owned()),
                "oauth_verifier" => oauth_verifier_option = Some(value.into_owned()),
                _ => (),
            }
        }
    }

    let oauth_token =
        oauth_token_option.ok_or_else(|| error::ErrorKind::OtherError("".to_owned().into()));
    let oauth_verifier =
        oauth_verifier_option.ok_or_else(|| error::ErrorKind::OtherError("".to_owned().into()));
    Ok((oauth_token?, oauth_verifier?))
}

fn get_oauth_keypair(oauth_token: &str) -> error::Result<KeyPair> {
    let map = OAUTH_TOKENS.lock().map_err(|e| -> error::Error {
        let kind = error::ErrorKind::OtherError("Could not get lock for OAUTH_TOKENS".to_owned());
        kind.into()
    })?;
    let keypair = map.get(oauth_token).ok_or_else(|| -> error::Error {
        let kind =
            error::ErrorKind::OtherError("Did not find oauth token in tokens map".to_owned());
        kind.into()
    })?;
    Ok(keypair.clone())
}

fn logged_in_response(
    list_count: usize,
    removal_url: &str,
) -> error::Result<Response<http_service::Body>> {
    let mut context = Context::new();
    context.insert("list_count", &Value::String(list_count.to_string()));
    context.insert("removal_url", &Value::String(removal_url.to_owned()));
    let response = Response::new(http_service::Body::from(
        TERA.render("logged_in.html", &context).unwrap(),
    ));
    Ok(response)
}

fn accept_twitter_authentication_3(
    context: tide::Context<()>,
) -> impl futures::Future<Output = Result<Response<http_service::Body>, error::Error>> {
    log::trace!("accept_twitter_authentication");

    let (oauth_token, oauth_verifier) = match parse_oauth_token_and_verifier(context.uri()) {
        Ok(x) => x,
        Err(e) => panic!(),
        // return futures01::future::Either::A(futures01::failed(e)),
    };

    let oauth_keypair = match get_oauth_keypair(&oauth_token) {
        Ok(x) => x,
        Err(e) => panic!(),
        // return futures01::future::Either::A(futures01::failed(e)),
    };

    let fut = egg_mode_2::access_token(
        &CONSUMER_TOKEN,
        &oauth_keypair,
        oauth_verifier,
        &CLIENT_POOL,
    )
    .compat()
    .and_then(|(access_token, user_id)| {
        egg_mode_2::get_owners_of_first_75_lists(
            user_id,
            &CONSUMER_TOKEN,
            &access_token,
            &CLIENT_POOL,
        )
        .compat()
        .map_ok(|lists| logged_in_response(lists.len(), "foo.com").unwrap())
    });
    fut
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
