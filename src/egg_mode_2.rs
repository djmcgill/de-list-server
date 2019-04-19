use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::error::Error as _;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use egg_mode::list::List;
use egg_mode::user::TwitterUser;
use egg_mode::KeyPair;
use futures::compat::Future01CompatExt;
use futures::Future;
use futures::{FutureExt, TryFutureExt};
use futures01::stream::Stream;
use futures01::Future as Future01;
use hmac::{Hmac, Mac};
use hyper::body::Body;
use hyper::client::{Client, HttpConnector};
use hyper::header::{HeaderValue, AUTHORIZATION};
use hyper::{Method, Request, Uri};
use hyper_tls::HttpsConnector;
use rand::distributions::{Alphanumeric, Distribution};
use serde::Deserialize;
use sha1::Sha1;
use std::collections::BTreeSet;
use std::iter::FromIterator;
use url::form_urlencoded;
use url::percent_encoding::{utf8_percent_encode, EncodeSet};

#[derive(Deserialize)]
struct TwitterUserId {
    id: u64,
}
#[derive(Deserialize)]
struct TwitterList {
    user: TwitterUserId,
}
#[derive(Deserialize)]
struct ListMembership {
    lists: Vec<TwitterList>,
}

use crate::Error;

pub const REQUEST_TOKEN: &'static str = "https://api.twitter.com/oauth/request_token";
pub const AUTHENTICATE: &'static str = "https://api.twitter.com/oauth/authenticate";
pub const ACCESS_TOKEN: &'static str = "https://api.twitter.com/oauth/access_token";
pub const MEMBERSHIPS: &'static str = "https://api.twitter.com/1.1/lists/memberships.json";

// NOTE THAT egg_mode hasn't been updated for hyper 0.12 yet
// and that's the only reason that this module exists.

pub fn get_owners_compat<'c>(
    user_id: u64,
    consumer_token: &KeyPair,
    access_token: &KeyPair,
    client: &'c Client<HttpsConnector<HttpConnector>, Body>,
) -> impl Future<Output = Result<Vec<u64>, Error<'c>>> {
    get_owners_of_first_75_lists(user_id, consumer_token, access_token, client).compat()
}
pub fn get_owners_of_first_75_lists<'a, 'b, 'c>(
    user_id: u64,
    consumer_token: &'a KeyPair,
    access_token: &'b KeyPair,
    client: &'c Client<HttpsConnector<HttpConnector>, Body>,
) -> impl Future01<Item = Vec<u64>, Error = Error<'c>> {
    let uri_with_query = format!("{}?cursor=-1&user_id={}&count=75", MEMBERSHIPS, user_id);

    let mut params = HashMap::new();
    add_param(&mut params, "cursor", "-1");
    add_param(&mut params, "user_id", user_id.to_string());
    add_param(&mut params, "count", "200");

    let header = get_header(
        Method::GET,
        MEMBERSHIPS,
        consumer_token,
        Some(access_token),
        None,
        None,
        Some(&params),
    );
    let header_value = header.header_value().unwrap();
    let request = Request::connect::<Uri>(uri_with_query.parse().unwrap())
        .header(AUTHORIZATION, HeaderValue::from_str(&header_value).unwrap())
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();

    client
        .request(request)
        .map_err(|e| -> Error { Box::new(e) })
        .and_then(|response| {
            println!("get_first_75_lists status code: {}", response.status());
            let (head, body) = response.into_parts();
            body.concat2()
                .map_err(|e| -> Error { Box::new(e) })
                .map(|body| parse_list_owners(body).unwrap().take(75).collect())
        })
}

fn parse_list_owners<'a>(
    body: impl IntoIterator<Item = u8> + 'a,
) -> Result<impl Iterator<Item = u64>, Error<'a>> {
    let body_bytes: Vec<u8> = body.into_iter().collect();
    let body_json: ListMembership = serde_json::from_slice(&body_bytes)?;
    let list_owners_iter = body_json.lists.into_iter().map(|json| json.user.id);
    Ok(BTreeSet::from_iter(list_owners_iter).into_iter())
}

pub fn request_token_compat<'a>(
    con_token: &KeyPair,
    callback: impl Into<String>,
    client: &'a Client<HttpsConnector<HttpConnector>, Body>,
) -> impl Future<Output = Result<KeyPair, Error<'a>>> {
    request_token(con_token, callback, client).compat()
}

// FIXME: ensure all tokens are alphanum only also limit length
pub fn request_token<'a, 'b, S: Into<String>>(
    con_token: &'a KeyPair,
    callback: S,
    client: &'b Client<HttpsConnector<HttpConnector>, Body>,
) -> impl Future01<Item = KeyPair, Error = Error<'b>> {
    let header = get_header(
        Method::POST,
        REQUEST_TOKEN,
        con_token,
        None,
        Some(callback.into()),
        None,
        None,
    );
    let header_value = header.header_value().unwrap();
    let request = Request::connect::<Uri>(REQUEST_TOKEN.parse().unwrap())
        .header(AUTHORIZATION, HeaderValue::from_str(&header_value).unwrap())
        .method(Method::POST)
        .body(Body::empty())
        .unwrap();

    client
        .request(request)
        .map_err(|e| -> Error { Box::new(e) })
        .and_then(|response| {
            println!("request_token status code: {}", response.status());
            let (head, body) = response.into_parts();
            body.concat2()
                .map_err(|e| -> Error { Box::new(e) })
                .map(|body| {
                    let body_bytes: Vec<u8> = body.into_iter().collect();
                    // oauth_callback_confirmed: true
                    parse_oauth_tok(&body_bytes).unwrap()
                })
        })
}

pub fn access_token_compat<'a>(
    con_token: &KeyPair,
    access_token_kp: &KeyPair,
    oauth_verifier: impl Into<String>,
    client: &'a Client<HttpsConnector<HttpConnector>, Body>,
) -> impl Future<Output=Result<(KeyPair, u64), Error<'a>>> {
    access_token(con_token, access_token_kp, oauth_verifier, client).compat()
}

pub fn access_token<'a, 'b, S: Into<String>>(
    con_token: &'a KeyPair,
    access_token: &KeyPair,
    oauth_verifier: S,
    client: &'b Client<HttpsConnector<HttpConnector>, Body>,
) -> impl Future01<Item = (KeyPair, u64), Error = Error<'b>> {
    let header = get_header(
        Method::POST,
        ACCESS_TOKEN,
        con_token,
        Some(access_token),
        None,
        Some(oauth_verifier.into()),
        None,
    );
    let header_value = header.header_value().unwrap();
    let request = Request::connect::<Uri>(ACCESS_TOKEN.parse().unwrap())
        .header(AUTHORIZATION, HeaderValue::from_str(&header_value).unwrap())
        .method(Method::POST)
        .body(Body::empty())
        .unwrap();
    println!("requesting access token with: {:?}", request);
    client
        .request(request)
        .map_err(|e| -> Error { Box::new(e) })
        .and_then(|response| {
            println!("access_token status code: {}", response.status());
            let (head, body) = response.into_parts();
            body.concat2()
                .map_err(|e| -> Error { Box::new(e) })
                .map(|body| {
                    let body_bytes: Vec<u8> = body.into_iter().collect();
                    let str_body = String::from_utf8(body_bytes.clone()).unwrap();
                    println!("access token response: {}", str_body);
                    //                    user_id: 111111111
                    //                    screen_name: foobar
                    parse_oauth_tok_and_user_id(&body_bytes).unwrap()
                })
        })
}

fn parse_oauth_tok_and_user_id<'a>(full_resp: &[u8]) -> Result<(KeyPair, u64), Error<'a>> {
    let mut parsed_key: Option<String> = None;
    let mut parsed_secret: Option<String> = None;
    let mut parsed_user_id: Option<u64> = None;

    for (key, value) in form_urlencoded::parse(full_resp) {
        match key.as_ref() {
            "oauth_token" => parsed_key = Some(value.into_owned()),
            "oauth_token_secret" => parsed_secret = Some(value.into_owned()),
            "user_id" => parsed_user_id = Some(value.parse::<u64>().unwrap()),
            other => println!("{}: {}", other, value),
        }
    }

    let key: Result<String, Error> =
        parsed_key.ok_or_else(|| "Could not find oauth_token parameter".to_owned().into());
    let secret: Result<String, Error> = parsed_secret.ok_or_else(|| {
        "Could not find oauth_token_secret parameter"
            .to_owned()
            .into()
    });
    let user_id: Result<u64, Error> = parsed_user_id.ok_or_else(|| {
        "Could not find (or parse) user_id parameter"
            .to_owned()
            .into()
    });

    Ok((KeyPair::new(key?, secret?), user_id?))
}

fn parse_oauth_tok<'a>(full_resp: &[u8]) -> Result<KeyPair, Error<'a>> {
    let mut parsed_key: Option<String> = None;
    let mut parsed_secret: Option<String> = None;

    for (key, value) in form_urlencoded::parse(full_resp) {
        match key.as_ref() {
            "oauth_token" => parsed_key = Some(value.into_owned()),
            "oauth_token_secret" => parsed_secret = Some(value.into_owned()),
            other => println!("{}: {}", other, value),
        }
    }

    let key: Result<String, Error> =
        parsed_key.ok_or_else(|| "Could not find oauth_token parameter".to_owned().into());
    let secret: Result<String, Error> = parsed_secret.ok_or_else(|| {
        "Could not find oauth_token_secret parameter"
            .to_owned()
            .into()
    });

    Ok(KeyPair::new(key?, secret?))
}
///With the given method parameters, return a signed OAuth header.
fn get_header(
    method: Method,
    uri: &str,
    con_token: &KeyPair,
    access_token: Option<&KeyPair>,
    callback: Option<String>,
    verifier: Option<String>,
    params: Option<&ParamList>,
) -> TwitterOAuth {
    let now_s = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur,
        Err(err) => err.duration(),
    }
    .as_secs();
    let header = TwitterOAuth {
        consumer_key: con_token.key.to_string(),
        nonce: Alphanumeric
            .sample_iter(&mut rand::thread_rng())
            .take(32)
            .collect::<String>(),
        signature: None,
        timestamp: now_s,
        token: access_token.map(|tok| tok.key.to_string()),
        callback,
        verifier,
    };

    sign(header, method, uri, params, con_token, access_token)
}

//the encode sets in the url crate don't quite match what twitter wants, so i'll make up my own
#[derive(Copy, Clone)]
struct TwitterEncodeSet;

impl EncodeSet for TwitterEncodeSet {
    fn contains(&self, byte: u8) -> bool {
        match byte {
            b'a'...b'z' | b'A'...b'Z' | b'0'...b'9' | b'-' | b'.' | b'_' | b'~' => false,
            _ => true,
        }
    }
}

///Convenience type used to hold parameters to an API call.
pub type ParamList<'a> = HashMap<Cow<'a, str>, Cow<'a, str>>;

///Convenience function to add a key/value parameter to a `ParamList`.
pub fn add_param<'a, K, V>(list: &mut ParamList<'a>, key: K, value: V) -> Option<Cow<'a, str>>
where
    K: Into<Cow<'a, str>>,
    V: Into<Cow<'a, str>>,
{
    list.insert(key.into(), value.into())
}

fn percent_encode(src: &str) -> String {
    utf8_percent_encode(src, TwitterEncodeSet).collect::<String>()
}

///With the given OAuth header and method parameters, create an OAuth signature and return the
///header with the signature inline.
fn sign(
    header: TwitterOAuth,
    method: Method,
    uri: &str,
    params: Option<&ParamList>,
    con_token: &KeyPair,
    access_token: Option<&KeyPair>,
) -> TwitterOAuth {
    let query_string = {
        let mut sig_params = params.cloned().unwrap_or_default();

        add_param(
            &mut sig_params,
            "oauth_consumer_key",
            header.consumer_key.as_str(),
        );
        add_param(&mut sig_params, "oauth_nonce", header.nonce.as_str());
        add_param(&mut sig_params, "oauth_signature_method", "HMAC-SHA1");
        add_param(
            &mut sig_params,
            "oauth_timestamp",
            format!("{}", header.timestamp),
        );
        add_param(&mut sig_params, "oauth_version", "1.0");

        if let Some(ref token) = header.token {
            add_param(&mut sig_params, "oauth_token", token.as_str());
        }

        if let Some(ref callback) = header.callback {
            add_param(&mut sig_params, "oauth_callback", callback.as_str());
        }

        if let Some(ref verifier) = header.verifier {
            add_param(&mut sig_params, "oauth_verifier", verifier.as_str());
        }

        let mut query = sig_params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>();
        query.sort();

        query.join("&")
    };

    let base_str = format!(
        "{}&{}&{}",
        percent_encode(method.as_ref()),
        percent_encode(uri),
        percent_encode(&query_string)
    );
    let key = format!(
        "{}&{}",
        percent_encode(&con_token.secret),
        percent_encode(&access_token.unwrap_or(&KeyPair::new("", "")).secret)
    );

    let mut digest = Hmac::<Sha1>::new_varkey(key.as_bytes()).unwrap();
    digest.input(base_str.as_bytes());

    let config = base64::Config::new(base64::CharacterSet::Standard, true);

    TwitterOAuth {
        signature: Some(base64::encode_config(&digest.result().code(), config)),
        ..header
    }
}

#[derive(Clone, Debug)]
struct TwitterOAuth {
    consumer_key: String,
    nonce: String,
    signature: Option<String>,
    timestamp: u64,
    token: Option<String>,
    callback: Option<String>,
    verifier: Option<String>,
}

impl std::str::FromStr for TwitterOAuth {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut consumer_key: Option<String> = None;
        let mut nonce: Option<String> = None;
        let mut signature: Option<String> = None;
        let mut timestamp: Option<u64> = None;
        let mut token: Option<String> = None;
        let mut callback: Option<String> = None;
        let mut verifier: Option<String> = None;

        for substr in s.split(',') {
            let mut parts = substr.trim().split('=');
            match parts.next() {
                Some("oauth_consumer_key") => consumer_key = parts.next().map(str::to_string),
                Some("oauth_nonce") => nonce = parts.next().map(str::to_string),
                Some("oauth_signature") => signature = parts.next().map(str::to_string),
                Some("oauth_timestamp") => {
                    match parts.next().map(<u64 as std::str::FromStr>::from_str) {
                        Some(Ok(n)) => timestamp = Some(n),
                        Some(Err(e)) => return Err(e.description().to_string()),
                        None => timestamp = None,
                    }
                }
                Some("oauth_token") => token = parts.next().map(str::to_string),
                Some("oauth_callback") => callback = parts.next().map(str::to_string),
                Some("oauth_verifier") => verifier = parts.next().map(str::to_string),
                Some(_) => return Err("unexpected OAuth Authorization header field".to_string()),
                None => return Err("unexpected header format".to_string()),
            }
        }

        Ok(TwitterOAuth {
            consumer_key: consumer_key.ok_or("no oauth_consumer_key")?,
            nonce: nonce.ok_or("no oauth_nonce")?,
            signature,
            timestamp: timestamp.ok_or("no oauth_timestamp")?,
            token,
            callback,
            verifier,
        })
    }
}

impl TwitterOAuth {
    fn header_value(&self) -> Result<String, std::fmt::Error> {
        let mut ret = String::new();
        write!(ret, "OAuth ")?;

        write!(
            ret,
            "oauth_consumer_key=\"{}\"",
            percent_encode(&self.consumer_key)
        )?;

        write!(ret, ", oauth_nonce=\"{}\"", percent_encode(&self.nonce))?;

        if let Some(ref signature) = self.signature {
            write!(ret, ", oauth_signature=\"{}\"", percent_encode(signature))?;
        }

        write!(
            ret,
            ", oauth_signature_method=\"{}\"",
            percent_encode("HMAC-SHA1")
        )?;

        write!(ret, ", oauth_timestamp=\"{}\"", self.timestamp)?;

        if let Some(ref token) = self.token {
            write!(ret, ", oauth_token=\"{}\"", percent_encode(token))?;
        }

        write!(ret, ", oauth_version=\"{}\"", "1.0")?;

        if let Some(ref callback) = self.callback {
            write!(ret, ", oauth_callback=\"{}\"", percent_encode(callback))?;
        }

        if let Some(ref verifier) = self.verifier {
            write!(ret, ", oauth_verifier=\"{}\"", percent_encode(verifier))?;
        }
        Ok(ret)
    }
}
