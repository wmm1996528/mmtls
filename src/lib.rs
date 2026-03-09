mod traits;
use ::cookie::CookieBuilder;
use ::wreq::cookie::Cookie;
use foldhash::fast::RandomState;
use http::HeaderMap;
use indexmap::IndexMap;
use napi::Error;
use napi_derive::napi;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use traits::HeadersTraits;
use uuid;
use wreq::cookie::CookieStore;
use wreq::header::OrigHeaderMap;
use wreq::http2::{StreamDependency, StreamId};
use wreq::redirect::Policy;
use wreq::{cookie, cookie::Jar, Client, EmulationFactory, Proxy};
use wreq_util::Emulation::Chrome141;
type IndexMapSSR = IndexMap<String, String, RandomState>;

// 1. 创建一个全局的 Tokio Runtime
// 因为 Java 可以在任意线程调用 Rust，我们需要一个常驻的 Runtime 来处理所有异步任务
static RT: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Failed to create Tokio runtime"));

pub struct QueryEngine {}

#[napi(js_name = "QueryEngine")]
pub struct JsQueryEngine {
  engine: QueryEngine,
}
#[napi(js_name = "ClientOptions")]
pub struct ClientOptions {
  pub proxy: Option<String>,
  pub allow_redirect: Option<bool>,
  pub header_order: Option<Vec<String>>,
  pub split_cookies: Option<bool>,
  pub debug: Option<bool>,
}

#[napi]
fn new_options(
  proxy: Option<String>,
  allow_redirect: Option<bool>,
  header_order: Option<Vec<String>>,
  split_cookies: Option<bool>,
  debug: Option<bool>,
) -> ClientOptions {
  ClientOptions {
    proxy,
    allow_redirect,
    header_order,
    split_cookies,
    debug,
  }
}
#[napi(object, js_name = "HttpResponse")]
pub struct HttpResponse {
  pub status: i8,
  pub error_msg: String,
  pub status_code: u16,
  pub body: String,
  pub content: String,
  pub headers: HashMap<String, String>,
  pub url: String,
}

pub enum TlsError {
  NetError(String),
}
pub struct JsTlsClient {}
// 你也可以导出结构体和对象方法
#[napi]
pub struct TlsClient {
  client: Mutex<Client>,
  jar: Arc<Jar>,
  header_order: Option<Vec<String>>,
  split_cookies: Option<bool>,
  debug: bool,
}

#[napi]
impl TlsClient {
  #[napi(constructor)]
  pub fn new(opt: &ClientOptions) -> Self {
    // .proxy(Proxy::all("http://127.0.0.1:7890").unwrap())
    let jar = Arc::new(cookie::Jar::default());
    let mut client_builder = Client::builder()
      .cookie_provider(jar.clone())
      .cert_verification(false);

    let mut header_order: Option<Vec<String>> = None;
    let mut split_cookies: Option<bool> = None;
    let mut debug: bool = false;
    if let Some(proxy) = &opt.proxy {
      client_builder = client_builder.proxy(Proxy::all(proxy).unwrap());
    }
    if opt.header_order.is_some() {
      header_order = opt.header_order.clone()
    }
    if opt.split_cookies.is_some() {
      split_cookies = opt.split_cookies
    }
    debug = opt.debug.unwrap_or(false);
    if let Some(allow) = opt.allow_redirect {
      if allow {
        client_builder = client_builder.redirect(Policy::limited(10));
      } else {
        client_builder = client_builder.redirect(Policy::none());
      }
    }
    let mut builder = wreq::Emulation::builder();
    let mut chrome_141 = Chrome141.emulation();
    let mut http2_options = chrome_141.http2_options_mut().clone().unwrap();
    let tls_options = chrome_141.tls_options_mut().clone().unwrap().clone();
    http2_options.headers_stream_dependency =
      Some(StreamDependency::new(StreamId::zero(), 0, true));
    let default_header = HeaderMap::new();
    builder = builder
      .tls_options(tls_options)
      .http2_options(http2_options)
      .headers(default_header.clone());
    client_builder = client_builder.emulation(builder.build());
    client_builder = client_builder.default_headers(default_header);
    let client = client_builder.build().unwrap();
    Self {
      client: Mutex::new(client),
      jar,
      header_order,
      split_cookies,
      debug,
    }
  }
  #[napi]
  pub async fn post(
    &self,
    url: String,
    data: Option<String>,
    headers: Option<HashMap<String, String>>,
  ) -> napi::Result<HttpResponse> {
    self.request("POST".to_string(), url, data, headers).await
  }
  #[napi]
  pub async fn get(
    &self,
    url: String,
    headers: Option<HashMap<String, String>>,
  ) -> napi::Result<HttpResponse> {
    self.request("GET".to_string(), url, None, headers).await
  }
  #[napi]
  pub fn clear_cookies(&self) {
    self.jar.clear();
  }
  #[napi]
  pub fn set_cookies(&self, cookies: HashMap<String, String>, url: String) {
    let parsed_url = http::uri::Uri::from_str(&url).unwrap();
    cookies.clone().into_iter().for_each(|(k, v)| {
      let cookie = CookieBuilder::new(k, v)
        .domain(parsed_url.host().unwrap().to_string())
        .path("/")
        .build();

      self.jar.add(cookie, &parsed_url)
    });
  }
  #[napi]
  pub fn get_cookies(&self) -> HashMap<String, String> {
    self
      .jar
      .clone()
      .get_all()
      .map(|x| (x.name().to_string(), x.value().to_string()))
      .collect()
  }
  async fn request(
    &self,
    method: String,
    url: String,
    data: Option<String>,
    headers: Option<HashMap<String, String>>,
  ) -> napi::Result<HttpResponse> {
    let uid = uuid::Uuid::new_v4().to_string();
    let client = self.client.lock().await.clone(); // ← assuming reqwest::Client is Clone (it is!)
    let header_order = self.header_order.clone();
    let jar_cookies = self.get_cookies();
    let split_cookies = self.split_cookies.clone();
    let debug = self.debug.clone();
    if debug {
      println!("{uid} method={method} url={url} data={data:?}");
    }
    let r = RT
      .spawn(async move {
        let header_orders = header_order.unwrap_or(vec![
          "content-length".to_string(),
          "sec-ch-ua-platform".to_string(),
          "x-auth-token".to_string(),
          "authorization".to_string(),
          "x-path".to_string(),
          "sec-ch-ua".to_string(),
          "sec-ch-ua-mobile".to_string(),
          "user-agent".to_string(),
          "accept".to_string(),
          "content-type".to_string(),
          "origin".to_string(),
          "sec-fetch-site".to_string(),
          "sec-fetch-mode".to_string(),
          "sec-fetch-dest".to_string(),
          "referer".to_string(),
          "accept-encoding".to_string(),
          "accept-language".to_string(),
          "cookie".to_string(),
          "priority".to_string(),
        ]);

        // Create request builder
        let mut request_builder = client.request(method.parse().unwrap(), url);

        // Params
        // if let Some(params) = params {
        //     request_builder = request_builder.query(&params);
        // }
        let has_files = false;
        // Calculate body content and length for POST/PUT/PATCH (before setting headers)
        let (body_bytes, content_type_header): (Option<Vec<u8>>, Option<String>) =
          if let Some(b) = data {
            (Some(b.as_str().as_bytes().to_vec()), None)
          } else {
            (None, None)
          };

        // let (body_bytes, content_type_header): (Option<Vec<u8>>, Option<String>) = if is_post_put_patch {
        //     if has_files {
        //         // Multipart will be handled later, can't pre-calculate
        //         (None, None)
        //     } else if let Some(content) = content {
        //         // Raw bytes content - move instead of clone to avoid allocation
        //         (Some(content), None)
        //     } else if let Some(form_data) = &data_value {
        //         // Data - smart handling
        //         if let Some(json_str) = form_data.as_str() {
        //             // JSON string
        //             if let Ok(parsed_json) = serde_json::from_str::<Value>(json_str) {
        //                 let serialized = serde_json::to_vec(&parsed_json)?;
        //                 (Some(serialized), Some("application/json".to_string()))
        //             } else {
        //                 (Some(json_str.as_bytes().to_vec()), None)
        //             }
        //         } else {
        //             // Check if nested
        //             let is_nested = if let Some(obj) = form_data.as_object() {
        //                 obj.values().any(|v| v.is_object() || v.is_array())
        //             } else {
        //                 false
        //             };
        //
        //             if is_nested {
        //                 // Nested - use JSON
        //                 let serialized = serde_json::to_vec(&form_data)?;
        //                 (Some(serialized), Some("application/json".to_string()))
        //             } else {
        //                 // Flat - use form-urlencoded
        //                 let encoded = serde_urlencoded::to_string(&form_data)?;
        //                 (Some(encoded.as_bytes().to_vec()), Some("application/x-www-form-urlencoded".to_string()))
        //             }
        //         }
        //     } else if let Some(json_data) = &json_value {
        //         // JSON
        //         let serialized = serde_json::to_vec(&json_data)?;
        //         (Some(serialized), Some("application/json".to_string()))
        //     } else {
        //         (None, None)
        //     }
        // } else {
        //     (None, None)
        // };

        // Cookies - get effective cookies (from parameter or cookie_jar)
        // Do this BEFORE processing headers so we can include cookies in header ordering
        let effective_cookies = {
          // Get cookies from cookie_jar
          Some(IndexMapSSR::from_iter(jar_cookies))
        };
        if debug {
          println!("{uid} cookies={effective_cookies:?}");
        }
        // Headers - reorder to match browser behavior: Host first, then Content-Length, then others
        // Merge client-level and request-level headers (request-level takes precedence)
        // This matches Python requests.Session() behavior
        let mut effective_headers = {
          if let Some(request_hdrs) = headers {
            // Has request headers - need to merge
            let mut merged =
              IndexMapSSR::with_capacity_and_hasher(request_hdrs.len(), RandomState::default());
            for (key, value) in request_hdrs {
              // Remove any existing header with same lowercase name
              merged.retain(|k, _| k.to_lowercase() != key.to_lowercase());
              merged.insert(key, value);
            }
            merged
          } else {
            // No request headers, clone client headers or create empty map
            IndexMapSSR::with_capacity_and_hasher(4, RandomState::default())
          }
        };

        // Always process headers (even if empty) to ensure Content-Type and Content-Length are added
        {
          let hdrs = &mut effective_headers;
          // Create a new ordered map with strict ordering
          let mut reordered_headers =
            IndexMapSSR::with_capacity_and_hasher(hdrs.len() + 2, RandomState::default());

          // 1. First, add Host header if present (case-insensitive check)
          let host_value = hdrs
            .get("Host")
            .or_else(|| hdrs.get("host"))
            .or_else(|| hdrs.get("HOST"));

          if let Some(host) = host_value {
            reordered_headers.insert("Host".to_string(), host.clone());
          }

          // 2. For POST/PUT/PATCH with body, add Content-Length in 2nd position
          if let Some(ref body) = body_bytes {
            let content_length = body.len().to_string();
            reordered_headers.insert("Content-Length".to_string(), content_length);
          } else if has_files {
            // For multipart, we can't pre-calculate, but reserve the position
            // This will be overwritten by wreq, but maintains position
            reordered_headers.insert("Content-Length".to_string(), "0".to_string());
          }

          // 3. Only add auto-calculated Content-Type in 3rd position if user didn't provide one
          // This allows user's Content-Type to maintain its original position in headers
          let user_has_content_type = hdrs.iter().any(|(k, _)| k.to_lowercase() == "content-type");

          if !user_has_content_type {
            if let Some(ct) = content_type_header {
              // No user Content-Type, use auto-calculated in 3rd position
              reordered_headers.insert("Content-Type".to_string(), ct);
            }
          }

          // 4. Add all other headers in their original order (including user's Content-Type if provided)
          // Skip: Host, Content-Length (already handled above)
          // Skip: priority, cookie (will be added at the end)
          let mut priority_header: Option<(String, String)> = None;
          let mut cookie_from_headers: Option<(String, String)> = None;

          for key in header_orders {
            // for (key, value) in hdrs.iter() {
            let key_lower = key.to_lowercase();

            // Skip host, content-length (already handled above)
            if key_lower == "host" || key_lower == "content-length" {
              continue;
            }

            // For Content-Type: skip if already auto-added, otherwise add in user's original position
            if key_lower == "content-type" {
              // Check if we already auto-added Content-Type in step 3
              let already_exists = reordered_headers
                .keys()
                .any(|k| k.to_lowercase() == "content-type");
              if already_exists {
                continue; // Skip, already auto-added
              }
              // Otherwise, fall through to add user's Content-Type in original position
            }

            // Check if this header (by lowercase name) is already in reordered_headers
            let already_exists = reordered_headers
              .keys()
              .any(|k| k.to_lowercase() == key_lower);
            if already_exists {
              continue;
            }
            if let Some(value) = hdrs.remove(&key_lower) {
              if key_lower == "priority" {
                priority_header = Some((key.to_string().clone(), value.clone()));
              } else if key_lower == "cookie" {
                cookie_from_headers = Some((key.to_string(), value.clone()));
              } else {
                reordered_headers.insert(key.to_string(), value.clone());
              }
            }
          }
          for (key, value) in hdrs.iter() {
            let key_lower = key.to_lowercase();
            let already_exists = reordered_headers
              .keys()
              .any(|k| k.to_lowercase() == key_lower);
            if already_exists {
              continue;
            }
            reordered_headers.insert(key.to_string(), value.clone());
          }
          // 5. Handle cookies based on split_cookies option
          let should_add_cookies_separately = split_cookies.unwrap_or(false);

          // Build orig_headermap manually to control exact order
          let mut orig_headermap = OrigHeaderMap::with_capacity(reordered_headers.len() + 10);

          // Add all current headers to orig_headermap
          for (key, _) in reordered_headers.iter() {
            orig_headermap.insert(key.clone());
          }

          if should_add_cookies_separately {
            // Split cookies: add each cookie as a separate header in orig_headermap
            if let Some(cookies) = &effective_cookies {
              for (_k, _v) in cookies.iter() {
                // Add to orig_headermap for ordering
                orig_headermap.insert("cookie".to_string());
                // Add to request_builder after applying headers
              }
            } else if let Some((_, ref value)) = cookie_from_headers {
              // Split the cookie value and add each part
              for part in value.split(';') {
                let part = part.trim();
                if !part.is_empty() {
                  orig_headermap.insert("cookie".to_string());
                }
              }
            }

            // Add priority to orig_headermap at the end
            if let Some((ref key, _)) = priority_header {
              orig_headermap.insert(key.clone());
            }
          } else {
            // Merge cookies into single header
            if let Some(cookies) = &effective_cookies {
              if !cookies.is_empty() {
                let cookie_value = cookies
                  .iter()
                  .map(|(k, v)| format!("{}={}", k, v))
                  .collect::<Vec<_>>()
                  .join("; ");
                reordered_headers.insert("cookie".to_string(), cookie_value);
                orig_headermap.insert("cookie".to_string());
              }
            } else if let Some((ref key, ref value)) = cookie_from_headers {
              reordered_headers.insert(key.clone(), value.clone());
              orig_headermap.insert(key.clone());
            }

            // Add priority at the very end
            if let Some((ref key, ref value)) = priority_header {
              reordered_headers.insert(key.clone(), value.clone());
              orig_headermap.insert(key.clone());
            }
          }

          // Apply the reordered headers with strict order preservation
          let headers_headermap = reordered_headers.to_headermap();
          request_builder = request_builder
            .default_headers(false)
            .headers(headers_headermap)
            .orig_headers(orig_headermap);

          // If split_cookies=true, add cookies separately using header_append
          if should_add_cookies_separately {
            if let Some(cookies) = &effective_cookies {
              if !cookies.is_empty() {
                for (k, v) in cookies.iter() {
                  let cookie_value = format!("{}={}", k, v);
                  request_builder = request_builder.header("cookie", cookie_value);
                }
              }
            } else if let Some((_, ref value)) = cookie_from_headers {
              // If cookie came from headers, split it
              for part in value.split(';') {
                let part = part.trim();
                if !part.is_empty() {
                  request_builder = request_builder.header("cookie", part);
                }
              }
            }

            // Add priority after cookies to maintain order
            // Use header_append to ensure it's added at the end
            if let Some((ref key, ref value)) = priority_header {
              request_builder = request_builder.header(key, value);
            }
          }
        } // End of header processing block

        // Only if method POST || PUT || PATCH

        if let Some(body) = body_bytes {
          request_builder = request_builder.body(body);
        }
        let request = request_builder.build().unwrap();
        if debug {
          println!("{uid} request.headers={:?}", request.headers());
        }

        // Send the request and await the response
        let resp = client.execute(request).await;
        match resp {
          Ok(res) => {
            let res_headers: HashMap<String, String> = res
              .headers()
              .clone()
              .iter()
              .map(|(k, v)| {
                (
                  k.clone().to_string(),
                  v.clone().to_str().unwrap().to_string(),
                )
              })
              .collect();
            let status_code = res.status().as_u16();
            let resp_url = res.uri().to_string();
            let body = res.text().await;
            if debug {
              println!("{uid} response.headers={:?}", res_headers);
              println!("{uid} response.body={:?}", body);
            }
            Ok(HttpResponse {
              status: 0,
              error_msg: "".to_string(),
              status_code,
              body: body.unwrap().to_string(),
              content: "".to_string(),
              headers: res_headers,
              url: resp_url,
            })
          }
          Err(err) => Err(Error::from_reason(err.to_string())),
        }
      })
      .await
      .expect("Failed to spawn request");
    r
  }
}
