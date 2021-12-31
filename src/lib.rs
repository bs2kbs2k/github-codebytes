use worker::*;

mod utils;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
}

#[event(fetch)]
pub async fn main(req: Request, env: Env) -> Result<Response> {
    log_request(&req);

    // Optionally, get more helpful error messages written to the console in the case of a panic.
    utils::set_panic_hook();

    // Optionally, use the Router to handle matching endpoints, use ":name" placeholders, or "*name"
    // catch-alls to match on specific patterns. Alternatively, use `Router::with_data(D)` to
    // provide arbitrary data that will be accessible in each route via the `ctx.data()` method.
    let router = Router::new();

    // Add as many routes as your Worker needs! Each route will get a `Request` for handling HTTP
    // functionality and a `RouteContext` which you can use to  and get route parameters and
    // Environment bindings like KV Stores, Durable Objects, Secrets, and Variables.
    router
        .get("/", |_, _| Response::from_html(include_str!("index.html").replace("CLIENT_ID", env!("CLIENT_ID"))))
        .get_async("/callback", |req, ctx| async move {
            async fn handle(req: Request, ctx: RouteContext<()>) -> Result<Response> {
                let mut url = req.url()?;
                let code = url.query_pairs().next().ok_or(Error::RustError("github's fault".to_string()))?.1;
                let mut req = Url::parse("https://github.com/login/oauth/access_token")?;
                req.query_pairs_mut()
                    .append_pair("client_id", env!("CLIENT_ID"))
                    .append_pair("client_secret", env!("CLIENT_SECRET"))
                    .append_pair("code", &code);
                let mut headers = Headers::new();
                headers.append("Accept", "application/json")?;
                let req =
                    Request::new_with_init(req.as_str(), RequestInit::new().with_headers(headers))?;
                let mut resp = Fetch::Request(req).send().await?;
                let resp: serde_json::Value = resp.json().await?;
                let token = resp["access_token"].clone();
                let token = token.as_str().ok_or(Error::RustError("github's fault".to_string()))?;
                url.set_path("/");
                url.set_query(None);
                let mut headers = Headers::new();
                headers.set("Set-Cookie", format!("token={}", token).as_str())?;
                headers.set("Location", url.as_str())?;
                Ok(Response::redirect(url)?.with_headers(headers))
            }
            match handle(req, ctx).await {
                Ok(resp) => Ok(resp),
                Err(resp) => Response::error(resp.to_string(), 500),
            }
        })
        .get("/worker-version", |_, ctx| {
            let version = ctx.var("WORKERS_RS_VERSION")?.to_string();
            Response::ok(version)
        })
        .run(req, env)
        .await
}
