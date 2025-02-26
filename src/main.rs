use actix_files as fs;
use actix_multipart::Multipart;
use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorInternalServerError,
    middleware::{DefaultHeaders, Logger},
    web, App, Error, HttpRequest, HttpResponse, HttpServer,
};
use actix_web::rt::task;
use clap::Parser;
use futures_util::future::{ok, LocalBoxFuture, Ready};
use futures_util::StreamExt;
use rand::rng;
use rand::Rng;
use serde_json::json;
use std::{
    fs as stdfs,
    io::Write,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tera::{Context as TeraContext, Tera, to_value, Value};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use actix_web::http::header::HeaderValue;
use hostname::get as get_hostname;
use std::collections::HashMap;
use urlencoding::encode;

use rust_embed::RustEmbed;
use mime_guess::from_path;

#[derive(RustEmbed)]
#[folder = "templates/"]
pub struct Templates;

#[derive(RustEmbed)]
#[folder = "public/"]
pub struct PublicFiles;

fn url_encode_filter(value: &Value, _args: &HashMap<String, Value>) -> tera::Result<Value> {
    if let Some(s) = value.as_str() {
        Ok(to_value(encode(s).into_owned())?)
    } else {
        Err("url_encode filter: value is not a string".into())
    }
}

fn custom_ends_with_test(value: Option<&Value>, args: &[Value]) -> tera::Result<bool> {
    let s = match value {
        Some(val) => val.as_str().ok_or("ends_with test: value is not a string")?,
        None => return Ok(false),
    };
    if args.len() != 1 {
        return Err("ends_with test: expected exactly one argument".into());
    }
    let suffix = args[0].as_str().ok_or("ends_with test: argument is not a string")?;
    Ok(s.ends_with(suffix))
}

/// Load embedded templates into a Tera instance.
fn load_embedded_templates() -> tera::Result<Tera> {
    let mut tera = Tera::default();
    for file in Templates::iter() {
        if let Some(content) = Templates::get(&file) {
            let s = std::str::from_utf8(content.data.as_ref())
                .map_err(|e| tera::Error::msg(format!("UTF8 error in {}: {}", file, e)))?;
            tera.add_raw_template(&file, s)?;
        }
    }
    Ok(tera)
}

/// Command-line configuration options.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// Port the server listens on.
    #[arg(short = 'P', long, default_value_t = 58080)]
    port: u16,

    /// Username for Basic Auth.
    #[arg(short, long, default_value = "admin")]
    user: String,

    /// Password for Basic Auth.
    #[arg(short, long, default_value = "password")]
    password: String,

    /// Directory to store uploaded files.
    #[arg(short, long, default_value = "./")]
    dir: String,

    /// Maximum number of files per upload.
    #[arg(long = "max-files", default_value_t = 10)]
    max_files: usize,

    /// Maximum allowed file size (in bytes).
    #[arg(long = "max-size", default_value_t = 5 * 1024 * 1024 * 1024)]
    max_size: usize,

    /// Comma-separated list of allowed file extensions (without dots); leave blank for no restrictions.
    #[arg(long = "extensions", default_value = "")]
    extensions: String,
}

impl Config {
    fn allowed_extensions(&self) -> Vec<String> {
        if self.extensions.trim().is_empty() {
            vec![]
        } else {
            self.extensions
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .collect()
        }
    }
}

/// Application state shared among handlers.
struct AppState {
    config: Config,
    tera: Tera,
    upload_dir: PathBuf,
}

/// Generates a simple random alphanumeric password.
fn generate_simple_random_password(length: usize) -> String {
    let mut rng = rng();
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..chars.len());
            chars[idx] as char
        })
        .collect()
}

/// Checks the provided Authorization header against our configuration.
fn check_auth_header(auth: Option<HeaderValue>, config: &Config) -> Result<(), HttpResponse> {
    if let Some(val) = auth {
        if let Ok(auth_str) = val.to_str() {
            if auth_str.starts_with("Basic ") {
                let encoded = &auth_str[6..];
                if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(encoded) {
                    if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                        let parts: Vec<&str> = decoded.splitn(2, ':').collect();
                        if parts.len() == 2 && parts[0] == config.user && parts[1] == config.password {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    let mut resp = HttpResponse::Unauthorized();
    resp.insert_header(("WWW-Authenticate", r#"Basic realm="uplite""#));
    Err(resp.finish())
}

/// Handler to serve embedded static files from the "public" folder.
async fn embedded_static(req: HttpRequest) -> Result<HttpResponse, Error> {
    // Extract the path from the URL (everything after /static/)
    let path: String = req.match_info().query("filename").parse().unwrap_or_default();
    if let Some(content) = PublicFiles::get(&path) {
        let mime = from_path(&path).first_or_octet_stream();
        Ok(HttpResponse::Ok()
            .content_type(mime.as_ref())
            .body(content.data.into_owned()))
    } else {
        Ok(HttpResponse::NotFound().body("Not Found"))
    }
}

/// Renders the index page.
async fn index(_req: HttpRequest, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    let mut entries: Vec<(String, u64)> = vec![];
    for entry in stdfs::read_dir(&data.upload_dir).map_err(ErrorInternalServerError)? {
        let entry = entry.map_err(ErrorInternalServerError)?;
        let path = entry.path();
        if path.is_file() {
            let metadata = stdfs::metadata(&path).map_err(ErrorInternalServerError)?;
            let mtime = metadata
                .modified()
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if let Some(fname) = path.file_name().and_then(|s| s.to_str()) {
                entries.push((fname.to_string(), mtime));
            }
        }
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    let files: Vec<String> = entries.into_iter().map(|(name, _)| name).collect();
    let mut ctx = TeraContext::new();
    ctx.insert("files", &files);
    eprintln!("Files: {:?}", files);
    let rendered = data.tera.render("index.html", &ctx).map_err(|e| {
        eprintln!("Tera render error: {:?}", e);
        ErrorInternalServerError(e)
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Handles file uploads via multipart/form-data.
async fn upload(mut payload: Multipart, _req: HttpRequest, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    let config = &data.config;
    let allowed_extensions = config.allowed_extensions();
    let mut file_count = 0;
    while let Some(item) = payload.next().await {
        let mut field = item?;
        file_count += 1;
        if file_count > config.max_files {
            return Ok(HttpResponse::BadRequest().body("Too many files uploaded."));
        }
        let original_filename = if let Some(cd) = field.content_disposition() {
            if let Some(fname) = cd.get_filename() { fname.to_string() } else { continue; }
        } else { continue; };
        if !allowed_extensions.is_empty() {
            let ext = Path::new(&original_filename)
                .extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
            if !allowed_extensions.contains(&ext) {
                return Ok(HttpResponse::BadRequest().body(
                    format!("Invalid file type. Allowed extensions are: {}", allowed_extensions.join(", "))
                ));
            }
        }
        let re = Regex::new(r"[^a-zA-Z0-9_\-\.]").unwrap();
        let clean_filename = re.replace_all(&original_filename, "_");
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let filename = format!("{}-{}", timestamp, clean_filename);
        let filepath = data.upload_dir.join(&filename);
        let file = stdfs::File::create(&filepath).map_err(ErrorInternalServerError)?;
        let file = Arc::new(Mutex::new(file));
        while let Some(chunk) = field.next().await {
            let data_chunk = chunk?;
            let file = file.clone();
            task::spawn_blocking(move || {
                let mut f = file.lock().unwrap();
                f.write_all(&data_chunk)
            })
            .await
            .map_err(ErrorInternalServerError)??;
        }
    }
    Ok(HttpResponse::SeeOther().append_header(("Location", "/")).finish())
}

/// Renders a page displaying detailed file information.
async fn info(_req: HttpRequest, data: web::Data<AppState>, path: web::Path<String>) -> Result<HttpResponse, Error> {
    let filename = path.into_inner();
    let filepath = data.upload_dir.join(&filename);
    if !filepath.exists() {
        return Ok(HttpResponse::NotFound().body("File not found."));
    }
    let metadata = stdfs::metadata(&filepath).map_err(ErrorInternalServerError)?;
    let size_mb = (metadata.len() as f64) / (1024.0 * 1024.0);
    let modified = metadata.modified().ok().and_then(|mtime| mtime.elapsed().ok())
        .map(|d| format!("{} seconds ago", d.as_secs()))
        .unwrap_or_else(|| "unknown".to_string());
    let host = get_hostname().unwrap_or_else(|_| "unknown".into()).to_string_lossy().into_owned();
    let file_info = json!({
        "name": filename,
        "size": format!("{:.2} MB", size_mb),
        "modified": modified,
        "absolutePath": filepath.to_string_lossy(),
        "host": host,
    });
    let mut ctx = TeraContext::new();
    ctx.insert("fileInfo", &file_info);
    let rendered = data.tera.render("info.html", &ctx).map_err(ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Renders a confirmation page for file deletion.
async fn delete_confirm(_req: HttpRequest, data: web::Data<AppState>, path: web::Path<String>) -> Result<HttpResponse, Error> {
    let filename = path.into_inner();
    let filepath = data.upload_dir.join(&filename);
    if !filepath.exists() {
        return Ok(HttpResponse::NotFound().body("File not found."));
    }
    let mut ctx = TeraContext::new();
    ctx.insert("fileName", &filename);
    let rendered = data.tera.render("confirm-delete.html", &ctx).map_err(ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Deletes the specified file and redirects to the index.
async fn delete_file(_req: HttpRequest, data: web::Data<AppState>, path: web::Path<String>) -> Result<HttpResponse, Error> {
    let filename = path.into_inner();
    let filepath = data.upload_dir.join(&filename);
    if filepath.exists() {
        let _ = web::block(move || stdfs::remove_file(filepath))
            .await
            .map_err(ErrorInternalServerError)?;
    }
    Ok(HttpResponse::SeeOther().append_header(("Location", "/")).finish())
}

/// Basic authentication middleware.
struct BasicAuth;

impl<S, B> Transform<S, ServiceRequest> for BasicAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = BasicAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    fn new_transform(&self, service: S) -> Self::Future {
        ok(BasicAuthMiddleware { service: Rc::new(service) })
    }
}

struct BasicAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for BasicAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;
    
    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }
    
    fn call(&self, req: ServiceRequest) -> Self::Future {
        if req.path().starts_with("/static") {
            let svc = self.service.clone();
            Box::pin(async move {
                svc.call(req)
                    .await
                    .map(|res| res.map_into_boxed_body())
            })
        } else {
            let config = req
                .app_data::<web::Data<AppState>>()
                .expect("AppState missing")
                .config
                .clone();
            let auth_result = check_auth_header(req.headers().get("Authorization").cloned(), &config);
            let svc = self.service.clone();
            Box::pin(async move {
                match auth_result {
                    Ok(()) => svc.call(req).await.map(|res| res.map_into_boxed_body()),
                    Err(resp) => Ok(req.into_response(resp.map_into_boxed_body())),
                }
            })
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let mut config = Config::parse();
    if config.password == "password" {
        config.password = generate_simple_random_password(8);
    }
    let upload_dir = PathBuf::from(&config.dir)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&config.dir));
    stdfs::create_dir_all(&upload_dir).expect("Failed to create upload directory");

    println!("\n=== uplite server is running ===\n");
    println!(" - Shared Folder     : {:?}", upload_dir);
    println!(" - Username          : {}", config.user);
    println!(" - Password          : {}", config.password);
    println!(" - Allowed Extensions: {}",
        if config.allowed_extensions().is_empty() {
            "All".to_string()
        } else {
            config.allowed_extensions().join(", ")
        }
    );
    println!(" - Max Files/Upload  : {}", config.max_files);
    println!(" - Max File Size     : {:.2} MB\n", (config.max_size as f64) / (1024.0 * 1024.0));

    // Load embedded templates.
    let mut tera = load_embedded_templates().expect("Error loading embedded templates");
    tera.register_filter("url_encode", url_encode_filter);
    tera.register_tester("ends_with", custom_ends_with_test);

    let state = web::Data::new(AppState {
        config: config.clone(),
        tera,
        upload_dir: upload_dir.clone(),
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(
                DefaultHeaders::new()
                    .add(("Cache-Control", "no-store"))
                    .add(("X-Content-Type-Options", "nosniff")),
            )
            .wrap(BasicAuth)
            .app_data(state.clone())
            // Serve embedded static files on /static
            .service(
                web::resource("/static/{filename:.*}")
                    .route(web::get().to(|req: HttpRequest| async move {
                        let filename: String = req.match_info().query("filename").parse().unwrap_or_default();
                        if let Some(content) = PublicFiles::get(&filename) {
                            let mime = from_path(&filename).first_or_octet_stream();
                            Ok::<HttpResponse, Error>(HttpResponse::Ok()
                                .content_type(mime.as_ref())
                                .body(content.data.into_owned()))
                        } else {
                            Ok::<HttpResponse, Error>(HttpResponse::NotFound().body("Not Found"))
                        }
                    }))
            )
            // Serve uploaded files on /downloads (not embedded)
            .service(fs::Files::new("/downloads", state.upload_dir.to_str().unwrap()).show_files_listing())
            .service(
                web::scope("")
                    .route("/", web::get().to(index))
                    .route("/upload", web::post().to(upload))
                    .route("/info/{filename}", web::get().to(info))
                    .route("/delete/{filename}", web::get().to(delete_confirm))
                    .route("/delete/{filename}", web::post().to(delete_file))
            )
    })
    .bind(("0.0.0.0", config.port))?
    .run()
    .await
}
