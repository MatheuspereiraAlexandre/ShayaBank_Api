/* chama todas as dependencias */
use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, Responder, post, web};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chrono::{DateTime, Utc};
use chrono_tz::America::Sao_Paulo;
use mongodb::bson::doc;
use mongodb::{Client, Collection, options::ClientOptions};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Conecta no MongoDB
    let client_options = ClientOptions::parse("mongodb://localhost:27017/")
        .await
        .unwrap(); // a url do mongo claro q tem q user .env
    let client = Client::with_options(client_options).unwrap();
    let db = client.database("ShayaStorage"); // alterado para ShayaStorage, e se for mudar o banco usa isso 
    let collection = db.collection::<UserDocument>("Users"); // alterado para Users o mesmo vale para o isso

    HttpServer::new(move || {
        App::new() // defini o app no caso o webapp
            .wrap(
                Cors::default() // cors né quem não sabe não sabe
                    .allowed_origin("http://localhost:3000")
                    .allowed_methods(vec!["POST", "GET", "OPTIONS"])
                    .allowed_headers(vec!["Content-Type"])
                    .supports_credentials(),
            )
            .app_data(web::Data::new(collection.clone()))
            .service(register)
    })
    .bind(("127.0.0.1", 8080))? // binda a porta e o ip no caso ai localhost:8080
    .run()
    .await
}

#[derive(Deserialize)] // define o codigo q vai ser usado a seguir
struct UserInput {
    // input do usuario (sem ScodeN pois vai ser gerado aqui)
    name: String,     // nome
    password: String, // password
}

#[derive(Serialize)]
struct UserDocument {
    name: String,          // usa tirng no nome
    password_hash: String, // hash da senha la
    scodeN_hash: String,
    created_at: DateTime<Utc>, // pode manter como UTC no banco
}

#[post("/register")] // defini que aqui vai ser post
async fn register(
    user: web::Json<UserInput>,
    db: web::Data<Collection<UserDocument>>, // coisas quases intnediveis
) -> impl Responder {
    // função para registrar
    let argon2 = Argon2::default(); // define o argon2 

    // Gerar ScodeN aleatório (16 bytes, codificado em hex)
    let mut random_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut random_bytes);
    let scode_n_plain = hex::encode(random_bytes); // precisa da crate hex no Cargo.toml

    // Hashear senha
    let salt1 = SaltString::generate(&mut OsRng);
    let password_hash = match argon2.hash_password(user.password.as_bytes(), &salt1) {
        Ok(hash) => hash.to_string(),
        Err(_) => return HttpResponse::InternalServerError().body("Erro ao hashear senha"), // se der erro aparece tlgd
    };

    // Hashear ScodeN gerado
    let salt2 = SaltString::generate(&mut OsRng); // gera a string hashed
    let scode_hash = match argon2.hash_password(scode_n_plain.as_bytes(), &salt2) {
        Ok(hash) => hash.to_string(),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .body("Erro ao criptoafsfa essa desgraça ai ScodeN");
        } // memsa coisa da senha
    };

    // Salva no banco os hashes password_hash e scode_hash com o nome
    let created_at = chrono::Utc::now();
    let user_doc = UserDocument {
        // isso daqui é a definição do document do user para o mongo
        name: user.name.clone(),
        password_hash: password_hash.clone(),
        scodeN_hash: scode_hash.clone(),
        created_at,
    };

    if let Err(e) = db.insert_one(user_doc, None).await {
        return HttpResponse::InternalServerError()
            .body(format!("Erro ao salvar na porra do banco: {}", e)); // se der erro avisoa
    }

    // Converte para horário de Brasília para exibir na resposta
    let created_at_br = created_at.with_timezone(&Sao_Paulo);

    HttpResponse::Ok().json(json!({
        "name": user.name,
        "password_hash": password_hash,
        "scodeN_hash": scode_hash,
        "scodeN_plain": scode_n_plain,
        "created_at": created_at_br.to_rfc3339(), // retorna no horário brasileiro
    }))
}
