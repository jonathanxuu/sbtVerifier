use std::fs;
mod helpers;
use helpers::calRoothash::restore_roothash;

use actix_web::middleware::Logger;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use env_logger::Env;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Req {
    // used to verify the ZKP result
    pub program_hash: String,
    pub stack_inputs: String,
    pub zkp_result: String,
}

// #[derive(Deserialize, Serialize, Debug)]
// pub struct Resp {
//     roothash: String,
//     security_level: u32,
// }



// #[post("verify")]
// async fn verify(req: web::Json<Req>) -> impl Responder {
fn main() {
    let zkp_result: String =
        fs::read_to_string("src/zkp_result.json").expect("LogRocket: error reading file");
    let program_hash: String =
        String::from("01d680e6c4f82c8274c43626c67a0f494e65f147245330a3bd6a9c69271223c1");
    let stack_inputs: String = String::from("12");

    // A request data demo
    let req_data = Req {
        program_hash,
        stack_inputs,
        zkp_result,
    };

    // =========================== Execution Phrase ===============================
    // We suppose the User has generated his/her ZKP via zkID Wallet,

    // ========================== User Send ZKP To Us ===========================
    // User send its ZKP to us, and we saved it in the `./zkp_result.json` , we only verify the ZKP in rust

    // ========================== Verification Phrase =============================
    // In the Verification Phrase, we check the validity of user's zkp result(if the ZKP is valid, the verify_result should be a u32 which represent security level, i.g. 96)
    let security_level: u32 = miden_vm::verify_zk_program(
        req_data.program_hash,
        req_data.stack_inputs,
        req_data.zkp_result.clone(),
    );
    let roothash: String = restore_roothash(req_data.zkp_result);
    // assert_eq!(
    //     type_of(verify_result), u32,
    //     "The User's ZKP doesn't pass the verification"
    // );

    if type_of(security_level) != String::from("u32") {
        log::warn!("The User's ZKP doesn't pass the verification.")
    } else {
        log::info!("Success.")
    }

    // HttpResponse::Ok().json(Resp {
    //     roothash,
    //     security_level
    // });
}

// ====================== Helper Function ====================================
fn type_of<T>(_: T) -> &'static str {
    std::any::type_name::<T>()
}

// #[get("/")]
// async fn echo() -> impl Responder {
//     HttpResponse::Ok().body("OK")
// }

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     env_logger::init_from_env(Env::default().default_filter_or("debug"));

//     HttpServer::new(|| {
//         App::new()
//             .wrap(Logger::default())
//             .wrap(Logger::new("%a %{User-Agent}i"))
//             .service(echo)
//             .service(verify)
//     })
//     .bind(("0.0.0.0", 7010))?
//     .run()
//     .await
// }
