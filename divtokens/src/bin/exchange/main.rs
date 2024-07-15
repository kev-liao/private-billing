////#![deny(warnings)]
//use challenge_bypass_ristretto::voprf::SigningKey;
//use divtokens::voprf::{
//    exchange::Exchange,
//    messages::{
//        IssueRequest,
//        RedeemRequest,
//    },
//};
//use parking_lot::RwLock;
//use rand::rngs::OsRng;
//use std::sync::Arc;
//use warp::Filter;
//
//async fn sign_tokens(req: IssueRequest,
//                     exchange: Exchange)
//                     -> Result<impl warp::Reply, warp::Rejection> {
//    let resp = exchange.sign_tokens(req);
//    Ok(warp::reply::json(&resp))
//}
//
//async fn redeem_tokens(req: RedeemRequest,
//                       mut exchange: Exchange)
//                       -> Result<impl warp::Reply, warp::Rejection> {
//    let resp = exchange.redeem_tokens(&req);
//    Ok(warp::reply::json(&resp))
//}
//
////#[tokio::main]
//#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
//async fn main() {
//    let mut rng = OsRng;
//    let signing_key = SigningKey::random(&mut rng);
//    let exchange = Exchange {
//        signing_key,
//        spent_tokens: Arc::new(RwLock::new(Vec::new())),
//    };
//    
//    let issue = warp::path("issue")
//        .and(warp::body::content_length_limit(1024 * 16))
//        .and(warp::body::json())
//        .and_then({
//            let exchange = exchange.clone();
//            move |req| sign_tokens(req, exchange.clone())
//        });
//    
//    let redeem = warp::path("redeem")
//        .and(warp::body::content_length_limit(1024 * 16))
//        .and(warp::body::json())
//        .and_then({
//            let exchange = exchange.clone();
//            move |req| redeem_tokens(req, exchange.clone())
//        });
//
//    let routes = warp::post().and(
//        issue.or(redeem),
//    );
//
//    warp::serve(routes)
//        .tls()
//        .cert_path("config/exchange-cert.pem")
//        .key_path("config/exchange-key.pem")
//        .run(([127, 0, 0, 1], 3030))
//        .await;
//}

fn main() {
}
