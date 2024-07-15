//use divtokens::voprf::messages::{
//    RedeemRequest,
//    RedeemResponse,
//    WinNotice,
//};
//use reqwest::ClientBuilder;
//use std::{fs::File, io::Read};
//
//#[tokio::main]
//async fn main() -> Result<(), Box<dyn std::error::Error>> {
//    // TODO: Ad auction
//
//    let req = WinNotice { price: 42 };
//    
//    let mut buf = Vec::new();
//    File::open("config/rootCA.pem")?
//        .read_to_end(&mut buf)?;
//    let cert = reqwest::Certificate::from_pem(&buf)?;
//
//    let cb = ClientBuilder::new()
//        .add_root_certificate(cert)
//        .build()?;
//    let resp = cb
//        .post("https://localhost:3031/win")
//        .json(&req)
//        .send()
//        .await?;
//    
//    let resp = resp
//        .json::<RedeemRequest>()
//        .await?;
//
//    let resp = cb
//        .post("https://localhost:3032/redeem")
//        .json(&resp)
//        .send()
//        .await?;
//
//    let resp = resp
//        .json::<RedeemResponse>()
//        .await?;
//
//    println!("{:#?}", resp);
//    
//    Ok(())    
//}

fn main() {
}
