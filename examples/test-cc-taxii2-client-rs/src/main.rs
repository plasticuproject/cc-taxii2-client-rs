use cc_taxii2_client_rs::{CCTaxiiClient, TaxiiClient};
use std::collections::HashMap;
use std::env;

fn main() {
    dotenv::dotenv().ok();
    let username = env::var("TAXII_USERNAME").expect("You've not set the TAXII_USERNAME");
    let api_key = env::var("TAXII_API_KEY").expect("You've not set the TAXII_API_KEY");
    let agent = CCTaxiiClient::new(&username, &api_key);

    // Print CloudCover Taxii server information.
    match agent.get_discovery() {
        Ok(discovery) => {
            println!("Discovery: {:?}", discovery);
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

    // Print availible Collections for an account.
    match agent.get_collections(&username) {
        Ok(collections) => {
            println!("collections: {:?}", collections);
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

    // Print count of all indicator type IoCs for the public root silo.
    let mut matches = HashMap::new();
    matches.insert("type", "indicator");
    match agent.get_cc_indicators(None, Some(5), false, None, &None, false) {
        Ok(indicators) => {
            //println!("indicators: {:?}", indicators);
            println!("{:?}", indicators.len());
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

    // Print count of all IoCs for the private account root silo.
    match agent.get_cc_indicators(None, Some(5), true, None, &None, false) {
        Ok(indicators) => {
            //println!("indicators: {:?}", indicators);
            println!("{:?}", indicators.len());
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}
