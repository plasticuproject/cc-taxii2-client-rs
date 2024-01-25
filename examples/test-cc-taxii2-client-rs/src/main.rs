use cc_taxii2_client::{CCTaxiiClient, TaxiiClient};
use std::collections::HashMap;

fn main() {
    // Print CloudCover Taxii server information.
    let agent = CCTaxiiClient::new("account_name", "API_key");
    match agent.get_discovery() {
        Ok(discovery) => {
            println!("Discovery: {:?}", discovery);
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

    // Print availible Collections for an account.
    match agent.get_collections("cloudcover") {
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
    match agent.get_cc_indicators(None, None, false, None, &None, true) {
        Ok(indicators) => {
            //println!("indicators: {:?}", indicators);
            println!("{:?}", indicators.len());
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

    // Print count of all IoCs for the private account root silo.
    match agent.get_cc_indicators(None, None, true, None, &None, true) {
        Ok(indicators) => {
            //println!("indicators: {:?}", indicators);
            println!("{:?}", indicators.len());
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

}
