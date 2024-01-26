use crate::{
    taxiiclient::Collections,
    taxiiclient::Discovery,
    Result, TaxiiClient,
    TaxiiError::{
        JsonDeserializationError, TaxiiAuthorizationError, TaxiiCollectionError,
        TaxiiConnectionError, TaxiiGenericError, TaxiiNotFound,
    },
};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use ureq::{Agent, Response};

/// Represents an Indicator of Compromise (`IoC`) within a TAXII feed.
///
/// This struct encapsulates the details of an `IoC`, including its pattern, type, and metadata.
///
/// # Fields
///
/// - `created`: The creation date of the `IoC`.
/// - `description`: A human-readable description of the `IoC`.
/// - `id`: The unique identifier of the `IoC`.
/// - `modified`: The last modification date of the `IoC`.
/// - `name`: The name of the `IoC`.
/// - `pattern`: The pattern of the `IoC` used for matching.
/// - `pattern_type`: The type of pattern used.
/// - `pattern_version`: The version of the pattern syntax.
/// - `spec_version`: The TAXII specification version.
/// - `type`: The type of the `IoC` (e.g., "indicator").
/// - `valid_from`: The date from which the `IoC` is considered valid.
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct CCIndicator {
    created: String,
    description: String,
    id: String,
    modified: String,
    name: String,
    pattern: String,
    pattern_type: String,
    pattern_version: String,
    spec_version: String,
    r#type: String,
    valid_from: String,
}

/// Represents a `CloudCover `TAXII Envelope, used for wrapping `CloudCover `TAXII objects.
///
/// The Envelope is a container for objects in TAXII, potentially including additional
/// pagination information.
///
/// # Fields
///
/// - `more`: Indicates if more data is available (pagination).
/// - `next`: The URL for the next set of data, if `more` is `true`.
/// - `objects`: A collection of TAXII objects, each represented as a `HashMap<String, String>`.
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct CCEnvelope {
    more: Option<bool>,
    next: Option<String>,
    objects: Vec<CCIndicator>,
}

/// A Custom TAXII client for interacting with the `CloudCover`TAXII server.
///
/// This struct encapsulates the necessary details to make requests to a TAXII server,
/// including the server's base URL and common headers.
///
/// # Fields
///
/// - `agent`: The HTTP agent used to send requests.
/// - `base_url`: The base URL of the TAXII server.
/// - `common_headers`: Common HTTP headers included in every request.
/// - `account`: Username/account name used for TAXII server authentification.
pub struct CCTaxiiClient {
    agent: Agent,
    base_url: &'static str,
    common_headers: Vec<(&'static str, String)>,
    account: String,
}

impl TaxiiClient for CCTaxiiClient {
    fn new(username: &str, api_key: &str) -> Self {
        let key = format!("{username}:{api_key}");
        let auth = format!("Basic {}", base64::encode(key.as_bytes()));
        Self {
            account: username.to_string(),
            agent: Agent::new(),
            base_url: "https://taxii2.cloudcover.net",
            common_headers: vec![
                (
                    "Content-Type",
                    "application/taxii+json;version=2.1".to_owned(),
                ),
                ("Accept", "application/taxii+json;version=2.1".to_owned()),
                ("Authorization", auth),
            ],
        }
    }

    fn request(&self, url: &str) -> Result<Response> {
        let endpoint = format!("{}/{url}", self.base_url);
        let request = self
            .common_headers
            .iter()
            .fold(self.agent.request("GET", &endpoint), |req, (key, value)| {
                req.set(key, value)
            })
            .timeout(Duration::from_secs(30));
        match request.call() {
            Ok(response) => Ok(response),
            Err(ureq::Error::Status(code, response)) => match code {
                401 => Err(Box::new(TaxiiAuthorizationError(response))),
                404 => Err(Box::new(TaxiiNotFound(response))),
                _ => Err(Box::new(TaxiiGenericError(response))),
            },
            Err(_) => Err(Box::new(TaxiiConnectionError(
                "Request failed to execute".to_string(),
            ))),
        }
    }

    fn get_discovery(&self) -> Result<Discovery> {
        let response = self.request("taxii2/")?;
        response
            .into_json()
            .map_err(|e| Box::new(JsonDeserializationError(e.to_string())))
    }

    fn get_collections(&self, root: &str) -> Result<Vec<String>> {
        let collections_endpoint = format!("{root}/collections/");
        let response = self.request(&collections_endpoint)?;
        let collections: Collections = response
            .into_json()
            .map_err(|e| JsonDeserializationError(e.to_string()))?;
        Ok(collections.collections.into_iter().map(|c| c.id).collect())
    }
}

impl CCTaxiiClient {
    /// Retrieves a list of cyber threat indicators from the `CloudCover` TAXII server.
    ///
    /// This method fetches cyber threat indicators from a specified collection. It supports
    /// filtering based on a timestamp, custom matches, and can optionally follow pagination
    /// to retrieve all available indicators.
    ///
    /// # Parameters
    ///
    /// - `collection_id`: An optional reference to a string representing the collection ID
    ///   from which to retrieve indicators. If `None`, the first available collection ID is used.
    ///
    /// - `limit`: An optional usize value representing the maximum number of indicators to
    ///   retrieve in a single request. Defaults to 1000 if `None`.
    ///
    /// - `private`: A boolean flag indicating whether to use the private API root (`true`)
    ///   or the public API root (`false`).
    ///
    /// - `added_after`: An optional reference to a string representing a timestamp. If provided,
    ///   only indicators added after this timestamp will be retrieved.
    ///
    /// - `matches`: A reference to an optional `HashMap` with filter criteria in the form
    ///   of key-value pairs. The keys and values are references to strings.
    ///
    /// - `follow_pages`: A boolean flag indicating whether to follow pagination links to retrieve
    ///   additional indicators beyond the initial request (`true`), or to only retrieve the indicators
    ///   from the initial request (`false`).
    ///
    /// # Returns
    ///
    /// Returns a `Result<Vec<CCIndicator>>` which is either:
    /// - `Ok(Vec<CCIndicator>)` containing the list of retrieved indicators.
    /// - `Err(Box<TaxiiError>)` indicating an error occurred during the retrieval process.
    ///
    /// # Examples
    ///
    /// ```
    /// mut matches = std::Collections::HashMap::new();
    /// matches.insert("type", "indicator");
    /// let agent = CCTaxiiClient::new("my_username", "my_api_key");
    /// let indicators_result = agent.get_cc_indicators(
    ///     Some("collection_id"),
    ///     Some(500),
    ///     true,
    ///     Some("2024-01-01T00:00:00Z"),
    ///     &Some(matches),
    ///     true
    /// );
    ///
    /// match indicators_result {
    ///     Ok(indicators) => {
    ///         // Process the list of indicators
    ///     }
    ///     Err(error) => {
    ///         // Handle the error
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// This method can return various error types encapsulated within `TaxiiError`, such as:
    /// - `TaxiiCollectionError` if no collection is available or specified collection ID is invalid.
    /// - `JsonDeserializationError` if there is an error in parsing the response from the server.
    /// - Other errors related to network connectivity or server responses.
    pub fn get_cc_indicators(
        &self,
        collection_id: Option<&str>,
        limit: Option<usize>,
        private: bool,
        added_after: Option<&str>,
        matches: &Option<HashMap<&str, &str>>,
        follow_pages: bool,
    ) -> Result<Vec<CCIndicator>> {
        let root = if private { &self.account } else { "api" };
        let collection = match collection_id {
            Some(id) => id.to_string(),
            None => self
                .get_collections(root)?
                .get(0)
                .ok_or_else(|| {
                    Box::new(TaxiiCollectionError("No collections available".to_string()))
                })?
                .to_string(),
        };
        let limit = limit.unwrap_or(1000);
        let mut url = format!("{root}/collections/{collection}/objects/?limit={limit}");
        if let Some(timestamp) = added_after {
            url += &format!("&added_after={timestamp}");
        }
        let match_query = matches.as_ref().map_or(String::new(), |match_filters| {
            match_filters
                .iter()
                .fold(String::new(), |acc, (k, v)| format!("{acc}&match[{k}]={v}"))
        });
        url += &match_query;
        let mut all_indicators: Vec<CCIndicator> = Vec::new();
        let mut more = true;
        while more {
            let response = self.request(&url)?;
            let envelope: CCEnvelope = response
                .into_json()
                .map_err(|e| JsonDeserializationError(e.to_string()))?;
            all_indicators.extend(envelope.objects);
            more = follow_pages && envelope.more.unwrap_or(false);
            if let Some(next_url) = envelope.next {
                url += &format!("&next={next_url}");
            } else {
                break;
            }
        }
        Ok(all_indicators)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv;
    use std::env;

    #[test]
    fn get_discovery_test() {
        dotenv::dotenv().ok();
        let username = env::var("TAXII_USERNAME").expect("You've not set the TAXII_USERNAME");
        let api_key = env::var("TAXII_API_KEY").expect("You've not set the TAXII_API_KEY");
        let agent = CCTaxiiClient::new(&username, &api_key);
        let discovery = agent.get_discovery().expect("Failed to get discovery");

        assert_eq!(discovery.api_roots, ["/api/"], "API roots are incorrect");
        assert_eq!(
            discovery.contact, "it.support@cloudcover.net",
            "Contact email is incorrect"
        );
        assert_eq!(discovery.default, "/api/", "Default is incorrect");
        assert_eq!(discovery.description, "This API ROOT contains TAXII 2.1 REST API endpoints that serve CloudCover STIX 2.1 data", "Description is incorrect");
        assert_eq!(
            discovery.title, "CloudCover TAXII Server",
            "Title is incorrect"
        );
    }

    #[test]
    fn get_collections_test() {
        dotenv::dotenv().ok();
        let username = env::var("TAXII_USERNAME").expect("You've not set the TAXII_USERNAME");
        let api_key = env::var("TAXII_API_KEY").expect("You've not set the TAXII_API_KEY");
        let agent = CCTaxiiClient::new(&username, &api_key);
        let collections = agent
            .get_collections("api")
            .expect("Failed to get collections");
        assert_eq!(collections.len(), 1);
    }

    #[test]
    fn get_indicators_test() {
        dotenv::dotenv().ok();
        let username = env::var("TAXII_USERNAME").expect("You've not set the TAXII_USERNAME");
        let api_key = env::var("TAXII_API_KEY").expect("You've not set the TAXII_API_KEY");
        let agent = CCTaxiiClient::new(&username, &api_key);
        let indicators = agent
            .get_cc_indicators(None, Some(5), false, None, &None, false)
            .expect("Failed to get objects");
        assert_eq!(indicators.len(), 5);
    }
}
