use crate::Result;
use serde::Deserialize;
use std::collections::HashMap;
use ureq::Response;

/// `TaxiiClient` defines the interface for interacting with a TAXII server.
///
/// This trait outlines the fundamental operations that a TAXII client should support, such as
/// making requests to the server and retrieving various types of data related to cyber threat
/// intelligence, like collections and indicators.
///
/// Implementors of this trait can provide concrete mechanisms to interact with specific TAXII
/// server implementations, adhering to the TAXII 2.1 specifications.
///
/// # Examples
///
/// Implementing the `TaxiiClient` trait for a custom client:
///
/// ```
/// struct MyTaxiiClient {
///     // Custom fields for client implementation
/// }
///
/// impl TaxiiClient for MyTaxiiClient {
///     // Implementations of trait methods
/// }
/// ```
pub trait TaxiiClient {
    /// Creates a new instance of the `TaxiiClient`.
    ///
    /// This function initializes a new `TaxiiClient` with the specified username and API key.
    /// The username and API key are used to authenticate requests to the TAXII server.
    ///
    /// # Parameters
    ///
    /// - `username`: The username for TAXII server authentication.
    /// - `api_key`: The API key or password for TAXII server authentication.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `TaxiiClient`.
    ///
    /// # Examples
    ///
    /// ```
    /// let agent = TaxiiClient::new("my_username", "my_api_key");
    /// ```
    fn new(username: &str, api_key: &str) -> Self
    where
        Self: Sized;

    /// Sends a GET request to the specified URL.
    ///
    /// This method constructs and sends an HTTP GET request to the given URL. It includes
    /// common headers set during the construction of the `TaxiiClient` instance. The method
    /// handles HTTP errors and deserializes the response into a `Response`.
    ///
    /// # Parameters
    ///
    /// - `url`: The URL path to append to the base URL of the TAXII server.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Response)` if the request is successful.
    /// Returns `Err(TaxiiError)` if the request fails or the server responds with an error.
    ///
    /// # Errors
    ///
    /// - Returns `TaxiiAuthorizationError` if the response status code is 401 (Unauthorized).
    /// - Returns `TaxiiNotFoundError` if the response status code is 404 (Not Found).
    /// - Returns `TaxiiGenericError` for other non-successful status codes.
    /// - Returns `TaxiiConnectionError` if the request fails to execute.
    ///
    /// # Examples
    ///
    /// ```
    /// let agent = TaxiiClient::new("my_username", "my_api_key");
    /// let response = agent.request("taxii2/");
    /// ```
    fn request(&self, url: &str) -> Result<Response>;

    /// Retrieves discovery information from the TAXII server.
    ///
    /// This method sends a request to the TAXII server's discovery endpoint and attempts to
    /// deserialize the response into a `Discovery` object. The discovery endpoint provides
    /// information about the TAXII server's API roots and capabilities.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Discovery)` if the discovery information is successfully retrieved and deserialized.
    /// Returns `Err(TaxiiError)` if the request fails or if the response cannot be deserialized.
    ///
    /// # Errors
    ///
    /// - Returns an error if the request to the discovery endpoint fails.
    /// - Returns a deserialization error if the response cannot be parsed into a `Discovery` object.
    ///
    /// # Examples
    ///
    /// ```
    /// let agent = TaxiiClient::new("my_username", "my_api_key");
    /// let discovery = agent.get_discovery();
    /// ```
    fn get_discovery(&self) -> Result<Discovery>;

    /// Retrieves a list of collection IDs for the specified API root from the TAXII server.
    ///
    /// This method requests the collections available at a specific API root of the TAXII server.
    /// It deserializes the response to extract the collection IDs. The API root is a segment
    /// of the TAXII server's URL that specifies a particular set of collections.
    ///
    /// # Parameters
    ///
    /// - `root`: The API root for which to retrieve collections.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<String>)` with a list of collection IDs if the request is successful.
    /// Returns `Err(TaxiiError)` if the request fails or if the response cannot be deserialized.
    ///
    /// # Errors
    ///
    /// - Returns an error if the request to retrieve collections fails.
    /// - Returns a deserialization error if the response cannot be parsed into a list of collection IDs.
    ///
    /// # Examples
    ///
    /// ```
    /// let agent = TaxiiClient::new("my_username", "my_api_key");
    /// let collections = agent.get_collections(Some("api"));
    /// ```
    fn get_collections(&self, root: Option<&str>) -> Result<Vec<String>>;
}

/// Represents a TAXII Envelope, used for wrapping TAXII objects.
///
/// The Envelope is a container for objects in TAXII, potentially including additional
/// pagination information.
///
/// # Fields
///
/// - `more`: Indicates if more data is available (pagination).
/// - `next`: The URL for the next set of data, if `more` is `true`.
/// - `objects`: A collection of TAXII objects, each represented as a `HashMap<String, String>`.
#[derive(Deserialize, Debug)]
pub struct Envelope {
    pub more: Option<bool>,
    pub next: Option<String>,
    pub objects: Option<Vec<HashMap<String, String>>>,
}

/// Contains discovery information for a TAXII server.
///
/// This struct provides details about the TAXII server's capabilities, contact information,
/// and available API roots.
///
/// # Fields
///
/// - `api_roots`: A list of URIs of the API roots provided by this TAXII server.
/// - `contact`: Contact information for this TAXII server.
/// - `default`: The default API root for this server.
/// - `description`: A human-readable description of this server.
/// - `title`: A human-readable title for this server.
#[derive(Deserialize, Debug)]
pub struct Discovery {
    pub api_roots: Vec<String>,
    pub contact: String,
    pub default: String,
    pub description: String,
    pub title: String,
}

/// Represents a single collection within a TAXII server.
///
/// A collection is a set of cyber threat intelligence expressed in STIX 2.0.
///
/// # Fields
///
/// - `can_read`: Indicates if the collection supports read operations.
/// - `can_write`: Indicates if the collection supports write operations.
/// - `id`: The unique identifier of the collection.
/// - `media_types`: The media types supported by the collection.
/// - `name`: The name of the collection.
/// - `title`: A human-readable title for the collection.
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Collection {
    pub can_read: bool,
    pub can_write: bool,
    pub id: String,
    pub media_types: [String; 1],
    pub name: String,
    pub title: String,
}

/// A container for multiple `Collection` objects.
///
/// This struct is typically used to group multiple collections returned from a TAXII server.
///
/// # Fields
///
/// - `collections`: A vector of `Collection` structs.
#[derive(Deserialize, Debug)]
pub struct Collections {
    pub collections: Vec<Collection>,
}
