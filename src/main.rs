use log::{debug, error};
use log::info;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::AccessToken;
use oauth2::ClientId;
use oauth2::TokenResponse;
use serde_json::json;
use tokio;

fn true_bool() -> bool {
    true
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct Config {
    keycloak_url: String,
    auth_realm: String,
    auth_username: String,
    auth_password: String,
    auth_client_id: String,
    realm_base: String,
    realm_extended: String
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
struct User {
    id: String,
    username: String
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging log level to debug
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let input = std::fs::read_to_string("config.json")?;
    let config: Config = serde_json::from_str(&input)?;

    let client = KeycloakClient::new(config.keycloak_url,
        config.auth_realm,
        config.realm_base,
        config.realm_extended,
 config.auth_username,
        config.auth_password,
    ).await?;

    let base_users = client.get_all_base_users().await?;
    let extended_users = client.get_all_extended_users().await?;
    // Get the users that are in the base realm and in the extended realm as tuples
    for (base_user, extended_user) in base_users.iter().filter_map(|base_user| {
        extended_users.iter().find_map(|extended_user| {
            if base_user.username == extended_user.username {
                Some((base_user, extended_user))
            } else {
                None
            }
        })
    }) {
        client.link_accounts(base_user, extended_user).await?;
    };

    Ok(())
}

struct KeycloakClient {
    base_url: String,
    realm_base: String,
    realm_extended: String,
    token: AccessToken,
    reqwest_client: reqwest::Client,
}

impl KeycloakClient {
    async fn new(
        base_url: String,
        auth_realm: String,
        realm_base: String,
        realm_extended: String,
        user: String,
        password: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let oauth_client = BasicClient::new(
            ClientId::new("admin-cli".to_string()),
            None,
            oauth2::AuthUrl::new(format!(
                "{}/realms/{}/protocol/openid-connect/auth",
                base_url, auth_realm
            ))
                .unwrap(),
            Some(
                oauth2::TokenUrl::new(format!(
                    "{}/realms/master/protocol/openid-connect/token",
                    base_url
                ))
                    .unwrap(),
            ),
        );
        // Get a Token with Password Grant
        let token = oauth_client
            .exchange_password(
                &oauth2::ResourceOwnerUsername::new(user.clone()),
                &oauth2::ResourceOwnerPassword::new(password.clone()),
            )
            .request_async(async_http_client)
            .await?
            .access_token()
            .clone();

        Ok(KeycloakClient {
            base_url,
            realm_base,
            realm_extended,
            token,
            reqwest_client: reqwest::Client::new(),
        })
    }

    async fn get_all_base_users(&self) -> Result<Vec<User>, Box<dyn std::error::Error>> {
        // Create a request
        Ok(self
            .reqwest_client
            .get(format!(
                "{}/admin/realms/{}/users",
                self.base_url, self.realm_base
            ))
            .bearer_auth(self.token.secret())
            .send()
            .await?
            .json::<Vec<User>>()
            .await?)
    }

    async fn get_all_extended_users(&self) -> Result<Vec<User>, Box<dyn std::error::Error>> {
        // Create a request
        Ok(self
            .reqwest_client
            .get(format!(
                "{}/admin/realms/{}/users",
                self.base_url, self.realm_extended
            ))
            .bearer_auth(self.token.secret())
            .send()
            .await?
            .json::<Vec<User>>()
            .await?)
    }

    async fn link_accounts(&self, base_user: &User, extended_user: &User) -> Result<(), Box<dyn std::error::Error>> {
        // Create a request
        let text = self
            .reqwest_client
            .post(format!(
                "{}/admin/realms/{}/users/{}/federated-identity/keycloak-oidc",
                self.base_url, self.realm_extended, extended_user.id,
            ))
            .bearer_auth(self.token.secret())
            .json(&json!({
                "userId": base_user.id,
                "userName": base_user.username
            }))
            .send()
            .await?
            .text()
            .await?;
        debug!("{}", text);
        Ok(())
    }
}
