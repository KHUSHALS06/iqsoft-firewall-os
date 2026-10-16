use crate::{
    models::geoip::{
        normalize_country_code, normalize_direction, parse_zone_list, validate_comment,
        validate_source, GeoipDataset, GeoipImportRequest, GeoipImportResult, GeoipPolicy,
    },
    repository::geoip_repository::GeoipRepository,
};
use sqlx::SqlitePool;

pub struct GeoipService;

impl GeoipService {
    // ---------- policies (which countries to block, and in which direction) ----------

    pub async fn list_policies(pool: &SqlitePool) -> Result<Vec<GeoipPolicy>, String> {
        GeoipRepository::list_policies(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_policy(pool: &SqlitePool, policy: GeoipPolicy) -> Result<(), String> {
        let policy = Self::clean_policy(policy)?;

        let existing = GeoipRepository::get_policy_by_country(pool, &policy.country_code)
            .await
            .map_err(|e| e.to_string())?;

        if existing.is_some() {
            return Err(format!(
                "A Geo-IP policy for {} already exists",
                policy.country_code
            ));
        }

        GeoipRepository::add_policy(pool, policy)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub async fn update_policy(
        pool: &SqlitePool,
        id: i64,
        policy: GeoipPolicy,
    ) -> Result<(), String> {
        let policy = Self::clean_policy(policy)?;

        let existing = GeoipRepository::get_policy_by_country(pool, &policy.country_code)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(other) = existing {
            if other.id != Some(id) {
                return Err(format!(
                    "A Geo-IP policy for {} already exists",
                    policy.country_code
                ));
            }
        }

        let changed = GeoipRepository::update_policy(pool, id, policy)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Geo-IP policy {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_policy(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = GeoipRepository::delete_policy(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Geo-IP policy {} does not exist", id));
        }

        Ok(())
    }

    // ---------- datasets (the list of IP networks that belong to a country) ----------

    pub async fn list_datasets(pool: &SqlitePool) -> Result<Vec<GeoipDataset>, String> {
        GeoipRepository::list_datasets(pool)
            .await
            .map_err(|e| e.to_string())
    }

    /// Replaces the stored network list for one country with the pasted text.
    /// Importing again for the same country throws the old list away first.
    pub async fn import_dataset(
        pool: &SqlitePool,
        country_code: &str,
        request: GeoipImportRequest,
    ) -> Result<GeoipImportResult, String> {
        let code = normalize_country_code(country_code)
            .ok_or("Country code must be two letters, for example CN")?;

        validate_source(&request.source)?;

        let source = request
            .source
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let zone = parse_zone_list(&request.data)?;

        GeoipRepository::replace_dataset(pool, &code, source.as_deref(), &zone)
            .await
            .map_err(|e| e.to_string())?;

        Ok(GeoipImportResult {
            country_code: code,
            ipv4_imported: zone.ipv4.len(),
            ipv6_imported: zone.ipv6.len(),
            skipped: zone.skipped,
        })
    }

    pub async fn delete_dataset(pool: &SqlitePool, country_code: &str) -> Result<(), String> {
        let code = normalize_country_code(country_code)
            .ok_or("Country code must be two letters, for example CN")?;

        let changed = GeoipRepository::delete_dataset(pool, &code)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("No network list is stored for {}", code));
        }

        Ok(())
    }

    // ---------- helpers ----------

    fn clean_policy(mut policy: GeoipPolicy) -> Result<GeoipPolicy, String> {
        policy.country_code = normalize_country_code(&policy.country_code)
            .ok_or("Country code must be two letters, for example CN")?;

        policy.direction = normalize_direction(&policy.direction)
            .ok_or("Direction must be 'inbound', 'outbound' or 'both'")?
            .to_string();

        policy.comment = policy
            .comment
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());

        validate_comment(&policy.comment)?;

        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::geoip_schema::create_geoip_tables;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_geoip_tables(&pool).await.unwrap();
        pool
    }

    fn policy(code: &str, direction: &str) -> GeoipPolicy {
        GeoipPolicy {
            id: None,
            country_code: code.into(),
            direction: direction.into(),
            enabled: true,
            comment: None,
        }
    }

    fn import(data: &str) -> GeoipImportRequest {
        GeoipImportRequest {
            data: data.into(),
            source: Some("test list".into()),
        }
    }

    #[tokio::test]
    async fn policy_is_cleaned_before_it_is_saved() {
        let pool = memory_pool().await;

        let mut p = policy(" cn ", "BOTH");
        p.comment = Some("  scans  ".into());
        GeoipService::add_policy(&pool, p).await.unwrap();

        let saved = GeoipService::list_policies(&pool).await.unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].country_code, "CN");
        assert_eq!(saved[0].direction, "both");
        assert_eq!(saved[0].comment.as_deref(), Some("scans"));
    }

    #[tokio::test]
    async fn bad_policies_are_refused() {
        let pool = memory_pool().await;

        assert!(GeoipService::add_policy(&pool, policy("CHN", "inbound")).await.is_err());
        assert!(GeoipService::add_policy(&pool, policy("CN", "sideways")).await.is_err());

        let mut long = policy("CN", "inbound");
        long.comment = Some("x".repeat(500));
        assert!(GeoipService::add_policy(&pool, long).await.is_err());
    }

    #[tokio::test]
    async fn one_policy_per_country_even_through_update() {
        let pool = memory_pool().await;

        GeoipService::add_policy(&pool, policy("CN", "inbound")).await.unwrap();
        assert!(GeoipService::add_policy(&pool, policy("cn", "both")).await.is_err());

        GeoipService::add_policy(&pool, policy("RU", "inbound")).await.unwrap();

        let all = GeoipService::list_policies(&pool).await.unwrap();
        let ru_id = all.iter().find(|p| p.country_code == "RU").unwrap().id.unwrap();

        // Changing RU into CN would collide with the existing CN policy.
        assert!(GeoipService::update_policy(&pool, ru_id, policy("CN", "inbound")).await.is_err());

        // Saving RU as itself is fine.
        GeoipService::update_policy(&pool, ru_id, policy("RU", "both")).await.unwrap();

        assert!(GeoipService::update_policy(&pool, 9999, policy("KP", "inbound")).await.is_err());
        assert!(GeoipService::delete_policy(&pool, 9999).await.is_err());
        GeoipService::delete_policy(&pool, ru_id).await.unwrap();
    }

    #[tokio::test]
    async fn import_counts_and_replaces_the_old_list() {
        let pool = memory_pool().await;

        let result = GeoipService::import_dataset(
            &pool,
            "cn",
            import("1.0.1.0/24\n1.0.2.0/24\n2001:250::/32\n10.0.0.0/8\n"),
        )
        .await
        .unwrap();

        assert_eq!(result.country_code, "CN");
        assert_eq!(result.ipv4_imported, 2);
        assert_eq!(result.ipv6_imported, 1);
        assert_eq!(result.skipped, 1);

        GeoipService::import_dataset(&pool, "CN", import("1.0.9.0/24\n"))
            .await
            .unwrap();

        let datasets = GeoipService::list_datasets(&pool).await.unwrap();
        assert_eq!(datasets.len(), 1);
        assert_eq!(datasets[0].ipv4_count, 1);
        assert_eq!(datasets[0].ipv6_count, 0);
    }

    #[tokio::test]
    async fn bad_imports_are_refused() {
        let pool = memory_pool().await;

        assert!(GeoipService::import_dataset(&pool, "CHN", import("1.0.1.0/24\n")).await.is_err());
        assert!(GeoipService::import_dataset(&pool, "CN", import("rubbish\n")).await.is_err());
        assert!(GeoipService::import_dataset(&pool, "CN", import("")).await.is_err());

        let mut bad_source = import("1.0.1.0/24\n");
        bad_source.source = Some("bad\u{0007}".into());
        assert!(GeoipService::import_dataset(&pool, "CN", bad_source).await.is_err());

        assert!(GeoipService::list_datasets(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_a_dataset_that_is_not_there_is_an_error() {
        let pool = memory_pool().await;

        assert!(GeoipService::delete_dataset(&pool, "CN").await.is_err());

        GeoipService::import_dataset(&pool, "CN", import("1.0.1.0/24\n"))
            .await
            .unwrap();
        GeoipService::delete_dataset(&pool, "cn").await.unwrap();
        assert!(GeoipService::list_datasets(&pool).await.unwrap().is_empty());
    }
}
