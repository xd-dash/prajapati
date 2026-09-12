output "function_url" {
  description = "HTTPS trigger URL for the deployed token-minter function"
  value       = google_cloudfunctions2_function.token_minter.service_config[0].uri
}

output "token_minter_service_account" {
  description = "Email of the token-minter service account - pass as minter-service-account to .github/actions/mint-token, or as the resolved value of GCLOUD_TERRAFORM_SA's delegate target"
  value       = google_service_account.token_minter.email
}

output "tenant_service_accounts" {
  description = "Map of tenant_id -> the service account email actually in effect for that tenant (whether created by this module or supplied via service_account_email)"
  value       = local.tenant_sa_email
}
