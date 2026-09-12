terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  required_version = ">= 1.5.0"

  # State has to survive the ephemeral runner between deploys, same
  # reasoning as huram-abi's other modules - bucket/prefix come from
  # -backend-config at `terraform init` time (see
  # .github/actions/deploy-token-minter), which also supports swapping
  # this for a local backend backed by a cache via an override file.
  backend "gcs" {}
}

# Authenticates via whatever Application Default Credentials the calling
# workflow already established - Workload Identity Federation,
# impersonating huram-abi's `terraform` service account (terraform/wif in
# that repo) - no JSON key here.
provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "iamcredentials" {
  project            = var.project_id
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  project            = var.project_id
  service            = "iam.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloudfunctions" {
  project            = var.project_id
  service            = "cloudfunctions.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloudbuild" {
  project            = var.project_id
  service            = "cloudbuild.googleapis.com"
  disable_on_destroy = false
}

# Gen 2 functions run on Cloud Run and build into Artifact Registry.
resource "google_project_service" "run" {
  project            = var.project_id
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "artifactregistry" {
  project            = var.project_id
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

# --- The token-minter service account itself ---
#
# Deliberately granted NO project-level roles at all - not roles/editor,
# not roles/iam.serviceAccountTokenCreator project-wide, nothing. Its
# only IAM grants are the per-resource
# google_service_account_iam_member.minter_can_mint_for_tenant bindings
# below, one per tenant service account it's allowed to impersonate. That
# scoping is the entire point of this module: this identity can mint a
# short-lived token that acts as a specific tenant's service account, but
# it can never itself do anything that tenant's service account can do,
# and it can't touch any service account that hasn't been explicitly
# listed in var.tenants.
resource "google_service_account" "token_minter" {
  project      = var.project_id
  account_id   = var.minter_service_account_id
  display_name = "Multi-tenant token minter"
  description  = "Mints short-lived tokens on behalf of tenant service accounts. Holds roles/iam.serviceAccountTokenCreator on each tenant SA only - no project-wide roles."
}

# --- Tenant service accounts ---
#
# One dedicated caller identity per tenant cell. The account needs no
# project role merely to identify itself to Atman: Atman checks the signed
# email claim and exact audience. Its only required IAM relationship here
# is that token-minter may mint short-lived tokens for it.
resource "google_service_account" "tenant" {
  for_each = {
    for id, t in var.tenants : id => t
    if t.create_service_account
  }

  project      = var.project_id
  account_id   = "${var.tenant_service_account_prefix}${each.key}"
  display_name = "Tenant ${each.key} Atman caller"
  description  = "Short-lived caller identity for tenant ${each.key}'s Atman cell."
}

locals {
  # Resolve every tenant to a concrete service account resource, whether
  # this module created it above or the caller supplied an existing one.
  tenant_sa_email = {
    for id, t in var.tenants :
    id => t.create_service_account ? google_service_account.tenant[id].email : t.service_account_email
  }

  tenant_sa_resource_name = {
    for id, t in var.tenants :
    id => t.create_service_account ? google_service_account.tenant[id].name : "projects/${var.project_id}/serviceAccounts/${t.service_account_email}"
  }

  # The HTTP caller supplies only tenant_id and its API key. Target identity
  # and audience come from this server-side policy, so a caller cannot turn
  # the minter into an arbitrary token endpoint.
  tenants_json = jsonencode({
    for id, t in var.tenants : id => {
      service_account_email = local.tenant_sa_email[id]
      audience             = t.audience
      api_key_sha256       = sha256(t.api_key)
    }
  })
}

# The one grant that makes token-minting work: for every tenant, allow
# the token-minter service account to generate access/ID tokens that
# identify as that tenant's service account. Scoped to exactly this one
# resource per tenant - never project-wide - so removing a tenant from
# var.tenants immediately and completely revokes the minter's ability to
# impersonate them, with no other cleanup required.
resource "google_service_account_iam_member" "minter_can_mint_for_tenant" {
  for_each = local.tenant_sa_resource_name

  service_account_id = each.value
  role                = "roles/iam.serviceAccountTokenCreator"
  member              = "serviceAccount:${google_service_account.token_minter.email}"

  depends_on = [google_project_service.iam]
}

# Lets whatever's listed in var.minter_impersonators (typically huram-abi's
# `terraform` WIF service account) impersonate the token-minter service
# account directly - the delegate hop .github/actions/mint-token and
# cmd/mint-token use to mint a tenant token locally in CI without going
# through the deployed HTTP endpoint. Still per-resource (on the minter
# SA only), not project-wide.
resource "google_service_account_iam_member" "impersonate_minter" {
  for_each = toset(var.minter_impersonators)

  service_account_id = google_service_account.token_minter.name
  role                = "roles/iam.serviceAccountTokenCreator"
  member              = each.value
}

# --- The deployed Cloud Function (gen2 - see runtime variable) ---
#
# Dedicated bucket for this function's source archives, mirroring
# huram-abi's other Go Cloud Function modules.
resource "google_storage_bucket" "function_source" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.function_name}-source"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
}

data "archive_file" "source" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/.build/function-source.zip"
  excludes    = [".git"]
}

resource "google_storage_bucket_object" "source" {
  name   = "${var.function_name}/${data.archive_file.source.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.source.output_path
}

resource "google_cloudfunctions2_function" "token_minter" {
  project  = var.project_id
  location = var.region
  name     = var.function_name

  build_config {
    runtime     = var.runtime
    entry_point = "Main"

    # gospace-minimal's GCF entry point lives in function/, not the
    # checkout root - see its cmd/, internal/ layout, same convention
    # every other module deployed through that shell uses.
    environment_variables = {
      GOOGLE_FUNCTION_SOURCE = "function"
    }

    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.source.name
      }
    }
  }

  service_config {
    available_memory   = var.available_memory
    available_cpu      = var.available_cpu
    timeout_seconds    = 30
    min_instance_count = var.min_instances
    max_instance_count = var.max_instances
    ingress_settings   = "ALLOW_ALL"

    # This is the whole reason the function's identity matters: running
    # it as the token-minter service account (rather than the project's
    # default compute SA) is what makes internal/mint's calls to the IAM
    # Credentials API work without any credential ever being handed to
    # this function beyond its own ambient identity.
    service_account_email = google_service_account.token_minter.email

    environment_variables = {
      TENANTS_JSON = local.tenants_json
    }
  }

  depends_on = [
    google_project_service.cloudfunctions,
    google_project_service.cloudbuild,
    google_project_service.run,
    google_project_service.artifactregistry,
    google_project_service.iamcredentials,
  ]
}

# The function is reachable by anyone (ingress ALLOW_ALL, invoker
# allUsers) - same posture as huram-abi's logma-serverless - because its
# callers are tenants' own services, not authenticated GCP principals.
# The real gate is application-level: internal/tenant.Registry.Authenticate
# rejects any request without a matching tenant_id + X-API-Key. Getting
# past that only ever yields a token for that one tenant's own service
# account - never anything broader - so opening invocation up here doesn't
# widen what an attacker could reach even without it.
resource "google_cloud_run_service_iam_member" "invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloudfunctions2_function.token_minter.service_config[0].service

  role   = "roles/run.invoker"
  member = "allUsers"
}
