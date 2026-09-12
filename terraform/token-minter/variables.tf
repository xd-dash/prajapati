variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for the Cloud Function and its source bucket"
  type        = string
  default     = "us-central1"
}

variable "function_name" {
  description = "Cloud Function name for the deployed token-minter"
  type        = string
  default     = "token-minter"
}

variable "source_dir" {
  description = "Path to the checked-out dash-xd/gospace-minimal source to deploy, after its router action has pointed it at this repo's router package"
  type        = string
}

variable "minter_service_account_id" {
  description = "Account ID (local part of the email) for the token-minter service account"
  type        = string
  default     = "token-minter"
}

variable "tenant_service_account_prefix" {
  description = <<-EOT
    Prefix used to derive an account_id ("<prefix><tenant_id>") for tenant
    service accounts this module creates. GCP account_ids must be 6-30
    characters, lowercase letters/digits/hyphens - keep tenant_id short
    enough (and this prefix combined with it) to fit, or set
    create_service_account = false for that tenant and supply an existing
    service_account_email instead.
  EOT
  type        = string
  default     = "tenant-"
}

variable "tenants" {
  description = <<-EOT
    Map of tenant_id -> tenant config. tenant_id is whatever identifier
    callers pass as "tenant_id" when requesting a token - it never needs
    to be a real GCP resource name.

    For each entry:
      - service_account_email: existing service account this tenant's
        Cloud Function(s) run as. Required when create_service_account is
        false; ignored (and derived instead) when true.
      - create_service_account: have this module create a dedicated
        service account for this tenant instead of using an existing one.
        Defaults to true - the common case for a brand-new signup.
      - audience: exact HTTPS audience accepted by this tenant's Atman
        gateway. HTTP callers cannot override it.
      - api_key: shared secret this tenant's caller presents as the
        X-API-Key header to mint a token. Required, sensitive.

    The token-minter service account is granted
    roles/iam.serviceAccountTokenCreator on each tenant's service account
    ONLY (never project-wide) - see minter_can_mint_for_tenant in main.tf.
    That single per-resource grant is what lets this module stay a
    one-map-entry-per-tenant operation: onboarding or removing a tenant
    never requires touching any other tenant's identity or IAM state.
  EOT
  type = map(object({
    service_account_email  = optional(string, "")
    create_service_account = optional(bool, true)
    audience                = string
    api_key                  = string
  }))
  default   = {}
  sensitive = true

  validation {
    condition = alltrue([
      for t in values(var.tenants) : t.create_service_account || t.service_account_email != ""
    ])
    error_message = "Every tenant needs either create_service_account = true, or a non-empty service_account_email."
  }

  validation {
    condition = alltrue([
      for id in keys(var.tenants) : can(regex("^[A-Za-z0-9._-]{1,23}$", id))
    ])
    error_message = "Tenant IDs must use 1-23 ASCII letters, digits, dot, underscore, or hyphen so generated service-account IDs remain valid."
  }

  validation {
    condition = alltrue([
      for t in values(var.tenants) : can(regex("^https://[^/[:space:]]+", t.audience))
    ])
    error_message = "Every tenant audience must be an absolute HTTPS URL."
  }

  validation {
    condition = alltrue([
      for t in values(var.tenants) : length(t.api_key) >= 32
    ])
    error_message = "Every tenant api_key must contain at least 32 characters."
  }
}

variable "minter_impersonators" {
  description = <<-EOT
    IAM members (e.g. "serviceAccount:...", or a WIF
    "principalSet://...") allowed to impersonate the token-minter service
    account directly, granted roles/iam.serviceAccountTokenCreator on it
    (and only it - never on any tenant SA). Typically the huram-abi
    Terraform/WIF deploy identity, so .github/actions/mint-token and
    cmd/mint-token can mint a tenant token locally in CI by delegating
    through the minter, without going through the deployed HTTP endpoint.
  EOT
  type    = list(string)
  default = []
}

variable "min_instances" {
  description = "Minimum concurrent instances to keep warm. Defaults to 0 - token minting is bursty and has no standing-connection state, so there's no cost to scaling to zero between callers."
  type        = number
  default     = 0
}

variable "max_instances" {
  description = "Maximum concurrent instances for the deployed function"
  type        = number
  default     = 10
}

variable "available_memory" {
  description = "Cloud Functions gen2 memory allocation. This function does no CPU/memory-heavy work - it makes one outbound IAM Credentials API call per request - so the smallest tier is the default."
  type        = string
  default     = "128Mi"
}

variable "available_cpu" {
  description = "Cloud Functions gen2 CPU allocation, paired with available_memory."
  type        = string
  default     = "0.08"
}

variable "runtime" {
  description = <<-EOT
    Cloud Functions Go runtime identifier (e.g. "go126"). This project
    offers no Go runtime on gen1 at all (confirmed via `gcloud functions
    runtimes list --region=REGION`), hence gen2 here - and even on gen2,
    whichever version is current rotates on Google's decommission
    schedule. Re-run that command and pass the current value here if
    deploy fails with DEPLOYS_NOT_ALLOWED.
  EOT
  type        = string
  default     = "go126"
}
