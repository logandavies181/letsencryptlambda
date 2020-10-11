variable "bucket_name" {
  type = string
}

variable "domain" {
  type = string
}

variable "ca_dir_url" {
  type = string
  default = "https://acme-staging-v02.api.letsencrypt.org/directory"
}
