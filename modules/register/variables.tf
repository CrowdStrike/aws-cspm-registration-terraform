# Set prefix for all created AWS resource names
variable "resource_name" {
  default = "crowdstrike-horizon"
  type = string
}

# Set CrowdStrike Falcon API Credentials
variable "falcon_client_id" {
  type = string
  sensitive = true
}
variable "falcon_secret" {
  type = string
  sensitive = true
}
variable "crowdstrike_cloud" {
  type = string
}

# Set detection preferences
variable "enable_ioa" {
  type = bool
}