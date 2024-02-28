variable "profile" {
    type = string
}

variable "intermediate_role" {
    type = string
}

variable "external_id" {
    type = string
}

variable "iam_role_arn" {
    type = string
}

variable "cs_eventbus_arn" {
    type = string
}

# Set detection preferences
variable "enable_ioa" {
  type = bool
}

variable "exclude_regions" {
  type = list(string)
  default = []
}

variable "use_existing_cloudtrail" {
    type = bool
    default = true
}

variable "organization" {
    type = bool
    default = true
}

variable "cs_bucket_name" {
    type = string
    default = ""
}