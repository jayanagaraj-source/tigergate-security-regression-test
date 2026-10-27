# Naming module for the LOC fixture.
// Terraform also accepts C++-style line comments.

/*
  Block comment spanning
  three lines.
*/
terraform {
  required_version = ">= 1.5.0"
}

variable "prefix" {
  type    = string
  default = "regression" # a trailing comment keeps the line as code
}

resource "random_id" "suffix" {
  byte_length = 4
  keepers = {
    prefix = var.prefix
  }
}
