variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "s3_bucket_reports" {
  type    = string
  default = "cyberscan-ai-reports-REPLACE-CON-SUFIJO-UNICO"
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro" # ajustar segun carga real, no valido para "millones de usuarios"
}

variable "db_password" {
  type      = string
  sensitive = true
  # Sin default a proposito: se debe pasar con TF_VAR_db_password o -var
}

variable "backend_image" {
  type        = string
  description = "Imagen de ECR/GHCR del backend, ej: ghcr.io/tu-org/cyberscan-backend:latest"
}

variable "backend_desired_count" {
  type    = number
  default = 1
}
