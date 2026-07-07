terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Networking minimo: usa el VPC default para simplificar el arranque.
# En produccion real, sustituye por un modulo VPC dedicado (subnets privadas/publicas, NAT).
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# --- S3 para reportes PDF ---
resource "aws_s3_bucket" "reports" {
  bucket = var.s3_bucket_reports
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- RDS Postgres (instancia unica, sin Multi-AZ - ajustar segun SLA requerido) ---
resource "aws_db_subnet_group" "this" {
  name       = "cyberscan-db-subnets"
  subnet_ids = data.aws_subnets.default.ids
}

resource "aws_security_group" "db" {
  name   = "cyberscan-db-sg"
  vpc_id = data.aws_vpc.default.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "postgres" {
  identifier             = "cyberscan-postgres"
  engine                 = "postgres"
  engine_version         = "16.4"
  instance_class         = var.db_instance_class
  allocated_storage      = 20
  db_name                = "cyberscan"
  username               = "cyberscan"
  password               = var.db_password # pasar via -var o TF_VAR_db_password, nunca hardcodear
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_encrypted      = true
}

# --- ECS Fargate para el backend ---
resource "aws_ecs_cluster" "this" {
  name = "cyberscan-cluster"
}

resource "aws_security_group" "ecs_tasks" {
  name   = "cyberscan-ecs-sg"
  vpc_id = data.aws_vpc.default.id

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # produccion: restringir al ALB security group, no abierto a internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_task_definition" "backend" {
  family                   = "cyberscan-backend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name  = "backend"
    image = var.backend_image
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    environment = [
      { name = "ENVIRONMENT", value = "production" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/cyberscan-backend"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "backend"
      }
    }
  }])
}

resource "aws_cloudwatch_log_group" "backend" {
  name              = "/ecs/cyberscan-backend"
  retention_in_days = 30
}

resource "aws_iam_role" "ecs_execution" {
  name = "cyberscan-ecs-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_service" "backend" {
  name            = "cyberscan-backend"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = var.backend_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = true
  }
}
