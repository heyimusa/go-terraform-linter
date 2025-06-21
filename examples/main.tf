# Example Terraform configuration with security issues for testing

# 🚨 CRITICAL: Hardcoded secret
resource "aws_db_instance" "example" {
  identifier = "example-db"
  engine     = "mysql"
  password   = "weak123"  # This should trigger WEAK_PASSWORD and EXPOSED_SECRETS rules
  
  tags = {
    Name = "example-database"
  }
}

# 🚨 HIGH: Public S3 bucket
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"  # This should trigger PUBLIC_ACCESS rule
}

# 🚨 HIGH: Unencrypted EBS volume
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-west-2a"
  size              = 100
  # Missing encrypted = true - should trigger UNENCRYPTED_STORAGE rule
}

# 🚨 HIGH: Security group allowing access from anywhere
resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "Security group with open access"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # This should trigger PUBLIC_ACCESS rule
  }
  
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# 🚨 MEDIUM: Deprecated resource
resource "aws_instance" "legacy" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  # This should trigger DEPRECATED_RESOURCES rule
}

# 🚨 MEDIUM: Weak TLS configuration
resource "aws_cloudfront_distribution" "weak_tls" {
  enabled = true
  
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version      = "TLSv1"  # This should trigger WEAK_CRYPTO rule
  }
}

# 🚨 HIGH: IAM role with excessive permissions
resource "aws_iam_role" "admin_role" {
  name = "admin-role"
  
  inline_policy {
    name = "admin-policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = "*"  # This should trigger EXCESSIVE_PERMISSIONS rule
          Resource = "*"
        }
      ]
    })
  }
}

# 🚨 HIGH: RDS cluster without backup
resource "aws_rds_cluster" "no_backup" {
  cluster_identifier = "no-backup-cluster"
  engine             = "aurora-mysql"
  backup_retention_period = 0  # This should trigger MISSING_BACKUP rule
}

# ✅ GOOD: Properly configured resource
resource "aws_security_group" "secure_sg" {
  name        = "secure-security-group"
  description = "Security group with restricted access"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  
  tags = {
    Name = "secure-sg"
    Environment = "production"
  }
} 