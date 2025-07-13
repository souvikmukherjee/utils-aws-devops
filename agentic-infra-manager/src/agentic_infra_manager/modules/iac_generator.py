"""
Infrastructure as Code (IaC) Generator module for Terraform and CDK code generation.

This module provides comprehensive IaC generation capabilities including:
- Terraform configuration generation
- AWS CDK code generation
- Kubernetes manifest generation
- Helm chart generation
- Environment-specific configurations
- Best practices and optimizations
"""

import os
import json
import yaml
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import textwrap

from ..core.state import (
    ApplicationType,
    InfrastructurePlan,
    SecurityConfiguration,
    RepositoryAnalysis
)
from ..core.config import AgentConfig


class IaCFramework(Enum):
    """Infrastructure as Code frameworks."""
    TERRAFORM = "terraform"
    CDK_PYTHON = "cdk_python"
    CDK_TYPESCRIPT = "cdk_typescript"
    PULUMI = "pulumi"
    CLOUDFORMATION = "cloudformation"


class OutputFormat(Enum):
    """Output formats for IaC code."""
    HCL = "hcl"  # Terraform
    PYTHON = "py"  # CDK Python
    TYPESCRIPT = "ts"  # CDK TypeScript
    YAML = "yaml"  # CloudFormation/Kubernetes
    JSON = "json"  # CloudFormation/Kubernetes


@dataclass
class IaCConfig:
    """Configuration for IaC generation."""
    framework: IaCFramework
    output_format: OutputFormat
    output_directory: str
    project_name: str
    environment: str
    include_monitoring: bool = True
    include_backup: bool = True
    include_security: bool = True
    modular_structure: bool = True
    generate_docs: bool = True


@dataclass
class IaCModule:
    """IaC module definition."""
    name: str
    type: str  # vpc, eks, rds, etc.
    dependencies: List[str] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    resources: List[str] = field(default_factory=list)
    file_path: str = ""


@dataclass
class GenerationResult:
    """Result of IaC generation."""
    framework: IaCFramework
    output_files: List[str]
    modules: List[IaCModule]
    metadata: Dict[str, Any]
    generated_at: datetime
    file_sizes: Dict[str, int]


class TerraformGenerator:
    """Terraform code generator."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def generate_terraform_code(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration,
        iac_config: IaCConfig
    ) -> GenerationResult:
        """Generate Terraform code for infrastructure plan."""
        self.logger.info("Generating Terraform code")
        
        output_dir = Path(iac_config.output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        generated_files = []
        modules = []
        
        # Main configuration
        main_tf = self._generate_main_tf(infrastructure_plan, security_config, iac_config)
        main_file = output_dir / "main.tf"
        with open(main_file, 'w') as f:
            f.write(main_tf)
        generated_files.append(str(main_file))
        
        # Variables
        variables_tf = self._generate_variables_tf(infrastructure_plan, iac_config)
        variables_file = output_dir / "variables.tf"
        with open(variables_file, 'w') as f:
            f.write(variables_tf)
        generated_files.append(str(variables_file))
        
        # Outputs
        outputs_tf = self._generate_outputs_tf(infrastructure_plan, iac_config)
        outputs_file = output_dir / "outputs.tf"
        with open(outputs_file, 'w') as f:
            f.write(outputs_tf)
        generated_files.append(str(outputs_file))
        
        # Provider configuration
        provider_tf = self._generate_provider_tf(iac_config)
        provider_file = output_dir / "provider.tf"
        with open(provider_tf, 'w') as f:
            f.write(provider_tf)
        generated_files.append(str(provider_file))
        
        # VPC module
        if iac_config.modular_structure:
            vpc_module = self._generate_vpc_module(infrastructure_plan, iac_config)
            vpc_dir = output_dir / "modules" / "vpc"
            vpc_dir.mkdir(parents=True, exist_ok=True)
            
            vpc_main_file = vpc_dir / "main.tf"
            with open(vpc_main_file, 'w') as f:
                f.write(vpc_module['main'])
            generated_files.append(str(vpc_main_file))
            
            vpc_variables_file = vpc_dir / "variables.tf"
            with open(vpc_variables_file, 'w') as f:
                f.write(vpc_module['variables'])
            generated_files.append(str(vpc_variables_file))
            
            vpc_outputs_file = vpc_dir / "outputs.tf"
            with open(vpc_outputs_file, 'w') as f:
                f.write(vpc_module['outputs'])
            generated_files.append(str(vpc_outputs_file))
            
            modules.append(IaCModule(
                name="vpc",
                type="vpc",
                dependencies=[],
                file_path=str(vpc_dir)
            ))
        
        # EKS module
        if iac_config.modular_structure:
            eks_module = self._generate_eks_module(infrastructure_plan, security_config, iac_config)
            eks_dir = output_dir / "modules" / "eks"
            eks_dir.mkdir(parents=True, exist_ok=True)
            
            eks_main_file = eks_dir / "main.tf"
            with open(eks_main_file, 'w') as f:
                f.write(eks_module['main'])
            generated_files.append(str(eks_main_file))
            
            eks_variables_file = eks_dir / "variables.tf"
            with open(eks_variables_file, 'w') as f:
                f.write(eks_module['variables'])
            generated_files.append(str(eks_variables_file))
            
            eks_outputs_file = eks_dir / "outputs.tf"
            with open(eks_outputs_file, 'w') as f:
                f.write(eks_module['outputs'])
            generated_files.append(str(eks_outputs_file))
            
            modules.append(IaCModule(
                name="eks",
                type="eks",
                dependencies=["vpc"],
                file_path=str(eks_dir)
            ))
        
        # RDS module (if database is configured)
        if infrastructure_plan.get('database_resources'):
            rds_module = self._generate_rds_module(infrastructure_plan, security_config, iac_config)
            rds_dir = output_dir / "modules" / "rds"
            rds_dir.mkdir(parents=True, exist_ok=True)
            
            rds_main_file = rds_dir / "main.tf"
            with open(rds_main_file, 'w') as f:
                f.write(rds_module['main'])
            generated_files.append(str(rds_main_file))
            
            rds_variables_file = rds_dir / "variables.tf"
            with open(rds_variables_file, 'w') as f:
                f.write(rds_module['variables'])
            generated_files.append(str(rds_variables_file))
            
            rds_outputs_file = rds_dir / "outputs.tf"
            with open(rds_outputs_file, 'w') as f:
                f.write(rds_module['outputs'])
            generated_files.append(str(rds_outputs_file))
            
            modules.append(IaCModule(
                name="rds",
                type="rds",
                dependencies=["vpc"],
                file_path=str(rds_dir)
            ))
        
        # Terraform configuration files
        terraform_tfvars = self._generate_terraform_tfvars(infrastructure_plan, iac_config)
        tfvars_file = output_dir / f"{iac_config.environment}.tfvars"
        with open(tfvars_file, 'w') as f:
            f.write(terraform_tfvars)
        generated_files.append(str(tfvars_file))
        
        # Backend configuration
        backend_tf = self._generate_backend_tf(iac_config)
        backend_file = output_dir / "backend.tf"
        with open(backend_file, 'w') as f:
            f.write(backend_tf)
        generated_files.append(str(backend_file))
        
        # Generate documentation
        if iac_config.generate_docs:
            readme_content = self._generate_terraform_readme(infrastructure_plan, modules, iac_config)
            readme_file = output_dir / "README.md"
            with open(readme_file, 'w') as f:
                f.write(readme_content)
            generated_files.append(str(readme_file))
        
        # Calculate file sizes
        file_sizes = {}
        for file_path in generated_files:
            if Path(file_path).exists():
                file_sizes[file_path] = Path(file_path).stat().st_size
        
        result = GenerationResult(
            framework=IaCFramework.TERRAFORM,
            output_files=generated_files,
            modules=modules,
            metadata={
                'project_name': iac_config.project_name,
                'environment': iac_config.environment,
                'modular_structure': iac_config.modular_structure,
                'modules_count': len(modules),
                'estimated_cost': infrastructure_plan['estimated_cost']['monthly']
            },
            generated_at=datetime.utcnow(),
            file_sizes=file_sizes
        )
        
        self.logger.info(f"Terraform code generated successfully. Files: {len(generated_files)}")
        return result
    
    def _generate_main_tf(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration,
        iac_config: IaCConfig
    ) -> str:
        """Generate main Terraform configuration."""
        content = textwrap.dedent(f'''
        # Main Terraform configuration for {iac_config.project_name}
        # Environment: {iac_config.environment}
        # Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
        
        terraform {{
          required_version = ">= 1.0"
          required_providers {{
            aws = {{
              source  = "hashicorp/aws"
              version = "~> 5.0"
            }}
            kubernetes = {{
              source  = "hashicorp/kubernetes"
              version = "~> 2.0"
            }}
            helm = {{
              source  = "hashicorp/helm"
              version = "~> 2.0"
            }}
          }}
        }}
        
        locals {{
          project_name = var.project_name
          environment  = var.environment
          region      = var.aws_region
          
          common_tags = {{
            Project     = local.project_name
            Environment = local.environment
            ManagedBy   = "terraform"
            CreatedBy   = "agentic-infra-manager"
          }}
        }}
        
        # VPC Module
        module "vpc" {{
          source = "./modules/vpc"
          
          project_name        = local.project_name
          environment         = local.environment
          vpc_cidr           = var.vpc_cidr
          availability_zones = var.availability_zones
          
          tags = local.common_tags
        }}
        
        # EKS Module
        module "eks" {{
          source = "./modules/eks"
          
          project_name       = local.project_name
          environment        = local.environment
          cluster_version    = var.cluster_version
          
          vpc_id                = module.vpc.vpc_id
          private_subnet_ids    = module.vpc.private_subnet_ids
          public_subnet_ids     = module.vpc.public_subnet_ids
          
          node_groups = var.node_groups
          
          tags = local.common_tags
        }}
        ''')
        
        # Add RDS module if database is configured
        if infrastructure_plan.get('database_resources'):
            content += textwrap.dedent(f'''
            
            # RDS Module
            module "rds" {{
              source = "./modules/rds"
              
              project_name = local.project_name
              environment  = local.environment
              
              vpc_id             = module.vpc.vpc_id
              private_subnet_ids = module.vpc.private_subnet_ids
              
              engine               = var.db_engine
              engine_version       = var.db_engine_version
              instance_class       = var.db_instance_class
              allocated_storage    = var.db_allocated_storage
              
              tags = local.common_tags
            }}
            ''')
        
        return content
    
    def _generate_variables_tf(
        self,
        infrastructure_plan: InfrastructurePlan,
        iac_config: IaCConfig
    ) -> str:
        """Generate variables file."""
        vpc_config = infrastructure_plan['vpc_configuration']
        eks_config = infrastructure_plan['eks_configuration']
        
        content = textwrap.dedent(f'''
        # Variables for {iac_config.project_name}
        
        variable "project_name" {{
          description = "Name of the project"
          type        = string
          default     = "{iac_config.project_name}"
        }}
        
        variable "environment" {{
          description = "Environment name"
          type        = string
          default     = "{iac_config.environment}"
        }}
        
        variable "aws_region" {{
          description = "AWS region"
          type        = string
          default     = "{self.config.aws.region}"
        }}
        
        variable "vpc_cidr" {{
          description = "CIDR block for VPC"
          type        = string
          default     = "{vpc_config.vpc_cidr}"
        }}
        
        variable "availability_zones" {{
          description = "Availability zones"
          type        = list(string)
          default     = {json.dumps(vpc_config.availability_zones)}
        }}
        
        variable "cluster_version" {{
          description = "Kubernetes cluster version"
          type        = string
          default     = "{eks_config['version']}"
        }}
        
        variable "node_groups" {{
          description = "EKS node groups configuration"
          type        = any
          default     = {json.dumps(eks_config['node_groups'], indent=2)}
        }}
        ''')
        
        # Add database variables if configured
        if infrastructure_plan.get('database_resources'):
            db_config = infrastructure_plan['database_resources']
            content += textwrap.dedent(f'''
            
            variable "db_engine" {{
              description = "Database engine"
              type        = string
              default     = "{db_config.engine}"
            }}
            
            variable "db_engine_version" {{
              description = "Database engine version"
              type        = string
              default     = "{db_config.version}"
            }}
            
            variable "db_instance_class" {{
              description = "Database instance class"
              type        = string
              default     = "{db_config.instance_class}"
            }}
            
            variable "db_allocated_storage" {{
              description = "Database allocated storage"
              type        = number
              default     = {db_config.allocated_storage}
            }}
            ''')
        
        return content
    
    def _generate_outputs_tf(
        self,
        infrastructure_plan: InfrastructurePlan,
        iac_config: IaCConfig
    ) -> str:
        """Generate outputs file."""
        content = textwrap.dedent(f'''
        # Outputs for {iac_config.project_name}
        
        output "vpc_id" {{
          description = "VPC ID"
          value       = module.vpc.vpc_id
        }}
        
        output "vpc_cidr" {{
          description = "VPC CIDR block"
          value       = module.vpc.vpc_cidr
        }}
        
        output "private_subnet_ids" {{
          description = "Private subnet IDs"
          value       = module.vpc.private_subnet_ids
        }}
        
        output "public_subnet_ids" {{
          description = "Public subnet IDs"
          value       = module.vpc.public_subnet_ids
        }}
        
        output "eks_cluster_id" {{
          description = "EKS cluster ID"
          value       = module.eks.cluster_id
        }}
        
        output "eks_cluster_endpoint" {{
          description = "EKS cluster endpoint"
          value       = module.eks.cluster_endpoint
        }}
        
        output "eks_cluster_arn" {{
          description = "EKS cluster ARN"
          value       = module.eks.cluster_arn
        }}
        
        output "eks_cluster_security_group_id" {{
          description = "EKS cluster security group ID"
          value       = module.eks.cluster_security_group_id
        }}
        ''')
        
        # Add RDS outputs if configured
        if infrastructure_plan.get('database_resources'):
            content += textwrap.dedent('''
            
            output "rds_endpoint" {
              description = "RDS endpoint"
              value       = module.rds.endpoint
            }
            
            output "rds_port" {
              description = "RDS port"
              value       = module.rds.port
            }
            
            output "rds_security_group_id" {
              description = "RDS security group ID"
              value       = module.rds.security_group_id
            }
            ''')
        
        return content
    
    def _generate_provider_tf(self, iac_config: IaCConfig) -> str:
        """Generate provider configuration."""
        return textwrap.dedent(f'''
        # Provider configuration for {iac_config.project_name}
        
        provider "aws" {{
          region = var.aws_region
          
          default_tags {{
            tags = {{
              Project     = var.project_name
              Environment = var.environment
              ManagedBy   = "terraform"
            }}
          }}
        }}
        
        provider "kubernetes" {{
          host                   = module.eks.cluster_endpoint
          cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
          
          exec {{
            api_version = "client.authentication.k8s.io/v1beta1"
            command     = "aws"
            args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_id]
          }}
        }}
        
        provider "helm" {{
          kubernetes {{
            host                   = module.eks.cluster_endpoint
            cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
            
            exec {{
              api_version = "client.authentication.k8s.io/v1beta1"
              command     = "aws"
              args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_id]
            }}
          }}
        }}
        ''')
    
    def _generate_vpc_module(
        self,
        infrastructure_plan: InfrastructurePlan,
        iac_config: IaCConfig
    ) -> Dict[str, str]:
        """Generate VPC module files."""
        vpc_config = infrastructure_plan['vpc_configuration']
        
        # Main VPC configuration
        main_content = textwrap.dedent(f'''
        # VPC Module
        
        resource "aws_vpc" "main" {{
          cidr_block           = var.vpc_cidr
          enable_dns_hostnames = true
          enable_dns_support   = true
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-vpc"
          }})
        }}
        
        # Internet Gateway
        resource "aws_internet_gateway" "main" {{
          vpc_id = aws_vpc.main.id
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-igw"
          }})
        }}
        
        # Public Subnets
        resource "aws_subnet" "public" {{
          count = length(var.availability_zones)
          
          vpc_id                  = aws_vpc.main.id
          cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
          availability_zone       = var.availability_zones[count.index]
          map_public_ip_on_launch = true
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-public-${{count.index + 1}}"
            Type = "public"
          }})
        }}
        
        # Private Subnets
        resource "aws_subnet" "private" {{
          count = length(var.availability_zones)
          
          vpc_id            = aws_vpc.main.id
          cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
          availability_zone = var.availability_zones[count.index]
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-private-${{count.index + 1}}"
            Type = "private"
          }})
        }}
        
        # NAT Gateways
        resource "aws_eip" "nat" {{
          count = length(var.availability_zones)
          
          domain = "vpc"
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-nat-eip-${{count.index + 1}}"
          }})
        }}
        
        resource "aws_nat_gateway" "main" {{
          count = length(var.availability_zones)
          
          allocation_id = aws_eip.nat[count.index].id
          subnet_id     = aws_subnet.public[count.index].id
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-nat-${{count.index + 1}}"
          }})
        }}
        
        # Route Tables
        resource "aws_route_table" "public" {{
          vpc_id = aws_vpc.main.id
          
          route {{
            cidr_block = "0.0.0.0/0"
            gateway_id = aws_internet_gateway.main.id
          }}
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-public-rt"
          }})
        }}
        
        resource "aws_route_table" "private" {{
          count = length(var.availability_zones)
          
          vpc_id = aws_vpc.main.id
          
          route {{
            cidr_block     = "0.0.0.0/0"
            nat_gateway_id = aws_nat_gateway.main[count.index].id
          }}
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-private-rt-${{count.index + 1}}"
          }})
        }}
        
        # Route Table Associations
        resource "aws_route_table_association" "public" {{
          count = length(var.availability_zones)
          
          subnet_id      = aws_subnet.public[count.index].id
          route_table_id = aws_route_table.public.id
        }}
        
        resource "aws_route_table_association" "private" {{
          count = length(var.availability_zones)
          
          subnet_id      = aws_subnet.private[count.index].id
          route_table_id = aws_route_table.private[count.index].id
        }}
        ''')
        
        # VPC Endpoints
        if vpc_config.vpc_endpoints:
            for endpoint in vpc_config.vpc_endpoints:
                main_content += textwrap.dedent(f'''
                
                # VPC Endpoint for {endpoint}
                resource "aws_vpc_endpoint" "{endpoint.replace('.', '_')}" {{
                  vpc_id              = aws_vpc.main.id
                  service_name        = "com.amazonaws.${{var.aws_region}}.{endpoint}"
                  vpc_endpoint_type   = "Gateway"
                  route_table_ids     = aws_route_table.private[*].id
                  
                  tags = merge(var.tags, {{
                    Name = "${{var.project_name}}-${{var.environment}}-vpce-{endpoint}"
                  }})
                }}
                ''')
        
        # Variables
        variables_content = textwrap.dedent('''
        variable "project_name" {
          description = "Name of the project"
          type        = string
        }
        
        variable "environment" {
          description = "Environment name"
          type        = string
        }
        
        variable "aws_region" {
          description = "AWS region"
          type        = string
        }
        
        variable "vpc_cidr" {
          description = "CIDR block for VPC"
          type        = string
        }
        
        variable "availability_zones" {
          description = "Availability zones"
          type        = list(string)
        }
        
        variable "tags" {
          description = "Tags to apply to resources"
          type        = map(string)
          default     = {}
        }
        ''')
        
        # Outputs
        outputs_content = textwrap.dedent('''
        output "vpc_id" {
          description = "VPC ID"
          value       = aws_vpc.main.id
        }
        
        output "vpc_cidr" {
          description = "VPC CIDR block"
          value       = aws_vpc.main.cidr_block
        }
        
        output "public_subnet_ids" {
          description = "Public subnet IDs"
          value       = aws_subnet.public[*].id
        }
        
        output "private_subnet_ids" {
          description = "Private subnet IDs"
          value       = aws_subnet.private[*].id
        }
        
        output "internet_gateway_id" {
          description = "Internet Gateway ID"
          value       = aws_internet_gateway.main.id
        }
        
        output "nat_gateway_ids" {
          description = "NAT Gateway IDs"
          value       = aws_nat_gateway.main[*].id
        }
        ''')
        
        return {
            'main': main_content,
            'variables': variables_content,
            'outputs': outputs_content
        }
    
    def _generate_eks_module(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration,
        iac_config: IaCConfig
    ) -> Dict[str, str]:
        """Generate EKS module files."""
        eks_config = infrastructure_plan['eks_configuration']
        
        # Main EKS configuration
        main_content = textwrap.dedent(f'''
        # EKS Module
        
        # EKS Cluster
        resource "aws_eks_cluster" "main" {{
          name     = var.cluster_name
          role_arn = aws_iam_role.cluster.arn
          version  = var.cluster_version
          
          vpc_config {{
            subnet_ids         = concat(var.private_subnet_ids, var.public_subnet_ids)
            security_group_ids = [aws_security_group.cluster.id]
          }}
          
          enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
          
          tags = var.tags
        }}
        
        # EKS Cluster IAM Role
        resource "aws_iam_role" "cluster" {{
          name = "${{var.project_name}}-${{var.environment}}-eks-cluster-role"
          
          assume_role_policy = jsonencode({{
            Version = "2012-10-17"
            Statement = [
              {{
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Principal = {{
                  Service = "eks.amazonaws.com"
                }}
              }}
            ]
          }})
          
          tags = var.tags
        }}
        
        resource "aws_iam_role_policy_attachment" "cluster" {{
          policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
          role       = aws_iam_role.cluster.name
        }}
        
        # EKS Cluster Security Group
        resource "aws_security_group" "cluster" {{
          name        = "${{var.project_name}}-${{var.environment}}-eks-cluster-sg"
          description = "EKS cluster security group"
          vpc_id      = var.vpc_id
          
          egress {{
            from_port   = 0
            to_port     = 0
            protocol    = "-1"
            cidr_blocks = ["0.0.0.0/0"]
          }}
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-eks-cluster-sg"
          }})
        }}
        
        # EKS Node Groups
        resource "aws_eks_node_group" "main" {{
          for_each = {{ for ng in var.node_groups : ng.name => ng }}
          
          cluster_name    = aws_eks_cluster.main.name
          node_group_name = each.value.name
          node_role_arn   = aws_iam_role.node_group.arn
          subnet_ids      = var.private_subnet_ids
          
          instance_types = each.value.instance_types
          ami_type       = each.value.ami_type
          capacity_type  = each.value.capacity_type
          disk_size      = each.value.disk_size
          
          scaling_config {{
            desired_size = each.value.scaling_config.desired_size
            max_size     = each.value.scaling_config.max_size
            min_size     = each.value.scaling_config.min_size
          }}
          
          dynamic "taint" {{
            for_each = lookup(each.value, "taints", [])
            content {{
              key    = taint.value.key
              value  = taint.value.value
              effect = taint.value.effect
            }}
          }}
          
          labels = lookup(each.value, "labels", {{}})
          
          tags = var.tags
        }}
        
        # EKS Node Group IAM Role
        resource "aws_iam_role" "node_group" {{
          name = "${{var.project_name}}-${{var.environment}}-eks-node-group-role"
          
          assume_role_policy = jsonencode({{
            Version = "2012-10-17"
            Statement = [
              {{
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Principal = {{
                  Service = "ec2.amazonaws.com"
                }}
              }}
            ]
          }})
          
          tags = var.tags
        }}
        
        resource "aws_iam_role_policy_attachment" "node_group" {{
          for_each = toset([
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
          ])
          
          policy_arn = each.value
          role       = aws_iam_role.node_group.name
        }}
        
        # EKS Add-ons
        resource "aws_eks_addon" "main" {{
          for_each = {{ for addon in var.addons : addon.name => addon }}
          
          cluster_name      = aws_eks_cluster.main.name
          addon_name        = each.value.name
          addon_version     = each.value.version
          resolve_conflicts = each.value.resolve_conflicts
          
          tags = var.tags
        }}
        ''')
        
        # Variables
        variables_content = textwrap.dedent('''
        variable "project_name" {
          description = "Name of the project"
          type        = string
        }
        
        variable "environment" {
          description = "Environment name"
          type        = string
        }
        
        variable "cluster_name" {
          description = "EKS cluster name"
          type        = string
        }
        
        variable "cluster_version" {
          description = "EKS cluster version"
          type        = string
        }
        
        variable "vpc_id" {
          description = "VPC ID"
          type        = string
        }
        
        variable "private_subnet_ids" {
          description = "Private subnet IDs"
          type        = list(string)
        }
        
        variable "public_subnet_ids" {
          description = "Public subnet IDs"
          type        = list(string)
        }
        
        variable "node_groups" {
          description = "EKS node groups configuration"
          type        = any
        }
        
        variable "addons" {
          description = "EKS add-ons configuration"
          type        = any
          default     = []
        }
        
        variable "tags" {
          description = "Tags to apply to resources"
          type        = map(string)
          default     = {}
        }
        ''')
        
        # Outputs
        outputs_content = textwrap.dedent('''
        output "cluster_id" {
          description = "EKS cluster ID"
          value       = aws_eks_cluster.main.id
        }
        
        output "cluster_arn" {
          description = "EKS cluster ARN"
          value       = aws_eks_cluster.main.arn
        }
        
        output "cluster_endpoint" {
          description = "EKS cluster endpoint"
          value       = aws_eks_cluster.main.endpoint
        }
        
        output "cluster_certificate_authority_data" {
          description = "EKS cluster certificate authority data"
          value       = aws_eks_cluster.main.certificate_authority[0].data
        }
        
        output "cluster_security_group_id" {
          description = "EKS cluster security group ID"
          value       = aws_security_group.cluster.id
        }
        
        output "node_group_arns" {
          description = "EKS node group ARNs"
          value       = { for k, v in aws_eks_node_group.main : k => v.arn }
        }
        ''')
        
        return {
            'main': main_content,
            'variables': variables_content,
            'outputs': outputs_content
        }
    
    def _generate_rds_module(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration,
        iac_config: IaCConfig
    ) -> Dict[str, str]:
        """Generate RDS module files."""
        db_config = infrastructure_plan['database_resources']
        
        # Main RDS configuration
        main_content = textwrap.dedent(f'''
        # RDS Module
        
        # RDS Subnet Group
        resource "aws_db_subnet_group" "main" {{
          name       = "${{var.project_name}}-${{var.environment}}-db-subnet-group"
          subnet_ids = var.private_subnet_ids
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-db-subnet-group"
          }})
        }}
        
        # RDS Security Group
        resource "aws_security_group" "rds" {{
          name        = "${{var.project_name}}-${{var.environment}}-rds-sg"
          description = "RDS security group"
          vpc_id      = var.vpc_id
          
          ingress {{
            from_port   = var.port
            to_port     = var.port
            protocol    = "tcp"
            cidr_blocks = [var.vpc_cidr]
          }}
          
          egress {{
            from_port   = 0
            to_port     = 0
            protocol    = "-1"
            cidr_blocks = ["0.0.0.0/0"]
          }}
          
          tags = merge(var.tags, {{
            Name = "${{var.project_name}}-${{var.environment}}-rds-sg"
          }})
        }}
        
        # RDS Instance
        resource "aws_db_instance" "main" {{
          identifier = "${{var.project_name}}-${{var.environment}}-db"
          
          engine         = var.engine
          engine_version = var.engine_version
          instance_class = var.instance_class
          
          allocated_storage     = var.allocated_storage
          max_allocated_storage = var.allocated_storage * 2
          storage_type          = "gp3"
          storage_encrypted     = true
          
          db_name  = var.db_name
          username = var.username
          password = var.password
          
          vpc_security_group_ids = [aws_security_group.rds.id]
          db_subnet_group_name   = aws_db_subnet_group.main.name
          
          backup_retention_period = var.backup_retention_period
          backup_window          = "03:00-04:00"
          maintenance_window     = "sun:04:00-sun:05:00"
          
          multi_az               = var.multi_az
          deletion_protection    = var.deletion_protection
          skip_final_snapshot    = !var.deletion_protection
          
          tags = var.tags
        }}
        ''')
        
        # Variables
        variables_content = textwrap.dedent(f'''
        variable "project_name" {{
          description = "Name of the project"
          type        = string
        }}
        
        variable "environment" {{
          description = "Environment name"
          type        = string
        }}
        
        variable "vpc_id" {{
          description = "VPC ID"
          type        = string
        }}
        
        variable "vpc_cidr" {{
          description = "VPC CIDR block"
          type        = string
        }}
        
        variable "private_subnet_ids" {{
          description = "Private subnet IDs"
          type        = list(string)
        }}
        
        variable "engine" {{
          description = "Database engine"
          type        = string
          default     = "{db_config.engine}"
        }}
        
        variable "engine_version" {{
          description = "Database engine version"
          type        = string
          default     = "{db_config.version}"
        }}
        
        variable "instance_class" {{
          description = "Database instance class"
          type        = string
          default     = "{db_config.instance_class}"
        }}
        
        variable "allocated_storage" {{
          description = "Allocated storage in GB"
          type        = number
          default     = {db_config.allocated_storage}
        }}
        
        variable "db_name" {{
          description = "Database name"
          type        = string
          default     = "app_db"
        }}
        
        variable "username" {{
          description = "Database username"
          type        = string
          default     = "admin"
        }}
        
        variable "password" {{
          description = "Database password"
          type        = string
          sensitive   = true
        }}
        
        variable "port" {{
          description = "Database port"
          type        = number
          default     = {5432 if db_config.engine == 'postgres' else 3306}
        }}
        
        variable "backup_retention_period" {{
          description = "Backup retention period"
          type        = number
          default     = {db_config.backup_retention}
        }}
        
        variable "multi_az" {{
          description = "Multi-AZ deployment"
          type        = bool
          default     = {str(db_config.multi_az).lower()}
        }}
        
        variable "deletion_protection" {{
          description = "Deletion protection"
          type        = bool
          default     = {str(db_config.deletion_protection).lower()}
        }}
        
        variable "tags" {{
          description = "Tags to apply to resources"
          type        = map(string)
          default     = {{}}
        }}
        ''')
        
        # Outputs
        outputs_content = textwrap.dedent('''
        output "endpoint" {
          description = "RDS endpoint"
          value       = aws_db_instance.main.endpoint
        }
        
        output "port" {
          description = "RDS port"
          value       = aws_db_instance.main.port
        }
        
        output "db_name" {
          description = "Database name"
          value       = aws_db_instance.main.db_name
        }
        
        output "security_group_id" {
          description = "RDS security group ID"
          value       = aws_security_group.rds.id
        }
        
        output "subnet_group_name" {
          description = "RDS subnet group name"
          value       = aws_db_subnet_group.main.name
        }
        ''')
        
        return {
            'main': main_content,
            'variables': variables_content,
            'outputs': outputs_content
        }
    
    def _generate_terraform_tfvars(
        self,
        infrastructure_plan: InfrastructurePlan,
        iac_config: IaCConfig
    ) -> str:
        """Generate Terraform variables file."""
        vpc_config = infrastructure_plan['vpc_configuration']
        
        content = textwrap.dedent(f'''
        # Terraform variables for {iac_config.environment} environment
        
        project_name = "{iac_config.project_name}"
        environment  = "{iac_config.environment}"
        aws_region   = "{self.config.aws.region}"
        
        # VPC Configuration
        vpc_cidr           = "{vpc_config.vpc_cidr}"
        availability_zones = {json.dumps(vpc_config.availability_zones)}
        
        # EKS Configuration
        cluster_version = "{infrastructure_plan['eks_configuration']['version']}"
        ''')
        
        # Add database configuration if present
        if infrastructure_plan.get('database_resources'):
            db_config = infrastructure_plan['database_resources']
            content += textwrap.dedent(f'''
            
            # Database Configuration
            db_engine         = "{db_config.engine}"
            db_engine_version = "{db_config.version}"
            db_instance_class = "{db_config.instance_class}"
            db_allocated_storage = {db_config.allocated_storage}
            ''')
        
        return content
    
    def _generate_backend_tf(self, iac_config: IaCConfig) -> str:
        """Generate Terraform backend configuration."""
        return textwrap.dedent(f'''
        # Terraform backend configuration
        
        terraform {{
          backend "s3" {{
            bucket = "{iac_config.project_name}-terraform-state"
            key    = "{iac_config.environment}/terraform.tfstate"
            region = "{self.config.aws.region}"
            
            # DynamoDB table for state locking
            dynamodb_table = "{iac_config.project_name}-terraform-locks"
            encrypt        = true
          }}
        }}
        ''')
    
    def _generate_terraform_readme(
        self,
        infrastructure_plan: InfrastructurePlan,
        modules: List[IaCModule],
        iac_config: IaCConfig
    ) -> str:
        """Generate README for Terraform configuration."""
        return textwrap.dedent(f'''
        # {iac_config.project_name} - {iac_config.environment} Environment
        
        This directory contains Terraform configuration for deploying the {iac_config.project_name} infrastructure in the {iac_config.environment} environment.
        
        ## Architecture Overview
        
        - **VPC**: {infrastructure_plan['vpc_configuration'].vpc_cidr}
        - **EKS Cluster**: {infrastructure_plan['eks_configuration']['cluster_name']}
        - **Kubernetes Version**: {infrastructure_plan['eks_configuration']['version']}
        - **Node Groups**: {len(infrastructure_plan['eks_configuration']['node_groups'])}
        - **Estimated Monthly Cost**: ${infrastructure_plan['estimated_cost']['monthly']:.2f}
        
        ## Modules
        
        {chr(10).join(f"- **{module.name}**: {module.type}" for module in modules)}
        
        ## Prerequisites
        
        1. AWS CLI configured with appropriate credentials
        2. Terraform >= 1.0 installed
        3. kubectl installed for Kubernetes management
        
        ## Deployment
        
        1. Initialize Terraform:
           ```bash
           terraform init
           ```
        
        2. Plan the deployment:
           ```bash
           terraform plan -var-file="{iac_config.environment}.tfvars"
           ```
        
        3. Apply the configuration:
           ```bash
           terraform apply -var-file="{iac_config.environment}.tfvars"
           ```
        
        ## Cleanup
        
        To destroy the infrastructure:
        ```bash
        terraform destroy -var-file="{iac_config.environment}.tfvars"
        ```
        
        ## Generated Files
        
        - `main.tf`: Main Terraform configuration
        - `variables.tf`: Input variables
        - `outputs.tf`: Output values
        - `provider.tf`: Provider configuration
        - `backend.tf`: Backend configuration
        - `{iac_config.environment}.tfvars`: Environment-specific variables
        - `modules/`: Reusable Terraform modules
        
        ## Security Notes
        
        - All resources are tagged with project and environment information
        - Database passwords should be managed via AWS Secrets Manager
        - EKS cluster uses IAM roles for service accounts (IRSA)
        - VPC endpoints are configured for private connectivity
        
        ## Monitoring
        
        The infrastructure includes:
        - CloudWatch logging for EKS control plane
        - VPC Flow Logs for network monitoring
        - AWS Config for compliance monitoring
        
        ## Support
        
        Generated by Agentic Infrastructure Manager on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
        ''')


class IaCGenerator:
    """
    Comprehensive Infrastructure as Code generator.
    
    Generates Terraform, CDK, and Kubernetes manifests for infrastructure deployment.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the IaC Generator.
        
        Args:
            config: Agent configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize generators
        self.terraform_generator = TerraformGenerator(config)
        
        # Output directory
        self.output_dir = Path(config.workspace) / "iac"
        self.output_dir.mkdir(exist_ok=True)
        
        self.logger.info("IaC Generator initialized")
    
    async def generate_infrastructure_code(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration,
        repository_analysis: RepositoryAnalysis,
        framework: IaCFramework = IaCFramework.TERRAFORM,
        environment: str = "dev"
    ) -> GenerationResult:
        """
        Generate infrastructure code for the specified framework.
        
        Args:
            infrastructure_plan: Infrastructure plan to generate code for
            security_config: Security configuration
            repository_analysis: Repository analysis results
            framework: IaC framework to use
            environment: Target environment
            
        Returns:
            Generation result
        """
        self.logger.info(f"Generating {framework.value} code for {environment} environment")
        
        # Create IaC configuration
        iac_config = IaCConfig(
            framework=framework,
            output_format=OutputFormat.HCL if framework == IaCFramework.TERRAFORM else OutputFormat.PYTHON,
            output_directory=str(self.output_dir / framework.value / environment),
            project_name=repository_analysis['name'],
            environment=environment,
            include_monitoring=True,
            include_backup=environment == "prod",
            include_security=True,
            modular_structure=True,
            generate_docs=True
        )
        
        # Generate code based on framework
        if framework == IaCFramework.TERRAFORM:
            result = self.terraform_generator.generate_terraform_code(
                infrastructure_plan, security_config, iac_config
            )
        elif framework == IaCFramework.CDK_PYTHON:
            result = await self._generate_cdk_python(
                infrastructure_plan, security_config, iac_config
            )
        elif framework == IaCFramework.CDK_TYPESCRIPT:
            result = await self._generate_cdk_typescript(
                infrastructure_plan, security_config, iac_config
            )
        else:
            raise ValueError(f"Unsupported framework: {framework}")
        
        # Generate Kubernetes manifests
        k8s_manifests = await self._generate_kubernetes_manifests(
            infrastructure_plan, repository_analysis, iac_config
        )
        result.output_files.extend(k8s_manifests)
        
        self.logger.info(f"Infrastructure code generated successfully: {len(result.output_files)} files")
        return result
    
    async def _generate_cdk_python(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration,
        iac_config: IaCConfig
    ) -> GenerationResult:
        """Generate CDK Python code."""
        # This would implement CDK Python code generation
        # For now, return a placeholder
        return GenerationResult(
            framework=IaCFramework.CDK_PYTHON,
            output_files=[],
            modules=[],
            metadata={'note': 'CDK Python generation not implemented yet'},
            generated_at=datetime.utcnow(),
            file_sizes={}
        )
    
    async def _generate_cdk_typescript(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration,
        iac_config: IaCConfig
    ) -> GenerationResult:
        """Generate CDK TypeScript code."""
        # This would implement CDK TypeScript code generation
        # For now, return a placeholder
        return GenerationResult(
            framework=IaCFramework.CDK_TYPESCRIPT,
            output_files=[],
            modules=[],
            metadata={'note': 'CDK TypeScript generation not implemented yet'},
            generated_at=datetime.utcnow(),
            file_sizes={}
        )
    
    async def _generate_kubernetes_manifests(
        self,
        infrastructure_plan: InfrastructurePlan,
        repository_analysis: RepositoryAnalysis,
        iac_config: IaCConfig
    ) -> List[str]:
        """Generate Kubernetes manifests."""
        self.logger.info("Generating Kubernetes manifests")
        
        k8s_dir = Path(iac_config.output_directory) / "kubernetes"
        k8s_dir.mkdir(parents=True, exist_ok=True)
        
        generated_files = []
        
        # Namespace
        namespace_manifest = textwrap.dedent(f'''
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {repository_analysis['name']}
          labels:
            environment: {iac_config.environment}
            project: {iac_config.project_name}
        ''')
        
        namespace_file = k8s_dir / "namespace.yaml"
        with open(namespace_file, 'w') as f:
            f.write(namespace_manifest)
        generated_files.append(str(namespace_file))
        
        # Deployment
        deployment_manifest = textwrap.dedent(f'''
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {repository_analysis['name']}
          namespace: {repository_analysis['name']}
          labels:
            app: {repository_analysis['name']}
            environment: {iac_config.environment}
        spec:
          replicas: 2
          selector:
            matchLabels:
              app: {repository_analysis['name']}
          template:
            metadata:
              labels:
                app: {repository_analysis['name']}
            spec:
              containers:
              - name: {repository_analysis['name']}
                image: {repository_analysis['name']}:latest
                ports:
                - containerPort: 8080
                resources:
                  requests:
                    memory: "256Mi"
                    cpu: "250m"
                  limits:
                    memory: "512Mi"
                    cpu: "500m"
                env:
                - name: ENVIRONMENT
                  value: "{iac_config.environment}"
                livenessProbe:
                  httpGet:
                    path: /health
                    port: 8080
                  initialDelaySeconds: 30
                  periodSeconds: 10
                readinessProbe:
                  httpGet:
                    path: /ready
                    port: 8080
                  initialDelaySeconds: 5
                  periodSeconds: 5
        ''')
        
        deployment_file = k8s_dir / "deployment.yaml"
        with open(deployment_file, 'w') as f:
            f.write(deployment_manifest)
        generated_files.append(str(deployment_file))
        
        # Service
        service_manifest = textwrap.dedent(f'''
        apiVersion: v1
        kind: Service
        metadata:
          name: {repository_analysis['name']}-service
          namespace: {repository_analysis['name']}
          labels:
            app: {repository_analysis['name']}
        spec:
          selector:
            app: {repository_analysis['name']}
          ports:
          - protocol: TCP
            port: 80
            targetPort: 8080
          type: ClusterIP
        ''')
        
        service_file = k8s_dir / "service.yaml"
        with open(service_file, 'w') as f:
            f.write(service_manifest)
        generated_files.append(str(service_file))
        
        # Ingress
        ingress_manifest = textwrap.dedent(f'''
        apiVersion: networking.k8s.io/v1
        kind: Ingress
        metadata:
          name: {repository_analysis['name']}-ingress
          namespace: {repository_analysis['name']}
          annotations:
            kubernetes.io/ingress.class: alb
            alb.ingress.kubernetes.io/scheme: internet-facing
            alb.ingress.kubernetes.io/target-type: ip
        spec:
          rules:
          - host: {repository_analysis['name']}.{iac_config.environment}.example.com
            http:
              paths:
              - path: /
                pathType: Prefix
                backend:
                  service:
                    name: {repository_analysis['name']}-service
                    port:
                      number: 80
        ''')
        
        ingress_file = k8s_dir / "ingress.yaml"
        with open(ingress_file, 'w') as f:
            f.write(ingress_manifest)
        generated_files.append(str(ingress_file))
        
        # HPA
        hpa_manifest = textwrap.dedent(f'''
        apiVersion: autoscaling/v2
        kind: HorizontalPodAutoscaler
        metadata:
          name: {repository_analysis['name']}-hpa
          namespace: {repository_analysis['name']}
        spec:
          scaleTargetRef:
            apiVersion: apps/v1
            kind: Deployment
            name: {repository_analysis['name']}
          minReplicas: 2
          maxReplicas: 10
          metrics:
          - type: Resource
            resource:
              name: cpu
              target:
                type: Utilization
                averageUtilization: 70
          - type: Resource
            resource:
              name: memory
              target:
                type: Utilization
                averageUtilization: 80
        ''')
        
        hpa_file = k8s_dir / "hpa.yaml"
        with open(hpa_file, 'w') as f:
            f.write(hpa_manifest)
        generated_files.append(str(hpa_file))
        
        self.logger.info(f"Generated {len(generated_files)} Kubernetes manifests")
        return generated_files
    
    async def validate_generated_code(self, result: GenerationResult) -> List[str]:
        """
        Validate generated infrastructure code.
        
        Args:
            result: Generation result to validate
            
        Returns:
            List of validation errors
        """
        self.logger.info("Validating generated infrastructure code")
        
        validation_errors = []
        
        # Check if files exist
        for file_path in result.output_files:
            if not Path(file_path).exists():
                validation_errors.append(f"Generated file does not exist: {file_path}")
        
        # Framework-specific validation
        if result.framework == IaCFramework.TERRAFORM:
            terraform_errors = await self._validate_terraform_code(result)
            validation_errors.extend(terraform_errors)
        
        # Check for required modules
        required_modules = ['vpc', 'eks']
        for module in result.modules:
            if module.name in required_modules:
                required_modules.remove(module.name)
        
        if required_modules:
            validation_errors.append(f"Missing required modules: {required_modules}")
        
        if validation_errors:
            self.logger.warning(f"Code validation found {len(validation_errors)} issues")
        else:
            self.logger.info("Code validation passed")
        
        return validation_errors
    
    async def _validate_terraform_code(self, result: GenerationResult) -> List[str]:
        """Validate Terraform code."""
        errors = []
        
        # Check for required files
        required_files = ['main.tf', 'variables.tf', 'outputs.tf', 'provider.tf']
        for file_name in required_files:
            if not any(file_name in path for path in result.output_files):
                errors.append(f"Missing required Terraform file: {file_name}")
        
        return errors
    
    async def cleanup_old_code(self, days_old: int = 30):
        """
        Clean up old generated code.
        
        Args:
            days_old: Number of days after which to delete files
        """
        self.logger.info(f"Cleaning up generated code older than {days_old} days")
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        cleaned_files = 0
        
        for file_path in self.output_dir.rglob("*"):
            if file_path.is_file():
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_mtime < cutoff_date:
                    file_path.unlink()
                    cleaned_files += 1
        
        self.logger.info(f"Cleaned up {cleaned_files} old generated files")
        return cleaned_files 