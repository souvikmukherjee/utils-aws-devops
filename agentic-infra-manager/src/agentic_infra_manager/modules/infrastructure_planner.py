"""
Infrastructure Planner module for AWS infrastructure planning and optimization.

This module provides comprehensive infrastructure planning capabilities including:
- AWS resource planning and sizing
- Network topology design
- High availability and disaster recovery planning
- Cost optimization recommendations
- Infrastructure as Code generation
- Multi-region deployment strategies
"""

import json
import boto3
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import yaml

from ..core.state import (
    InfrastructurePlan, 
    InfrastructureRequirement,
    ApplicationType,
    DeploymentPhase,
    RepositoryAnalysis,
    SecurityConfiguration
)
from ..core.config import AgentConfig


class DeploymentStrategy(Enum):
    """Deployment strategy types."""
    BLUE_GREEN = "blue_green"
    CANARY = "canary"
    ROLLING = "rolling"
    RECREATE = "recreate"


class HighAvailabilityLevel(Enum):
    """High availability levels."""
    SINGLE_AZ = "single_az"
    MULTI_AZ = "multi_az"
    MULTI_REGION = "multi_region"


@dataclass
class ResourceRequirement:
    """Resource requirement specification."""
    resource_type: str
    count: int
    specifications: Dict[str, Any]
    dependencies: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class NetworkTopology:
    """Network topology configuration."""
    vpc_cidr: str
    availability_zones: List[str]
    public_subnets: List[Dict[str, Any]]
    private_subnets: List[Dict[str, Any]]
    nat_gateways: int
    internet_gateway: bool
    vpc_endpoints: List[str]
    route_tables: List[Dict[str, Any]]


@dataclass
class ComputeConfiguration:
    """Compute resource configuration."""
    instance_types: List[str]
    min_instances: int
    max_instances: int
    desired_instances: int
    auto_scaling_enabled: bool
    spot_instances_enabled: bool
    spot_percentage: int = 0


@dataclass
class StorageConfiguration:
    """Storage configuration."""
    storage_type: str  # ebs, efs, s3
    size_gb: int
    iops: Optional[int] = None
    throughput: Optional[int] = None
    encryption_enabled: bool = True
    backup_enabled: bool = True
    retention_days: int = 30


@dataclass
class DatabaseConfiguration:
    """Database configuration."""
    engine: str
    version: str
    instance_class: str
    allocated_storage: int
    multi_az: bool = True
    backup_retention: int = 7
    encryption: bool = True
    deletion_protection: bool = True


class InfrastructurePlanner:
    """
    Comprehensive infrastructure planning and optimization for AWS deployments.
    
    This class analyzes application requirements and generates optimized infrastructure
    plans considering cost, performance, security, and compliance requirements.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the Infrastructure Planner.
        
        Args:
            config: Agent configuration containing AWS and deployment settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize AWS clients
        self.ec2_client = boto3.client('ec2', region_name=config.aws.region)
        self.eks_client = boto3.client('eks', region_name=config.aws.region)
        self.pricing_client = boto3.client('pricing', region_name='us-east-1')
        self.cloudformation_client = boto3.client('cloudformation', region_name=config.aws.region)
        
        # Resource templates and best practices
        self.resource_templates = self._load_resource_templates()
        self.cost_optimization_rules = self._load_cost_optimization_rules()
        
        self.logger.info("Infrastructure Planner initialized")
    
    async def create_infrastructure_plan(
        self,
        repository_analysis: RepositoryAnalysis,
        security_config: SecurityConfiguration,
        target_environment: str,
        user_requirements: Dict[str, Any] = None
    ) -> InfrastructurePlan:
        """
        Create a comprehensive infrastructure plan.
        
        Args:
            repository_analysis: Repository analysis results
            security_config: Security configuration requirements
            target_environment: Target environment (dev/staging/prod)
            user_requirements: Additional user-specified requirements
            
        Returns:
            Complete infrastructure plan
        """
        self.logger.info(f"Creating infrastructure plan for {repository_analysis['name']}")
        
        user_requirements = user_requirements or {}
        
        # Analyze infrastructure requirements
        infra_requirements = repository_analysis['infrastructure_requirements']
        
        # Plan network topology
        network_topology = await self._plan_network_topology(
            infra_requirements, target_environment, user_requirements
        )
        
        # Plan compute resources
        compute_config = await self._plan_compute_resources(
            repository_analysis, infra_requirements, target_environment
        )
        
        # Plan storage resources
        storage_config = await self._plan_storage_resources(
            repository_analysis, infra_requirements, target_environment
        )
        
        # Plan database resources if needed
        database_config = await self._plan_database_resources(
            repository_analysis, infra_requirements, target_environment
        )
        
        # Plan EKS cluster configuration
        eks_config = await self._plan_eks_cluster(
            repository_analysis, security_config, target_environment
        )
        
        # Plan monitoring and observability
        monitoring_config = await self._plan_monitoring_resources(
            repository_analysis, target_environment
        )
        
        # Determine deployment strategy
        deployment_strategy = self._determine_deployment_strategy(
            repository_analysis, target_environment
        )
        
        # Calculate costs
        cost_estimate = await self._calculate_infrastructure_costs(
            network_topology, compute_config, storage_config, database_config, eks_config
        )
        
        # Generate deployment timeline
        deployment_timeline = self._generate_deployment_timeline(
            network_topology, compute_config, storage_config, database_config, eks_config
        )
        
        # Create infrastructure plan
        plan = InfrastructurePlan(
            plan_id=f"plan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            vpc_configuration=network_topology,
            eks_configuration=eks_config,
            compute_resources=compute_config,
            storage_resources=storage_config,
            database_resources=database_config,
            networking_config=network_topology,
            security_config=security_config,
            monitoring_config=monitoring_config,
            deployment_strategy=deployment_strategy.value,
            estimated_cost=cost_estimate,
            deployment_timeline=deployment_timeline,
            terraform_code=None,  # Will be generated by IaC generator
            cdk_code=None,
            k8s_manifests=[]
        )
        
        self.logger.info(f"Infrastructure plan created: {plan['plan_id']}")
        return plan
    
    async def optimize_infrastructure_plan(
        self,
        plan: InfrastructurePlan,
        optimization_goals: List[str] = None
    ) -> InfrastructurePlan:
        """
        Optimize an existing infrastructure plan.
        
        Args:
            plan: Original infrastructure plan
            optimization_goals: List of optimization goals (cost, performance, security)
            
        Returns:
            Optimized infrastructure plan
        """
        self.logger.info(f"Optimizing infrastructure plan: {plan['plan_id']}")
        
        optimization_goals = optimization_goals or ['cost', 'performance']
        optimized_plan = plan.copy()
        
        # Cost optimization
        if 'cost' in optimization_goals:
            optimized_plan = await self._optimize_for_cost(optimized_plan)
        
        # Performance optimization
        if 'performance' in optimization_goals:
            optimized_plan = await self._optimize_for_performance(optimized_plan)
        
        # Security optimization
        if 'security' in optimization_goals:
            optimized_plan = await self._optimize_for_security(optimized_plan)
        
        # Recalculate costs after optimization
        optimized_plan['estimated_cost'] = await self._calculate_infrastructure_costs(
            optimized_plan['vpc_configuration'],
            optimized_plan['compute_resources'],
            optimized_plan['storage_resources'],
            optimized_plan['database_resources'],
            optimized_plan['eks_configuration']
        )
        
        # Update plan ID
        optimized_plan['plan_id'] = f"{plan['plan_id']}-optimized"
        
        self.logger.info(f"Infrastructure plan optimized: {optimized_plan['plan_id']}")
        return optimized_plan
    
    async def validate_infrastructure_plan(self, plan: InfrastructurePlan) -> List[str]:
        """
        Validate an infrastructure plan for best practices and constraints.
        
        Args:
            plan: Infrastructure plan to validate
            
        Returns:
            List of validation errors and warnings
        """
        self.logger.info(f"Validating infrastructure plan: {plan['plan_id']}")
        
        validation_errors = []
        
        # Validate network configuration
        network_errors = await self._validate_network_configuration(plan['vpc_configuration'])
        validation_errors.extend(network_errors)
        
        # Validate compute configuration
        compute_errors = await self._validate_compute_configuration(plan['compute_resources'])
        validation_errors.extend(compute_errors)
        
        # Validate storage configuration
        storage_errors = await self._validate_storage_configuration(plan['storage_resources'])
        validation_errors.extend(storage_errors)
        
        # Validate EKS configuration
        eks_errors = await self._validate_eks_configuration(plan['eks_configuration'])
        validation_errors.extend(eks_errors)
        
        # Validate security configuration
        security_errors = await self._validate_security_configuration(plan['security_config'])
        validation_errors.extend(security_errors)
        
        # Cost validation
        cost_errors = await self._validate_cost_configuration(plan['estimated_cost'])
        validation_errors.extend(cost_errors)
        
        if validation_errors:
            self.logger.warning(f"Infrastructure plan validation found {len(validation_errors)} issues")
        else:
            self.logger.info("Infrastructure plan validation passed")
        
        return validation_errors
    
    async def generate_alternatives(
        self,
        plan: InfrastructurePlan,
        criteria: Dict[str, Any] = None
    ) -> List[InfrastructurePlan]:
        """
        Generate alternative infrastructure plans.
        
        Args:
            plan: Base infrastructure plan
            criteria: Criteria for generating alternatives
            
        Returns:
            List of alternative plans
        """
        self.logger.info(f"Generating alternatives for plan: {plan['plan_id']}")
        
        alternatives = []
        criteria = criteria or {}
        
        # Generate cost-optimized alternative
        if criteria.get('generate_cost_optimized', True):
            cost_optimized = await self._generate_cost_optimized_alternative(plan)
            alternatives.append(cost_optimized)
        
        # Generate performance-optimized alternative
        if criteria.get('generate_performance_optimized', True):
            performance_optimized = await self._generate_performance_optimized_alternative(plan)
            alternatives.append(performance_optimized)
        
        # Generate high-availability alternative
        if criteria.get('generate_high_availability', True):
            ha_optimized = await self._generate_high_availability_alternative(plan)
            alternatives.append(ha_optimized)
        
        # Generate multi-region alternative
        if criteria.get('generate_multi_region', False):
            multi_region = await self._generate_multi_region_alternative(plan)
            alternatives.append(multi_region)
        
        self.logger.info(f"Generated {len(alternatives)} alternative plans")
        return alternatives
    
    # Private planning methods
    
    async def _plan_network_topology(
        self,
        infra_requirements: InfrastructureRequirement,
        target_environment: str,
        user_requirements: Dict[str, Any]
    ) -> NetworkTopology:
        """Plan network topology and VPC configuration."""
        self.logger.debug("Planning network topology")
        
        # Determine VPC CIDR based on environment
        vpc_cidrs = {
            'dev': '10.0.0.0/16',
            'staging': '10.1.0.0/16',
            'prod': '10.2.0.0/16'
        }
        vpc_cidr = user_requirements.get('vpc_cidr', vpc_cidrs.get(target_environment, '10.0.0.0/16'))
        
        # Get available AZs with fallback
        available_azs = []
        try:
            az_response = self.ec2_client.describe_availability_zones()
            available_azs = [az['ZoneName'] for az in az_response['AvailabilityZones']]
        except Exception as e:
            self.logger.warning(f"Failed to get availability zones from AWS API: {e}")
            # Use fallback AZs based on common AWS regions
            region_azs = {
                'us-east-1': ['us-east-1a', 'us-east-1b', 'us-east-1c'],
                'us-west-2': ['us-west-2a', 'us-west-2b', 'us-west-2c'],
                'eu-west-1': ['eu-west-1a', 'eu-west-1b', 'eu-west-1c'],
                'ap-southeast-1': ['ap-southeast-1a', 'ap-southeast-1b', 'ap-southeast-1c']
            }
            available_azs = region_azs.get(self.config.aws.region, 
                                           [f"{self.config.aws.region}a", f"{self.config.aws.region}b", f"{self.config.aws.region}c"])
        
        # Select AZs based on environment
        if target_environment == 'prod':
            selected_azs = available_azs[:3]  # Use 3 AZs for production
        else:
            selected_azs = available_azs[:2]  # Use 2 AZs for dev/staging
        
        # Calculate subnet CIDRs
        public_subnets = []
        private_subnets = []
        
        for i, az in enumerate(selected_azs):
            # Public subnet
            public_subnets.append({
                'cidr': f"10.{target_environment == 'staging' and 1 or (target_environment == 'prod' and 2 or 0)}.{i}.0/24",
                'availability_zone': az,
                'map_public_ip_on_launch': True,
                'name': f"public-subnet-{i+1}"
            })
            
            # Private subnet
            private_subnets.append({
                'cidr': f"10.{target_environment == 'staging' and 1 or (target_environment == 'prod' and 2 or 0)}.{i+10}.0/24",
                'availability_zone': az,
                'map_public_ip_on_launch': False,
                'name': f"private-subnet-{i+1}"
            })
        
        # Determine number of NAT gateways
        nat_gateways = 1 if target_environment == 'dev' else len(selected_azs)
        
        # VPC endpoints for security and cost optimization
        vpc_endpoints = ['s3', 'ecr.api', 'ecr.dkr', 'logs']
        if target_environment == 'prod':
            vpc_endpoints.extend(['secretsmanager', 'ssm'])
        
        # Route tables
        route_tables = [
            {
                'name': 'public-route-table',
                'subnet_type': 'public',
                'routes': [
                    {'destination': '0.0.0.0/0', 'target': 'internet_gateway'}
                ]
            },
            {
                'name': 'private-route-table',
                'subnet_type': 'private',
                'routes': [
                    {'destination': '0.0.0.0/0', 'target': 'nat_gateway'}
                ]
            }
        ]
        
        return NetworkTopology(
            vpc_cidr=vpc_cidr,
            availability_zones=selected_azs,
            public_subnets=public_subnets,
            private_subnets=private_subnets,
            nat_gateways=nat_gateways,
            internet_gateway=True,
            vpc_endpoints=vpc_endpoints,
            route_tables=route_tables
        )
    
    async def _plan_compute_resources(
        self,
        repository_analysis: RepositoryAnalysis,
        infra_requirements: InfrastructureRequirement,
        target_environment: str
    ) -> ComputeConfiguration:
        """Plan compute resources and auto-scaling configuration."""
        self.logger.debug("Planning compute resources")
        
        app_type = repository_analysis['application_type']
        complexity_score = repository_analysis['complexity_score']
        
        # Base instance type selection
        instance_type_map = {
            'dev': ['t3.micro', 't3.small', 't3.medium'],
            'staging': ['t3.small', 't3.medium', 't3.large'],
            'prod': ['t3.medium', 't3.large', 't3.xlarge']
        }
        
        instance_types = instance_type_map.get(target_environment, ['t3.medium'])
        
        # Adjust for application type
        if app_type == ApplicationType.ML_SERVICE:
            if target_environment == 'prod':
                instance_types = ['m5.large', 'm5.xlarge', 'p3.2xlarge']
            else:
                instance_types = ['m5.large', 't3.xlarge']
        
        elif app_type == ApplicationType.DATA_PIPELINE:
            if target_environment == 'prod':
                instance_types = ['m5.xlarge', 'c5.xlarge', 'r5.xlarge']
            else:
                instance_types = ['m5.large', 'c5.large']
        
        # Scaling configuration
        base_scaling = {
            'dev': {'min': 1, 'max': 3, 'desired': 1},
            'staging': {'min': 1, 'max': 5, 'desired': 2},
            'prod': {'min': 2, 'max': 10, 'desired': 3}
        }
        
        scaling = base_scaling.get(target_environment, base_scaling['dev'])
        
        # Adjust for complexity
        if complexity_score > 0.7:
            scaling['desired'] += 1
            scaling['max'] += 2
        
        # Spot instance configuration
        spot_enabled = target_environment != 'prod'
        spot_percentage = 30 if target_environment == 'staging' else 50
        
        return ComputeConfiguration(
            instance_types=instance_types,
            min_instances=scaling['min'],
            max_instances=scaling['max'],
            desired_instances=scaling['desired'],
            auto_scaling_enabled=True,
            spot_instances_enabled=spot_enabled,
            spot_percentage=spot_percentage if spot_enabled else 0
        )
    
    async def _plan_storage_resources(
        self,
        repository_analysis: RepositoryAnalysis,
        infra_requirements: InfrastructureRequirement,
        target_environment: str
    ) -> List[StorageConfiguration]:
        """Plan storage resources."""
        self.logger.debug("Planning storage resources")
        
        storage_configs = []
        app_type = repository_analysis['application_type']
        
        # Container storage (EBS)
        container_storage = StorageConfiguration(
            storage_type='ebs',
            size_gb=infra_requirements['storage']['size_gb'],
            iops=None,
            throughput=None,
            encryption_enabled=True,
            backup_enabled=target_environment == 'prod',
            retention_days=7 if target_environment == 'dev' else 30
        )
        storage_configs.append(container_storage)
        
        # Application-specific storage
        if app_type == ApplicationType.ML_SERVICE:
            # S3 for model artifacts
            model_storage = StorageConfiguration(
                storage_type='s3',
                size_gb=100,
                encryption_enabled=True,
                backup_enabled=True,
                retention_days=90
            )
            storage_configs.append(model_storage)
        
        elif app_type == ApplicationType.DATA_PIPELINE:
            # S3 for data lake
            data_storage = StorageConfiguration(
                storage_type='s3',
                size_gb=1000,
                encryption_enabled=True,
                backup_enabled=True,
                retention_days=365
            )
            storage_configs.append(data_storage)
        
        # Shared file system if needed
        if app_type in [ApplicationType.WEB_APP, ApplicationType.MICROSERVICE]:
            shared_storage = StorageConfiguration(
                storage_type='efs',
                size_gb=50,
                throughput=100,
                encryption_enabled=True,
                backup_enabled=target_environment == 'prod',
                retention_days=30
            )
            storage_configs.append(shared_storage)
        
        return storage_configs
    
    async def _plan_database_resources(
        self,
        repository_analysis: RepositoryAnalysis,
        infra_requirements: InfrastructureRequirement,
        target_environment: str
    ) -> Optional[DatabaseConfiguration]:
        """Plan database resources if needed."""
        self.logger.debug("Planning database resources")
        
        dependencies = repository_analysis.get('dependencies', [])
        
        # Check if database is needed
        db_dependencies = [
            'postgresql', 'postgres', 'mysql', 'mariadb',
            'mongodb', 'redis', 'elasticsearch', 'dynamodb'
        ]
        
        detected_db = None
        for dep in dependencies:
            dep_lower = dep.lower()
            for db_dep in db_dependencies:
                if db_dep in dep_lower:
                    detected_db = db_dep
                    break
            if detected_db:
                break
        
        if not detected_db:
            return None
        
        # Database configuration based on detected DB
        if detected_db in ['postgresql', 'postgres']:
            engine = 'postgres'
            version = '14.9'
        elif detected_db in ['mysql', 'mariadb']:
            engine = 'mysql'
            version = '8.0.35'
        else:
            # Default to PostgreSQL
            engine = 'postgres'
            version = '14.9'
        
        # Instance class based on environment
        instance_classes = {
            'dev': 'db.t3.micro',
            'staging': 'db.t3.small',
            'prod': 'db.m5.large'
        }
        
        instance_class = instance_classes.get(target_environment, 'db.t3.micro')
        
        # Storage size
        storage_sizes = {
            'dev': 20,
            'staging': 100,
            'prod': 500
        }
        
        allocated_storage = storage_sizes.get(target_environment, 20)
        
        return DatabaseConfiguration(
            engine=engine,
            version=version,
            instance_class=instance_class,
            allocated_storage=allocated_storage,
            multi_az=target_environment == 'prod',
            backup_retention=7 if target_environment == 'dev' else 30,
            encryption=True,
            deletion_protection=target_environment == 'prod'
        )
    
    async def _plan_eks_cluster(
        self,
        repository_analysis: RepositoryAnalysis,
        security_config: SecurityConfiguration,
        target_environment: str
    ) -> Dict[str, Any]:
        """Plan EKS cluster configuration."""
        self.logger.debug("Planning EKS cluster configuration")
        
        # Kubernetes version
        k8s_versions = {
            'dev': '1.28',
            'staging': '1.28',
            'prod': '1.28'
        }
        
        k8s_version = k8s_versions.get(target_environment, '1.28')
        
        # Node group configuration
        node_groups = []
        
        # System node group
        system_node_group = {
            'name': 'system-nodes',
            'instance_types': ['t3.medium'],
            'scaling_config': {
                'min_size': 1,
                'max_size': 3,
                'desired_size': 2
            },
            'ami_type': 'AL2_x86_64',
            'capacity_type': 'ON_DEMAND',
            'disk_size': 20,
            'labels': {
                'node-type': 'system'
            },
            'taints': [
                {
                    'key': 'node-type',
                    'value': 'system',
                    'effect': 'NO_SCHEDULE'
                }
            ]
        }
        node_groups.append(system_node_group)
        
        # Application node group
        app_node_group = {
            'name': 'app-nodes',
            'instance_types': ['t3.medium', 't3.large'],
            'scaling_config': {
                'min_size': 1 if target_environment == 'dev' else 2,
                'max_size': 5 if target_environment == 'dev' else 10,
                'desired_size': 1 if target_environment == 'dev' else 3
            },
            'ami_type': 'AL2_x86_64',
            'capacity_type': 'ON_DEMAND',
            'disk_size': 50,
            'labels': {
                'node-type': 'application'
            }
        }
        node_groups.append(app_node_group)
        
        # Spot instance node group for non-production
        if target_environment != 'prod':
            spot_node_group = {
                'name': 'spot-nodes',
                'instance_types': ['t3.medium', 't3.large', 'm5.large'],
                'scaling_config': {
                    'min_size': 0,
                    'max_size': 5,
                    'desired_size': 1
                },
                'ami_type': 'AL2_x86_64',
                'capacity_type': 'SPOT',
                'disk_size': 50,
                'labels': {
                    'node-type': 'spot'
                }
            }
            node_groups.append(spot_node_group)
        
        # Add-ons
        addons = [
            {
                'name': 'vpc-cni',
                'version': 'latest',
                'resolve_conflicts': 'OVERWRITE'
            },
            {
                'name': 'kube-proxy',
                'version': 'latest',
                'resolve_conflicts': 'OVERWRITE'
            },
            {
                'name': 'coredns',
                'version': 'latest',
                'resolve_conflicts': 'OVERWRITE'
            }
        ]
        
        # Add EBS CSI driver for storage
        if target_environment in ['staging', 'prod']:
            addons.append({
                'name': 'aws-ebs-csi-driver',
                'version': 'latest',
                'resolve_conflicts': 'OVERWRITE'
            })
        
        # Logging configuration
        logging_config = {
            'enable': target_environment in ['staging', 'prod'],
            'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
        }
        
        return {
            'cluster_name': f"eks-{target_environment}-cluster",
            'version': k8s_version,
            'role_arn': f"arn:aws:iam::{self._get_account_id()}:role/eks-cluster-role",
            'node_groups': node_groups,
            'addons': addons,
            'logging': logging_config,
            'endpoint_config': {
                'private_access': True,
                'public_access': target_environment == 'dev',
                'public_access_cidrs': ['0.0.0.0/0'] if target_environment == 'dev' else []
            },
            'encryption_config': {
                'resources': ['secrets'],
                'provider': {
                    'key_id': 'alias/eks-cluster-key'
                }
            }
        }
    
    async def _plan_monitoring_resources(
        self,
        repository_analysis: RepositoryAnalysis,
        target_environment: str
    ) -> Dict[str, Any]:
        """Plan monitoring and observability resources."""
        self.logger.debug("Planning monitoring resources")
        
        monitoring_config = {
            'cloudwatch': {
                'enabled': True,
                'log_groups': [
                    f"/aws/eks/{target_environment}/cluster",
                    f"/aws/lambda/{target_environment}",
                    f"/aws/apigateway/{target_environment}"
                ],
                'metrics': {
                    'namespace': f"EKS/{target_environment}",
                    'detailed_monitoring': target_environment == 'prod'
                }
            },
            'prometheus': {
                'enabled': target_environment in ['staging', 'prod'],
                'namespace': 'prometheus',
                'storage_size': '50Gi',
                'retention': '30d'
            },
            'grafana': {
                'enabled': target_environment in ['staging', 'prod'],
                'namespace': 'grafana',
                'admin_password': 'random_generated',
                'persistence': {
                    'enabled': True,
                    'size': '10Gi'
                }
            },
            'alertmanager': {
                'enabled': target_environment == 'prod',
                'namespace': 'alertmanager',
                'slack_webhook': None,  # To be configured
                'email_config': None   # To be configured
            }
        }
        
        return monitoring_config
    
    def _determine_deployment_strategy(
        self,
        repository_analysis: RepositoryAnalysis,
        target_environment: str
    ) -> DeploymentStrategy:
        """Determine the best deployment strategy."""
        app_type = repository_analysis['application_type']
        
        # Production applications use blue-green by default
        if target_environment == 'prod':
            if app_type in [ApplicationType.WEB_APP, ApplicationType.API_SERVICE]:
                return DeploymentStrategy.BLUE_GREEN
            else:
                return DeploymentStrategy.ROLLING
        
        # Staging uses canary deployment
        elif target_environment == 'staging':
            return DeploymentStrategy.CANARY
        
        # Development uses rolling deployment
        else:
            return DeploymentStrategy.ROLLING
    
    async def _calculate_infrastructure_costs(
        self,
        network_topology: NetworkTopology,
        compute_config: ComputeConfiguration,
        storage_configs: List[StorageConfiguration],
        database_config: Optional[DatabaseConfiguration],
        eks_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate estimated infrastructure costs."""
        self.logger.debug("Calculating infrastructure costs")
        
        monthly_costs = {}
        
        # EKS cluster cost
        monthly_costs['eks_cluster'] = 72.0  # $0.10 per hour
        
        # Compute costs (simplified calculation)
        instance_costs = {
            't3.micro': 7.54,
            't3.small': 15.08,
            't3.medium': 30.17,
            't3.large': 60.34,
            't3.xlarge': 120.67,
            'm5.large': 69.35,
            'm5.xlarge': 138.70,
            'p3.2xlarge': 2188.32
        }
        
        # Calculate compute costs
        primary_instance = compute_config.instance_types[0]
        compute_cost = instance_costs.get(primary_instance, 50.0) * compute_config.desired_instances
        monthly_costs['compute'] = compute_cost
        
        # Storage costs
        storage_cost = 0
        for storage in storage_configs:
            if storage.storage_type == 'ebs':
                storage_cost += storage.size_gb * 0.10  # $0.10/GB/month
            elif storage.storage_type == 's3':
                storage_cost += storage.size_gb * 0.023  # $0.023/GB/month
            elif storage.storage_type == 'efs':
                storage_cost += storage.size_gb * 0.30  # $0.30/GB/month
        
        monthly_costs['storage'] = storage_cost
        
        # Database costs
        if database_config:
            db_costs = {
                'db.t3.micro': 14.60,
                'db.t3.small': 29.20,
                'db.m5.large': 131.40
            }
            monthly_costs['database'] = db_costs.get(database_config.instance_class, 50.0)
        else:
            monthly_costs['database'] = 0.0
        
        # Network costs (simplified)
        nat_gateway_cost = len(network_topology.availability_zones) * 32.85  # $32.85/month per NAT gateway
        monthly_costs['networking'] = nat_gateway_cost
        
        # Monitoring costs
        monthly_costs['monitoring'] = 20.0  # CloudWatch, approximate
        
        # Total
        total_monthly = sum(monthly_costs.values())
        
        return {
            'monthly': total_monthly,
            'breakdown': monthly_costs,
            'currency': 'USD',
            'estimated_on': datetime.utcnow().isoformat()
        }
    
    def _generate_deployment_timeline(
        self,
        network_topology: NetworkTopology,
        compute_config: ComputeConfiguration,
        storage_configs: List[StorageConfiguration],
        database_config: Optional[DatabaseConfiguration],
        eks_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate deployment timeline."""
        timeline = {
            'estimated_duration': '45 minutes',
            'phases': [
                {
                    'name': 'Network Setup',
                    'duration': '10 minutes',
                    'description': 'Create VPC, subnets, route tables'
                },
                {
                    'name': 'Security Setup',
                    'duration': '5 minutes',
                    'description': 'Create security groups, IAM roles'
                },
                {
                    'name': 'EKS Cluster Creation',
                    'duration': '15 minutes',
                    'description': 'Create EKS cluster and node groups'
                },
                {
                    'name': 'Storage Setup',
                    'duration': '5 minutes',
                    'description': 'Create EBS volumes, S3 buckets'
                },
                {
                    'name': 'Application Deployment',
                    'duration': '10 minutes',
                    'description': 'Deploy applications to Kubernetes'
                }
            ]
        }
        
        # Add database phase if needed
        if database_config:
            timeline['phases'].insert(3, {
                'name': 'Database Setup',
                'duration': '10 minutes',
                'description': 'Create RDS instance and configure'
            })
            timeline['estimated_duration'] = '55 minutes'
        
        return timeline
    
    # Resource templates and optimization rules
    
    def _load_resource_templates(self) -> Dict[str, Any]:
        """Load resource templates for different application types."""
        return {
            'web_app': {
                'load_balancer': True,
                'cdn': True,
                'auto_scaling': True,
                'session_affinity': False
            },
            'api_service': {
                'load_balancer': True,
                'cdn': False,
                'auto_scaling': True,
                'session_affinity': False
            },
            'microservice': {
                'service_mesh': True,
                'load_balancer': True,
                'auto_scaling': True,
                'circuit_breaker': True
            },
            'ml_service': {
                'gpu_instances': True,
                'model_storage': True,
                'batch_processing': True,
                'auto_scaling': True
            },
            'data_pipeline': {
                'batch_processing': True,
                'data_storage': True,
                'stream_processing': False,
                'scheduled_jobs': True
            }
        }
    
    def _load_cost_optimization_rules(self) -> List[Dict[str, Any]]:
        """Load cost optimization rules."""
        return [
            {
                'rule': 'use_spot_instances',
                'condition': 'non_production',
                'savings': 0.7,
                'description': 'Use spot instances for non-production workloads'
            },
            {
                'rule': 'rightsizing',
                'condition': 'low_utilization',
                'savings': 0.3,
                'description': 'Right-size instances based on utilization'
            },
            {
                'rule': 'reserved_instances',
                'condition': 'stable_workload',
                'savings': 0.4,
                'description': 'Use reserved instances for stable workloads'
            },
            {
                'rule': 'auto_scaling',
                'condition': 'variable_load',
                'savings': 0.2,
                'description': 'Implement auto-scaling for variable workloads'
            }
        ]
    
    # Optimization methods
    
    async def _optimize_for_cost(self, plan: InfrastructurePlan) -> InfrastructurePlan:
        """Optimize infrastructure plan for cost."""
        # Enable spot instances where possible
        compute_config = plan['compute_resources']
        if not compute_config.spot_instances_enabled:
            compute_config.spot_instances_enabled = True
            compute_config.spot_percentage = 50
        
        # Reduce instance sizes if possible
        current_instances = compute_config.instance_types
        cost_optimized_instances = []
        
        for instance in current_instances:
            if instance.startswith('t3.'):
                size = instance.split('.')[1]
                if size == 'xlarge':
                    cost_optimized_instances.append('t3.large')
                elif size == 'large':
                    cost_optimized_instances.append('t3.medium')
                else:
                    cost_optimized_instances.append(instance)
            else:
                cost_optimized_instances.append(instance)
        
        compute_config.instance_types = cost_optimized_instances
        
        return plan
    
    async def _optimize_for_performance(self, plan: InfrastructurePlan) -> InfrastructurePlan:
        """Optimize infrastructure plan for performance."""
        # Increase instance sizes
        compute_config = plan['compute_resources']
        performance_instances = []
        
        for instance in compute_config.instance_types:
            if instance.startswith('t3.'):
                size = instance.split('.')[1]
                if size == 'micro':
                    performance_instances.append('t3.small')
                elif size == 'small':
                    performance_instances.append('t3.medium')
                elif size == 'medium':
                    performance_instances.append('t3.large')
                else:
                    performance_instances.append(instance)
            else:
                performance_instances.append(instance)
        
        compute_config.instance_types = performance_instances
        
        # Disable spot instances for better performance
        compute_config.spot_instances_enabled = False
        compute_config.spot_percentage = 0
        
        return plan
    
    async def _optimize_for_security(self, plan: InfrastructurePlan) -> InfrastructurePlan:
        """Optimize infrastructure plan for security."""
        # Enable private endpoints
        eks_config = plan['eks_configuration']
        eks_config['endpoint_config']['public_access'] = False
        
        # Enable encryption for all storage
        for storage in plan['storage_resources']:
            storage.encryption_enabled = True
        
        return plan
    
    # Alternative generation methods
    
    async def _generate_cost_optimized_alternative(self, plan: InfrastructurePlan) -> InfrastructurePlan:
        """Generate cost-optimized alternative."""
        alternative = plan.copy()
        alternative['plan_id'] = f"{plan['plan_id']}-cost-optimized"
        
        # Apply cost optimizations
        alternative = await self._optimize_for_cost(alternative)
        
        # Recalculate costs
        alternative['estimated_cost'] = await self._calculate_infrastructure_costs(
            alternative['vpc_configuration'],
            alternative['compute_resources'],
            alternative['storage_resources'],
            alternative['database_resources'],
            alternative['eks_configuration']
        )
        
        return alternative
    
    async def _generate_performance_optimized_alternative(self, plan: InfrastructurePlan) -> InfrastructurePlan:
        """Generate performance-optimized alternative."""
        alternative = plan.copy()
        alternative['plan_id'] = f"{plan['plan_id']}-performance-optimized"
        
        # Apply performance optimizations
        alternative = await self._optimize_for_performance(alternative)
        
        # Recalculate costs
        alternative['estimated_cost'] = await self._calculate_infrastructure_costs(
            alternative['vpc_configuration'],
            alternative['compute_resources'],
            alternative['storage_resources'],
            alternative['database_resources'],
            alternative['eks_configuration']
        )
        
        return alternative
    
    async def _generate_high_availability_alternative(self, plan: InfrastructurePlan) -> InfrastructurePlan:
        """Generate high-availability alternative."""
        alternative = plan.copy()
        alternative['plan_id'] = f"{plan['plan_id']}-high-availability"
        
        # Increase minimum instances
        compute_config = alternative['compute_resources']
        compute_config.min_instances = max(3, compute_config.min_instances * 2)
        compute_config.desired_instances = max(3, compute_config.desired_instances * 2)
        
        # Enable multi-AZ for database
        if alternative['database_resources']:
            alternative['database_resources'].multi_az = True
        
        # Add more availability zones
        network_topology = alternative['vpc_configuration']
        if len(network_topology.availability_zones) < 3:
            # Add third AZ (simplified)
            network_topology.availability_zones.append('us-west-2c')
        
        return alternative
    
    async def _generate_multi_region_alternative(self, plan: InfrastructurePlan) -> InfrastructurePlan:
        """Generate multi-region alternative."""
        alternative = plan.copy()
        alternative['plan_id'] = f"{plan['plan_id']}-multi-region"
        
        # This would involve creating resources in multiple regions
        # For now, just mark it as multi-region
        alternative['multi_region'] = True
        alternative['regions'] = ['us-west-2', 'us-east-1']
        
        return alternative
    
    # Validation methods
    
    async def _validate_network_configuration(self, network_config: NetworkTopology) -> List[str]:
        """Validate network configuration."""
        errors = []
        
        # Check VPC CIDR
        if not network_config.vpc_cidr:
            errors.append("VPC CIDR is required")
        
        # Check subnets
        if not network_config.public_subnets:
            errors.append("At least one public subnet is required")
        
        if not network_config.private_subnets:
            errors.append("At least one private subnet is required")
        
        # Check availability zones
        if len(network_config.availability_zones) < 2:
            errors.append("At least 2 availability zones are required for high availability")
        
        return errors
    
    async def _validate_compute_configuration(self, compute_config: ComputeConfiguration) -> List[str]:
        """Validate compute configuration."""
        errors = []
        
        # Check instance types
        if not compute_config.instance_types:
            errors.append("At least one instance type is required")
        
        # Check scaling configuration
        if compute_config.min_instances > compute_config.max_instances:
            errors.append("Minimum instances cannot be greater than maximum instances")
        
        if compute_config.desired_instances < compute_config.min_instances:
            errors.append("Desired instances cannot be less than minimum instances")
        
        if compute_config.desired_instances > compute_config.max_instances:
            errors.append("Desired instances cannot be greater than maximum instances")
        
        return errors
    
    async def _validate_storage_configuration(self, storage_configs: List[StorageConfiguration]) -> List[str]:
        """Validate storage configuration."""
        errors = []
        
        for storage in storage_configs:
            if storage.size_gb <= 0:
                errors.append(f"Storage size must be positive: {storage.storage_type}")
            
            if storage.storage_type == 'ebs' and storage.size_gb < 1:
                errors.append("EBS volume size must be at least 1 GB")
        
        return errors
    
    async def _validate_eks_configuration(self, eks_config: Dict[str, Any]) -> List[str]:
        """Validate EKS configuration."""
        errors = []
        
        # Check cluster name
        if not eks_config.get('cluster_name'):
            errors.append("EKS cluster name is required")
        
        # Check node groups
        node_groups = eks_config.get('node_groups', [])
        if not node_groups:
            errors.append("At least one node group is required")
        
        for node_group in node_groups:
            if not node_group.get('name'):
                errors.append("Node group name is required")
            
            scaling_config = node_group.get('scaling_config', {})
            if scaling_config.get('min_size', 0) > scaling_config.get('max_size', 0):
                errors.append(f"Node group {node_group.get('name')}: min_size > max_size")
        
        return errors
    
    async def _validate_security_configuration(self, security_config: SecurityConfiguration) -> List[str]:
        """Validate security configuration."""
        errors = []
        
        # Check IAM roles
        iam_roles = security_config.get('iam_roles', [])
        if not iam_roles:
            errors.append("At least one IAM role is required")
        
        # Check security groups
        security_groups = security_config.get('security_groups', [])
        if not security_groups:
            errors.append("At least one security group is required")
        
        return errors
    
    async def _validate_cost_configuration(self, cost_estimate: Dict[str, Any]) -> List[str]:
        """Validate cost configuration."""
        errors = []
        
        monthly_cost = cost_estimate.get('monthly', 0)
        if monthly_cost <= 0:
            errors.append("Monthly cost estimate should be positive")
        
        # Check for unusually high costs
        if monthly_cost > 10000:
            errors.append(f"Monthly cost estimate seems unusually high: ${monthly_cost:.2f}")
        
        return errors
    
    # Utility methods
    
    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        try:
            sts_client = boto3.client('sts')
            return sts_client.get_caller_identity()['Account']
        except Exception:
            return "123456789012"  # Fallback for testing 