"""
Visualization module for infrastructure topology and diagram generation.

This module provides comprehensive visualization capabilities including:
- Infrastructure topology diagrams
- AWS architecture diagrams
- Kubernetes cluster visualizations
- Network topology diagrams
- Monitoring dashboards
- Cost analysis charts
- Deployment flow diagrams
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import base64
from pathlib import Path

from diagrams import Diagram, Edge, Cluster
from diagrams.aws.compute import EKS, EC2, Lambda, ECS
from diagrams.aws.database import RDS, DynamoDB, ElastiCache
from diagrams.aws.network import VPC, PrivateSubnet, PublicSubnet, NATGateway, InternetGateway, ALB, CloudFront
from diagrams.aws.storage import S3, EBS, EFS
from diagrams.aws.security import IAM, SecretsManager, KMS
from diagrams.aws.management import CloudWatch, CloudTrail, SystemsManager
from diagrams.aws.integration import SQS, SNS, EventBridge
from diagrams.k8s.compute import Pod, Deployment, ReplicaSet, StatefulSet
from diagrams.k8s.network import Service, Ingress
from diagrams.k8s.storage import PersistentVolume, PersistentVolumeClaim
from diagrams.k8s.rbac import ServiceAccount, Role, RoleBinding
from diagrams.onprem.monitoring import Prometheus, Grafana

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from PIL import Image

from ..core.state import (
    ApplicationType,
    InfrastructurePlan,
    SecurityConfiguration,
    RepositoryAnalysis
)
from ..core.config import AgentConfig


class DiagramType(Enum):
    """Types of diagrams that can be generated."""
    INFRASTRUCTURE_OVERVIEW = "infrastructure_overview"
    NETWORK_TOPOLOGY = "network_topology"
    SECURITY_ARCHITECTURE = "security_architecture"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    APPLICATION_FLOW = "application_flow"
    MONITORING_SETUP = "monitoring_setup"
    COST_ANALYSIS = "cost_analysis"
    DEPLOYMENT_PIPELINE = "deployment_pipeline"


class OutputFormat(Enum):
    """Output formats for diagrams."""
    PNG = "png"
    SVG = "svg"
    PDF = "pdf"
    HTML = "html"
    JSON = "json"


@dataclass
class DiagramConfig:
    """Configuration for diagram generation."""
    diagram_type: DiagramType
    output_format: OutputFormat
    output_path: str
    title: str
    description: Optional[str] = None
    show_details: bool = True
    include_costs: bool = False
    include_security: bool = True
    theme: str = "default"
    size: Tuple[int, int] = (1200, 800)


@dataclass
class VisualizationResult:
    """Result of visualization generation."""
    diagram_type: DiagramType
    output_files: List[str]
    metadata: Dict[str, Any]
    generated_at: datetime
    file_sizes: Dict[str, int]


class InfrastructureVisualizer:
    """
    Comprehensive infrastructure visualization and diagram generation.
    
    Creates visual representations of AWS infrastructure, Kubernetes clusters,
    network topologies, and application architectures.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the Infrastructure Visualizer.
        
        Args:
            config: Agent configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Output directory for diagrams
        self.output_dir = Path(config.workspace) / "diagrams"
        self.output_dir.mkdir(exist_ok=True)
        
        # Style configurations
        self.color_scheme = {
            'primary': '#0066cc',
            'secondary': '#ff6600',
            'success': '#28a745',
            'warning': '#ffc107',
            'danger': '#dc3545',
            'info': '#17a2b8'
        }
        
        # Cost thresholds for visualization
        self.cost_thresholds = {
            'low': 100,
            'medium': 500,
            'high': 1000
        }
        
        self.logger.info("Infrastructure Visualizer initialized")
    
    async def generate_infrastructure_overview(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration,
        config: DiagramConfig
    ) -> VisualizationResult:
        """
        Generate comprehensive infrastructure overview diagram.
        
        Args:
            infrastructure_plan: Infrastructure plan to visualize
            security_config: Security configuration
            config: Diagram configuration
            
        Returns:
            Visualization result
        """
        self.logger.info("Generating infrastructure overview diagram")
        
        output_file = self.output_dir / f"infrastructure_overview.{config.output_format.value}"
        
        with Diagram(
            config.title,
            filename=str(output_file.with_suffix('')),
            outformat=config.output_format.value,
            show=False,
            direction="TB"
        ):
            # Internet Gateway
            igw = InternetGateway("Internet Gateway")
            
            # VPC
            with Cluster("VPC"):
                vpc_config = infrastructure_plan['vpc_configuration']
                
                # Public subnets
                with Cluster("Public Subnets"):
                    public_subnets = []
                    for i, subnet in enumerate(vpc_config.public_subnets):
                        subnet_node = PublicSubnet(f"Public Subnet {i+1}\n{subnet['availability_zone']}")
                        public_subnets.append(subnet_node)
                
                # NAT Gateway
                nat_gateway = NATGateway("NAT Gateway")
                
                # Private subnets
                with Cluster("Private Subnets"):
                    private_subnets = []
                    for i, subnet in enumerate(vpc_config.private_subnets):
                        subnet_node = PrivateSubnet(f"Private Subnet {i+1}\n{subnet['availability_zone']}")
                        private_subnets.append(subnet_node)
                
                # EKS Cluster
                with Cluster("EKS Cluster"):
                    eks_cluster = EKS("EKS Control Plane")
                    
                    # Node groups
                    node_groups = []
                    for node_group in infrastructure_plan['eks_configuration']['node_groups']:
                        node_group_node = EC2(f"Node Group: {node_group['name']}")
                        node_groups.append(node_group_node)
                        eks_cluster >> node_group_node
                
                # Database (if exists)
                if infrastructure_plan.get('database_resources'):
                    db_config = infrastructure_plan['database_resources']
                    database = RDS(f"RDS {db_config.engine}")
                    private_subnets[0] >> database
                
                # Storage
                storage_resources = infrastructure_plan.get('storage_resources', [])
                storage_nodes = []
                for storage in storage_resources:
                    if storage.storage_type == 'ebs':
                        storage_node = EBS(f"EBS Volume\n{storage.size_gb}GB")
                    elif storage.storage_type == 's3':
                        storage_node = S3(f"S3 Bucket\n{storage.size_gb}GB")
                    elif storage.storage_type == 'efs':
                        storage_node = EFS(f"EFS\n{storage.size_gb}GB")
                    else:
                        continue
                    storage_nodes.append(storage_node)
                
                # Load Balancer
                alb = ALB("Application Load Balancer")
                
                # Connections
                igw >> public_subnets[0]
                public_subnets[0] >> nat_gateway
                nat_gateway >> private_subnets[0]
                private_subnets[0] >> eks_cluster
                alb >> eks_cluster
        
        # Generate metadata
        metadata = {
            'vpc_cidr': vpc_config.vpc_cidr,
            'availability_zones': len(vpc_config.availability_zones),
            'public_subnets': len(vpc_config.public_subnets),
            'private_subnets': len(vpc_config.private_subnets),
            'node_groups': len(infrastructure_plan['eks_configuration']['node_groups']),
            'estimated_monthly_cost': infrastructure_plan['estimated_cost']['monthly']
        }
        
        result = VisualizationResult(
            diagram_type=DiagramType.INFRASTRUCTURE_OVERVIEW,
            output_files=[str(output_file)],
            metadata=metadata,
            generated_at=datetime.utcnow(),
            file_sizes={str(output_file): output_file.stat().st_size if output_file.exists() else 0}
        )
        
        self.logger.info(f"Infrastructure overview diagram generated: {output_file}")
        return result
    
    async def generate_network_topology(
        self,
        infrastructure_plan: InfrastructurePlan,
        config: DiagramConfig
    ) -> VisualizationResult:
        """
        Generate network topology diagram.
        
        Args:
            infrastructure_plan: Infrastructure plan
            config: Diagram configuration
            
        Returns:
            Visualization result
        """
        self.logger.info("Generating network topology diagram")
        
        output_file = self.output_dir / f"network_topology.{config.output_format.value}"
        
        with Diagram(
            config.title,
            filename=str(output_file.with_suffix('')),
            outformat=config.output_format.value,
            show=False,
            direction="LR"
        ):
            vpc_config = infrastructure_plan['vpc_configuration']
            
            # Internet
            internet = InternetGateway("Internet")
            
            # VPC
            with Cluster(f"VPC ({vpc_config.vpc_cidr})"):
                # Internet Gateway
                igw = InternetGateway("IGW")
                
                # Public Route Table
                with Cluster("Public Route Table"):
                    public_rt = PublicSubnet("Public RT")
                
                # Private Route Table
                with Cluster("Private Route Table"):
                    private_rt = PrivateSubnet("Private RT")
                
                # NAT Gateway
                nat_gw = NATGateway("NAT GW")
                
                # Availability Zones
                for i, az in enumerate(vpc_config.availability_zones):
                    with Cluster(f"AZ: {az}"):
                        # Public subnet
                        public_subnet = PublicSubnet(f"Public\n{vpc_config.public_subnets[i]['cidr']}")
                        
                        # Private subnet
                        private_subnet = PrivateSubnet(f"Private\n{vpc_config.private_subnets[i]['cidr']}")
                        
                        # EKS Nodes
                        eks_nodes = EC2(f"EKS Nodes")
                        
                        # Connections
                        public_rt >> public_subnet
                        private_rt >> private_subnet
                        private_subnet >> eks_nodes
                        if i == 0:  # NAT Gateway in first AZ
                            public_subnet >> nat_gw
                            nat_gw >> private_rt
                
                # VPC Endpoints
                if vpc_config.vpc_endpoints:
                    with Cluster("VPC Endpoints"):
                        for endpoint in vpc_config.vpc_endpoints:
                            endpoint_node = EC2(f"VPC Endpoint\n{endpoint}")
                            private_rt >> endpoint_node
                
                # Route connections
                internet >> igw
                igw >> public_rt
        
        metadata = {
            'vpc_cidr': vpc_config.vpc_cidr,
            'availability_zones': vpc_config.availability_zones,
            'nat_gateways': vpc_config.nat_gateways,
            'vpc_endpoints': vpc_config.vpc_endpoints
        }
        
        result = VisualizationResult(
            diagram_type=DiagramType.NETWORK_TOPOLOGY,
            output_files=[str(output_file)],
            metadata=metadata,
            generated_at=datetime.utcnow(),
            file_sizes={str(output_file): output_file.stat().st_size if output_file.exists() else 0}
        )
        
        self.logger.info(f"Network topology diagram generated: {output_file}")
        return result
    
    async def generate_security_architecture(
        self,
        security_config: SecurityConfiguration,
        config: DiagramConfig
    ) -> VisualizationResult:
        """
        Generate security architecture diagram.
        
        Args:
            security_config: Security configuration
            config: Diagram configuration
            
        Returns:
            Visualization result
        """
        self.logger.info("Generating security architecture diagram")
        
        output_file = self.output_dir / f"security_architecture.{config.output_format.value}"
        
        with Diagram(
            config.title,
            filename=str(output_file.with_suffix('')),
            outformat=config.output_format.value,
            show=False,
            direction="TB"
        ):
            # IAM
            with Cluster("Identity and Access Management"):
                iam_roles = []
                for role in security_config.get('iam_roles', []):
                    iam_role = IAM(f"IAM Role\n{role['name']}")
                    iam_roles.append(iam_role)
            
            # Security Groups
            with Cluster("Network Security"):
                security_groups = []
                for sg in security_config.get('security_groups', []):
                    sg_node = EC2(f"Security Group\n{sg['name']}")
                    security_groups.append(sg_node)
            
            # Encryption
            with Cluster("Data Protection"):
                encryption_config = security_config.get('encryption_config', {})
                
                if encryption_config.get('ebs_encryption'):
                    ebs_encryption = KMS("EBS Encryption")
                
                if encryption_config.get('s3_encryption'):
                    s3_encryption = KMS("S3 Encryption")
                
                if encryption_config.get('secrets_encryption'):
                    secrets_encryption = SecretsManager("Secrets Manager")
            
            # Monitoring
            with Cluster("Security Monitoring"):
                monitoring_config = security_config.get('monitoring_config', {})
                
                if monitoring_config.get('cloudtrail_enabled'):
                    cloudtrail = CloudTrail("CloudTrail")
                
                if monitoring_config.get('config_enabled'):
                    config_service = SystemsManager("AWS Config")
                
                if monitoring_config.get('cloudwatch_enabled'):
                    cloudwatch = CloudWatch("CloudWatch")
        
        metadata = {
            'iam_roles': len(security_config.get('iam_roles', [])),
            'security_groups': len(security_config.get('security_groups', [])),
            'encryption_enabled': security_config.get('encryption_config', {}).get('ebs_encryption', False),
            'monitoring_enabled': security_config.get('monitoring_config', {}).get('cloudtrail_enabled', False)
        }
        
        result = VisualizationResult(
            diagram_type=DiagramType.SECURITY_ARCHITECTURE,
            output_files=[str(output_file)],
            metadata=metadata,
            generated_at=datetime.utcnow(),
            file_sizes={str(output_file): output_file.stat().st_size if output_file.exists() else 0}
        )
        
        self.logger.info(f"Security architecture diagram generated: {output_file}")
        return result
    
    async def generate_kubernetes_cluster(
        self,
        infrastructure_plan: InfrastructurePlan,
        config: DiagramConfig
    ) -> VisualizationResult:
        """
        Generate Kubernetes cluster diagram.
        
        Args:
            infrastructure_plan: Infrastructure plan
            config: Diagram configuration
            
        Returns:
            Visualization result
        """
        self.logger.info("Generating Kubernetes cluster diagram")
        
        output_file = self.output_dir / f"kubernetes_cluster.{config.output_format.value}"
        
        with Diagram(
            config.title,
            filename=str(output_file.with_suffix('')),
            outformat=config.output_format.value,
            show=False,
            direction="TB"
        ):
            eks_config = infrastructure_plan['eks_configuration']
            
            # EKS Control Plane
            with Cluster("EKS Control Plane"):
                control_plane = EKS(f"EKS Cluster\n{eks_config['cluster_name']}")
                
                # API Server
                api_server = Pod("API Server")
                control_plane >> api_server
            
            # Node Groups
            for node_group in eks_config['node_groups']:
                with Cluster(f"Node Group: {node_group['name']}"):
                    # Worker Nodes
                    for i in range(node_group['scaling_config']['desired_size']):
                        worker_node = EC2(f"Worker Node {i+1}")
                        
                        # Pods
                        with Cluster(f"Pods - Node {i+1}"):
                            pod1 = Pod("Application Pod")
                            pod2 = Pod("System Pod")
                            worker_node >> [pod1, pod2]
                        
                        control_plane >> worker_node
            
            # Add-ons
            if eks_config.get('addons'):
                with Cluster("Add-ons"):
                    for addon in eks_config['addons']:
                        addon_pod = Pod(f"{addon['name']}")
                        control_plane >> addon_pod
            
            # Services
            with Cluster("Services"):
                # Application Service
                app_service = Service("Application Service")
                
                # Load Balancer
                load_balancer = ALB("Load Balancer")
                
                # Ingress
                ingress = Ingress("Ingress Controller")
                
                load_balancer >> ingress >> app_service
            
            # Storage
            with Cluster("Storage"):
                # Persistent Volumes
                pv = PersistentVolume("Persistent Volume")
                pvc = PersistentVolumeClaim("PVC")
                
                pv >> pvc
            
            # Monitoring
            with Cluster("Monitoring"):
                prometheus = Prometheus("Prometheus")
                grafana = Grafana("Grafana")
                
                prometheus >> grafana
        
        metadata = {
            'cluster_name': eks_config['cluster_name'],
            'kubernetes_version': eks_config['version'],
            'node_groups': len(eks_config['node_groups']),
            'addons': len(eks_config.get('addons', [])),
            'total_nodes': sum(ng['scaling_config']['desired_size'] for ng in eks_config['node_groups'])
        }
        
        result = VisualizationResult(
            diagram_type=DiagramType.KUBERNETES_CLUSTER,
            output_files=[str(output_file)],
            metadata=metadata,
            generated_at=datetime.utcnow(),
            file_sizes={str(output_file): output_file.stat().st_size if output_file.exists() else 0}
        )
        
        self.logger.info(f"Kubernetes cluster diagram generated: {output_file}")
        return result
    
    async def generate_cost_analysis_chart(
        self,
        infrastructure_plan: InfrastructurePlan,
        config: DiagramConfig
    ) -> VisualizationResult:
        """
        Generate cost analysis chart.
        
        Args:
            infrastructure_plan: Infrastructure plan
            config: Diagram configuration
            
        Returns:
            Visualization result
        """
        self.logger.info("Generating cost analysis chart")
        
        output_file = self.output_dir / f"cost_analysis.{config.output_format.value}"
        
        # Extract cost data
        cost_data = infrastructure_plan['estimated_cost']['breakdown']
        
        # Create cost breakdown pie chart
        plt.figure(figsize=(12, 8))
        
        # Pie chart
        plt.subplot(2, 2, 1)
        sizes = list(cost_data.values())
        labels = list(cost_data.keys())
        colors = plt.cm.Set3(range(len(labels)))
        
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title('Cost Breakdown by Service')
        
        # Bar chart
        plt.subplot(2, 2, 2)
        plt.bar(labels, sizes, color=colors)
        plt.title('Monthly Cost by Service')
        plt.ylabel('Cost ($)')
        plt.xticks(rotation=45)
        
        # Cost trend (projected)
        plt.subplot(2, 2, 3)
        months = ['Month 1', 'Month 2', 'Month 3', 'Month 6', 'Month 12']
        total_cost = sum(sizes)
        projected_costs = [total_cost * (1 + i * 0.1) for i in range(len(months))]
        
        plt.plot(months, projected_costs, marker='o', linewidth=2, markersize=8)
        plt.title('Projected Cost Trend')
        plt.ylabel('Total Cost ($)')
        plt.xticks(rotation=45)
        
        # Cost optimization opportunities
        plt.subplot(2, 2, 4)
        optimization_savings = {
            'Spot Instances': total_cost * 0.3,
            'Reserved Instances': total_cost * 0.2,
            'Right-sizing': total_cost * 0.15,
            'Auto-scaling': total_cost * 0.1
        }
        
        opt_labels = list(optimization_savings.keys())
        opt_savings = list(optimization_savings.values())
        
        plt.barh(opt_labels, opt_savings, color='green', alpha=0.7)
        plt.title('Potential Monthly Savings')
        plt.xlabel('Savings ($)')
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        metadata = {
            'total_monthly_cost': total_cost,
            'highest_cost_service': max(cost_data, key=cost_data.get),
            'potential_savings': sum(optimization_savings.values()),
            'cost_categories': len(cost_data)
        }
        
        result = VisualizationResult(
            diagram_type=DiagramType.COST_ANALYSIS,
            output_files=[str(output_file)],
            metadata=metadata,
            generated_at=datetime.utcnow(),
            file_sizes={str(output_file): output_file.stat().st_size if output_file.exists() else 0}
        )
        
        self.logger.info(f"Cost analysis chart generated: {output_file}")
        return result
    
    async def generate_deployment_pipeline(
        self,
        repository_analysis: RepositoryAnalysis,
        infrastructure_plan: InfrastructurePlan,
        config: DiagramConfig
    ) -> VisualizationResult:
        """
        Generate deployment pipeline diagram.
        
        Args:
            repository_analysis: Repository analysis
            infrastructure_plan: Infrastructure plan
            config: Diagram configuration
            
        Returns:
            Visualization result
        """
        self.logger.info("Generating deployment pipeline diagram")
        
        output_file = self.output_dir / f"deployment_pipeline.{config.output_format.value}"
        
        with Diagram(
            config.title,
            filename=str(output_file.with_suffix('')),
            outformat=config.output_format.value,
            show=False,
            direction="LR"
        ):
            # Source Code
            with Cluster("Source Control"):
                source_code = Lambda(f"Repository\n{repository_analysis['name']}")
            
            # CI/CD Pipeline
            with Cluster("CI/CD Pipeline"):
                build = Lambda("Build")
                test = Lambda("Test")
                security_scan = Lambda("Security Scan")
                
                source_code >> build >> test >> security_scan
            
            # Container Registry
            with Cluster("Container Registry"):
                ecr = ECS("ECR")
                security_scan >> ecr
            
            # Infrastructure Deployment
            with Cluster("Infrastructure"):
                # EKS Cluster
                eks_cluster = EKS("EKS Cluster")
                
                # Application Deployment
                app_deployment = Pod("Application")
                
                ecr >> eks_cluster >> app_deployment
            
            # Monitoring
            with Cluster("Monitoring"):
                monitoring = CloudWatch("CloudWatch")
                app_deployment >> monitoring
        
        metadata = {
            'repository_name': repository_analysis['name'],
            'language': repository_analysis['language'],
            'framework': repository_analysis['framework'],
            'deployment_strategy': infrastructure_plan.get('deployment_strategy', 'rolling_update')
        }
        
        result = VisualizationResult(
            diagram_type=DiagramType.DEPLOYMENT_PIPELINE,
            output_files=[str(output_file)],
            metadata=metadata,
            generated_at=datetime.utcnow(),
            file_sizes={str(output_file): output_file.stat().st_size if output_file.exists() else 0}
        )
        
        self.logger.info(f"Deployment pipeline diagram generated: {output_file}")
        return result
    
    async def generate_monitoring_dashboard(
        self,
        infrastructure_plan: InfrastructurePlan,
        config: DiagramConfig
    ) -> VisualizationResult:
        """
        Generate monitoring setup diagram.
        
        Args:
            infrastructure_plan: Infrastructure plan
            config: Diagram configuration
            
        Returns:
            Visualization result
        """
        self.logger.info("Generating monitoring dashboard diagram")
        
        output_file = self.output_dir / f"monitoring_setup.{config.output_format.value}"
        
        with Diagram(
            config.title,
            filename=str(output_file.with_suffix('')),
            outformat=config.output_format.value,
            show=False,
            direction="TB"
        ):
            # Data Sources
            with Cluster("Data Sources"):
                # EKS Cluster
                eks_cluster = EKS("EKS Cluster")
                
                # Applications
                applications = Pod("Applications")
                
                # AWS Services
                aws_services = CloudWatch("AWS Services")
                
                eks_cluster >> applications
            
            # Metrics Collection
            with Cluster("Metrics Collection"):
                prometheus = Prometheus("Prometheus")
                cloudwatch = CloudWatch("CloudWatch")
                
                applications >> prometheus
                aws_services >> cloudwatch
            
            # Visualization
            with Cluster("Visualization"):
                grafana = Grafana("Grafana")
                
                prometheus >> grafana
                cloudwatch >> grafana
            
            # Alerting
            with Cluster("Alerting"):
                alertmanager = Prometheus("AlertManager")
                sns = SNS("SNS")
                
                prometheus >> alertmanager >> sns
            
            # Log Management
            with Cluster("Log Management"):
                log_aggregator = CloudWatch("Log Aggregator")
                
                applications >> log_aggregator
        
        metadata = {
            'monitoring_enabled': True,
            'prometheus_enabled': True,
            'grafana_enabled': True,
            'alerting_enabled': True,
            'log_aggregation_enabled': True
        }
        
        result = VisualizationResult(
            diagram_type=DiagramType.MONITORING_SETUP,
            output_files=[str(output_file)],
            metadata=metadata,
            generated_at=datetime.utcnow(),
            file_sizes={str(output_file): output_file.stat().st_size if output_file.exists() else 0}
        )
        
        self.logger.info(f"Monitoring dashboard diagram generated: {output_file}")
        return result
    
    async def generate_all_diagrams(
        self,
        repository_analysis: RepositoryAnalysis,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration
    ) -> List[VisualizationResult]:
        """
        Generate all types of diagrams.
        
        Args:
            repository_analysis: Repository analysis
            infrastructure_plan: Infrastructure plan
            security_config: Security configuration
            
        Returns:
            List of visualization results
        """
        self.logger.info("Generating all infrastructure diagrams")
        
        results = []
        
        # Infrastructure Overview
        overview_config = DiagramConfig(
            diagram_type=DiagramType.INFRASTRUCTURE_OVERVIEW,
            output_format=OutputFormat.PNG,
            output_path=str(self.output_dir),
            title="Infrastructure Overview",
            description="Complete AWS infrastructure architecture"
        )
        overview_result = await self.generate_infrastructure_overview(
            infrastructure_plan, security_config, overview_config
        )
        results.append(overview_result)
        
        # Network Topology
        network_config = DiagramConfig(
            diagram_type=DiagramType.NETWORK_TOPOLOGY,
            output_format=OutputFormat.PNG,
            output_path=str(self.output_dir),
            title="Network Topology",
            description="VPC and networking architecture"
        )
        network_result = await self.generate_network_topology(
            infrastructure_plan, network_config
        )
        results.append(network_result)
        
        # Security Architecture
        security_config_diag = DiagramConfig(
            diagram_type=DiagramType.SECURITY_ARCHITECTURE,
            output_format=OutputFormat.PNG,
            output_path=str(self.output_dir),
            title="Security Architecture",
            description="Security controls and compliance"
        )
        security_result = await self.generate_security_architecture(
            security_config, security_config_diag
        )
        results.append(security_result)
        
        # Kubernetes Cluster
        k8s_config = DiagramConfig(
            diagram_type=DiagramType.KUBERNETES_CLUSTER,
            output_format=OutputFormat.PNG,
            output_path=str(self.output_dir),
            title="Kubernetes Cluster",
            description="EKS cluster architecture"
        )
        k8s_result = await self.generate_kubernetes_cluster(
            infrastructure_plan, k8s_config
        )
        results.append(k8s_result)
        
        # Cost Analysis
        cost_config = DiagramConfig(
            diagram_type=DiagramType.COST_ANALYSIS,
            output_format=OutputFormat.PNG,
            output_path=str(self.output_dir),
            title="Cost Analysis",
            description="Infrastructure cost breakdown and optimization"
        )
        cost_result = await self.generate_cost_analysis_chart(
            infrastructure_plan, cost_config
        )
        results.append(cost_result)
        
        # Deployment Pipeline
        pipeline_config = DiagramConfig(
            diagram_type=DiagramType.DEPLOYMENT_PIPELINE,
            output_format=OutputFormat.PNG,
            output_path=str(self.output_dir),
            title="Deployment Pipeline",
            description="CI/CD and deployment workflow"
        )
        pipeline_result = await self.generate_deployment_pipeline(
            repository_analysis, infrastructure_plan, pipeline_config
        )
        results.append(pipeline_result)
        
        # Monitoring Setup
        monitoring_config = DiagramConfig(
            diagram_type=DiagramType.MONITORING_SETUP,
            output_format=OutputFormat.PNG,
            output_path=str(self.output_dir),
            title="Monitoring Setup",
            description="Monitoring and observability architecture"
        )
        monitoring_result = await self.generate_monitoring_dashboard(
            infrastructure_plan, monitoring_config
        )
        results.append(monitoring_result)
        
        self.logger.info(f"Generated {len(results)} diagrams successfully")
        return results
    
    async def create_summary_report(
        self,
        visualization_results: List[VisualizationResult],
        infrastructure_plan: InfrastructurePlan
    ) -> str:
        """
        Create a summary report with all diagrams.
        
        Args:
            visualization_results: List of visualization results
            infrastructure_plan: Infrastructure plan
            
        Returns:
            Path to summary report
        """
        self.logger.info("Creating summary report")
        
        report_file = self.output_dir / "infrastructure_summary.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Infrastructure Summary Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .diagram-section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                .diagram-title {{ font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
                .diagram-image {{ max-width: 100%; height: auto; border: 1px solid #ccc; }}
                .metadata {{ background-color: #f9f9f9; padding: 10px; margin-top: 10px; border-radius: 3px; }}
                .cost-summary {{ background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Infrastructure Summary Report</h1>
                <p>Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
                <p>Plan ID: {infrastructure_plan.get('plan_id', 'N/A')}</p>
            </div>
            
            <div class="cost-summary">
                <h2>Cost Summary</h2>
                <p><strong>Estimated Monthly Cost:</strong> ${infrastructure_plan['estimated_cost']['monthly']:.2f}</p>
                <p><strong>Deployment Timeline:</strong> {infrastructure_plan['deployment_timeline']['estimated_duration']}</p>
            </div>
        """
        
        # Add each diagram section
        for result in visualization_results:
            html_content += f"""
            <div class="diagram-section">
                <div class="diagram-title">{result.diagram_type.value.replace('_', ' ').title()}</div>
                <img src="{os.path.basename(result.output_files[0])}" alt="{result.diagram_type.value}" class="diagram-image">
                <div class="metadata">
                    <strong>Metadata:</strong><br>
                    {self._format_metadata(result.metadata)}
                </div>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        # Write HTML report
        with open(report_file, 'w') as f:
            f.write(html_content)
        
        self.logger.info(f"Summary report created: {report_file}")
        return str(report_file)
    
    def _format_metadata(self, metadata: Dict[str, Any]) -> str:
        """Format metadata for HTML display."""
        formatted = []
        for key, value in metadata.items():
            if isinstance(value, (list, dict)):
                value = json.dumps(value, indent=2)
            formatted.append(f"{key}: {value}")
        return "<br>".join(formatted)
    
    async def cleanup_old_diagrams(self, days_old: int = 7):
        """
        Clean up old diagram files.
        
        Args:
            days_old: Number of days after which to delete files
        """
        self.logger.info(f"Cleaning up diagrams older than {days_old} days")
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        cleaned_files = 0
        
        for file_path in self.output_dir.glob("*"):
            if file_path.is_file():
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_mtime < cutoff_date:
                    file_path.unlink()
                    cleaned_files += 1
        
        self.logger.info(f"Cleaned up {cleaned_files} old diagram files")
        return cleaned_files 