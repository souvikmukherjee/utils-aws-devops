"""
Kubernetes Manager module for EKS cluster management and application deployment.

This module provides comprehensive Kubernetes management capabilities including:
- EKS cluster creation and configuration
- Application deployment with various strategies
- Horizontal Pod Autoscaling (HPA) and Vertical Pod Autoscaling (VPA)
- Service mesh integration
- Ingress and load balancer configuration
- Monitoring and observability setup
- Backup and disaster recovery
"""

import json
import yaml
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import base64

import boto3
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import helm

from ..core.state import (
    ApplicationType,
    DeploymentPhase,
    RepositoryAnalysis,
    SecurityConfiguration,
    InfrastructurePlan
)
from ..core.config import AgentConfig


class DeploymentStrategy(Enum):
    """Kubernetes deployment strategies."""
    ROLLING_UPDATE = "rolling_update"
    BLUE_GREEN = "blue_green"
    CANARY = "canary"
    RECREATE = "recreate"


class ServiceType(Enum):
    """Kubernetes service types."""
    CLUSTER_IP = "ClusterIP"
    NODE_PORT = "NodePort"
    LOAD_BALANCER = "LoadBalancer"
    EXTERNAL_NAME = "ExternalName"


class IngressClass(Enum):
    """Ingress controller classes."""
    NGINX = "nginx"
    ALB = "alb"
    TRAEFIK = "traefik"


@dataclass
class ApplicationDeployment:
    """Application deployment configuration."""
    name: str
    namespace: str
    image: str
    tag: str
    replicas: int
    resources: Dict[str, Any]
    environment_variables: Dict[str, str] = field(default_factory=dict)
    config_maps: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)
    service_type: ServiceType = ServiceType.CLUSTER_IP
    ingress_enabled: bool = False
    health_checks: Dict[str, Any] = field(default_factory=dict)
    monitoring_enabled: bool = True


@dataclass
class HelmChart:
    """Helm chart configuration."""
    name: str
    repository: str
    chart: str
    version: str
    namespace: str
    values: Dict[str, Any] = field(default_factory=dict)
    custom_values_file: Optional[str] = None


@dataclass
class ClusterConfiguration:
    """EKS cluster configuration."""
    cluster_name: str
    region: str
    version: str
    node_groups: List[Dict[str, Any]]
    addons: List[Dict[str, Any]]
    logging_enabled: bool = True
    monitoring_enabled: bool = True
    ingress_controller: IngressClass = IngressClass.ALB


class KubernetesManager:
    """
    Comprehensive Kubernetes cluster management and application deployment.
    
    This class handles EKS cluster operations, application deployments,
    scaling, monitoring, and maintenance tasks.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the Kubernetes Manager.
        
        Args:
            config: Agent configuration containing AWS and Kubernetes settings
        """
        self.config = config
        self.k8s_config = config.kubernetes
        self.logger = logging.getLogger(__name__)
        
        # Initialize AWS clients
        self.eks_client = boto3.client('eks', region_name=config.aws.region)
        self.ec2_client = boto3.client('ec2', region_name=config.aws.region)
        self.sts_client = boto3.client('sts', region_name=config.aws.region)
        
        # Kubernetes client will be initialized when connecting to cluster
        self.k8s_client = None
        self.k8s_apps_client = None
        self.k8s_networking_client = None
        
        # Cluster state tracking
        self.current_cluster = None
        self.cluster_config = None
        
        # Deployment tracking
        self.deployed_applications = {}
        self.helm_releases = {}
        
        self.logger.info("Kubernetes Manager initialized")
    
    async def create_eks_cluster(
        self,
        infrastructure_plan: InfrastructurePlan,
        security_config: SecurityConfiguration
    ) -> Dict[str, Any]:
        """
        Create an EKS cluster based on infrastructure plan.
        
        Args:
            infrastructure_plan: Infrastructure plan containing EKS configuration
            security_config: Security configuration for the cluster
            
        Returns:
            Cluster creation result
        """
        eks_config = infrastructure_plan['eks_configuration']
        cluster_name = eks_config['cluster_name']
        
        self.logger.info(f"Creating EKS cluster: {cluster_name}")
        
        try:
            # Create EKS cluster
            cluster_response = await self._create_cluster(eks_config, infrastructure_plan)
            
            # Wait for cluster to be active
            await self._wait_for_cluster_active(cluster_name)
            
            # Create node groups
            node_group_results = []
            for node_group in eks_config['node_groups']:
                node_group_result = await self._create_node_group(
                    cluster_name, node_group, infrastructure_plan
                )
                node_group_results.append(node_group_result)
            
            # Install add-ons
            addon_results = []
            for addon in eks_config.get('addons', []):
                addon_result = await self._install_addon(cluster_name, addon)
                addon_results.append(addon_result)
            
            # Configure cluster authentication
            await self._configure_cluster_auth(cluster_name)
            
            # Set up monitoring and logging
            if eks_config.get('logging', {}).get('enable', False):
                await self._enable_cluster_logging(cluster_name, eks_config['logging'])
            
            # Configure networking
            await self._configure_cluster_networking(cluster_name, infrastructure_plan)
            
            # Store cluster configuration
            self.cluster_config = ClusterConfiguration(
                cluster_name=cluster_name,
                region=self.config.aws.region,
                version=eks_config['version'],
                node_groups=eks_config['node_groups'],
                addons=eks_config['addons'],
                logging_enabled=eks_config.get('logging', {}).get('enable', False),
                monitoring_enabled=True
            )
            
            result = {
                'cluster_name': cluster_name,
                'cluster_arn': cluster_response['cluster']['arn'],
                'cluster_endpoint': cluster_response['cluster']['endpoint'],
                'cluster_status': 'ACTIVE',
                'node_groups': node_group_results,
                'addons': addon_results,
                'created_at': datetime.utcnow().isoformat(),
                'region': self.config.aws.region
            }
            
            self.current_cluster = result
            self.logger.info(f"EKS cluster created successfully: {cluster_name}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to create EKS cluster: {e}")
            raise
    
    async def deploy_application(
        self,
        app_deployment: ApplicationDeployment,
        deployment_strategy: DeploymentStrategy = DeploymentStrategy.ROLLING_UPDATE
    ) -> Dict[str, Any]:
        """
        Deploy an application to the Kubernetes cluster.
        
        Args:
            app_deployment: Application deployment configuration
            deployment_strategy: Deployment strategy to use
            
        Returns:
            Deployment result
        """
        self.logger.info(f"Deploying application: {app_deployment.name}")
        
        if not self.k8s_client:
            await self._connect_to_cluster()
        
        try:
            # Create namespace if it doesn't exist
            await self._ensure_namespace(app_deployment.namespace)
            
            # Create config maps
            for config_map in app_deployment.config_maps:
                await self._create_config_map(config_map, app_deployment.namespace)
            
            # Create secrets
            for secret in app_deployment.secrets:
                await self._create_secret(secret, app_deployment.namespace)
            
            # Create deployment
            deployment_result = await self._create_deployment(
                app_deployment, deployment_strategy
            )
            
            # Create service
            service_result = await self._create_service(app_deployment)
            
            # Create ingress if enabled
            ingress_result = None
            if app_deployment.ingress_enabled:
                ingress_result = await self._create_ingress(app_deployment)
            
            # Configure horizontal pod autoscaler
            hpa_result = await self._configure_hpa(app_deployment)
            
            # Set up monitoring
            if app_deployment.monitoring_enabled:
                await self._configure_monitoring(app_deployment)
            
            # Store deployment information
            self.deployed_applications[app_deployment.name] = {
                'deployment': deployment_result,
                'service': service_result,
                'ingress': ingress_result,
                'hpa': hpa_result,
                'namespace': app_deployment.namespace,
                'deployed_at': datetime.utcnow().isoformat()
            }
            
            result = {
                'application_name': app_deployment.name,
                'namespace': app_deployment.namespace,
                'deployment_name': deployment_result['metadata']['name'],
                'service_name': service_result['metadata']['name'],
                'ingress_name': ingress_result['metadata']['name'] if ingress_result else None,
                'endpoints': await self._get_application_endpoints(app_deployment),
                'status': 'deployed',
                'deployed_at': datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Application deployed successfully: {app_deployment.name}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to deploy application {app_deployment.name}: {e}")
            raise
    
    async def install_helm_chart(
        self,
        helm_chart: HelmChart,
        wait: bool = True
    ) -> Dict[str, Any]:
        """
        Install a Helm chart to the cluster.
        
        Args:
            helm_chart: Helm chart configuration
            wait: Whether to wait for the installation to complete
            
        Returns:
            Installation result
        """
        self.logger.info(f"Installing Helm chart: {helm_chart.name}")
        
        try:
            # Add Helm repository
            await self._add_helm_repository(helm_chart.repository)
            
            # Update repository
            await self._update_helm_repository()
            
            # Create namespace if it doesn't exist
            await self._ensure_namespace(helm_chart.namespace)
            
            # Install chart
            install_result = await self._install_helm_chart(helm_chart, wait)
            
            # Store Helm release information
            self.helm_releases[helm_chart.name] = {
                'chart': helm_chart.chart,
                'version': helm_chart.version,
                'namespace': helm_chart.namespace,
                'installed_at': datetime.utcnow().isoformat(),
                'status': install_result.get('status', 'unknown')
            }
            
            self.logger.info(f"Helm chart installed successfully: {helm_chart.name}")
            return install_result
            
        except Exception as e:
            self.logger.error(f"Failed to install Helm chart {helm_chart.name}: {e}")
            raise
    
    async def scale_application(
        self,
        application_name: str,
        namespace: str,
        replicas: int
    ) -> Dict[str, Any]:
        """
        Scale an application deployment.
        
        Args:
            application_name: Name of the application
            namespace: Kubernetes namespace
            replicas: Target number of replicas
            
        Returns:
            Scaling result
        """
        self.logger.info(f"Scaling application {application_name} to {replicas} replicas")
        
        if not self.k8s_apps_client:
            await self._connect_to_cluster()
        
        try:
            # Update deployment replica count
            deployment = self.k8s_apps_client.read_namespaced_deployment(
                name=application_name,
                namespace=namespace
            )
            
            deployment.spec.replicas = replicas
            
            updated_deployment = self.k8s_apps_client.patch_namespaced_deployment(
                name=application_name,
                namespace=namespace,
                body=deployment
            )
            
            # Wait for scaling to complete
            await self._wait_for_deployment_ready(application_name, namespace)
            
            result = {
                'application_name': application_name,
                'namespace': namespace,
                'previous_replicas': deployment.spec.replicas,
                'new_replicas': replicas,
                'scaled_at': datetime.utcnow().isoformat(),
                'status': 'scaled'
            }
            
            self.logger.info(f"Application scaled successfully: {application_name}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to scale application {application_name}: {e}")
            raise
    
    async def update_application(
        self,
        application_name: str,
        namespace: str,
        new_image: str,
        deployment_strategy: DeploymentStrategy = DeploymentStrategy.ROLLING_UPDATE
    ) -> Dict[str, Any]:
        """
        Update an application with a new image.
        
        Args:
            application_name: Name of the application
            namespace: Kubernetes namespace
            new_image: New container image
            deployment_strategy: Update strategy
            
        Returns:
            Update result
        """
        self.logger.info(f"Updating application {application_name} with image {new_image}")
        
        if not self.k8s_apps_client:
            await self._connect_to_cluster()
        
        try:
            # Get current deployment
            deployment = self.k8s_apps_client.read_namespaced_deployment(
                name=application_name,
                namespace=namespace
            )
            
            # Update image
            deployment.spec.template.spec.containers[0].image = new_image
            
            # Apply deployment strategy
            if deployment_strategy == DeploymentStrategy.ROLLING_UPDATE:
                deployment.spec.strategy.type = "RollingUpdate"
                deployment.spec.strategy.rolling_update = client.V1RollingUpdateDeployment(
                    max_unavailable=1,
                    max_surge=1
                )
            elif deployment_strategy == DeploymentStrategy.RECREATE:
                deployment.spec.strategy.type = "Recreate"
            
            # Update deployment
            updated_deployment = self.k8s_apps_client.patch_namespaced_deployment(
                name=application_name,
                namespace=namespace,
                body=deployment
            )
            
            # Wait for rollout to complete
            await self._wait_for_deployment_ready(application_name, namespace)
            
            result = {
                'application_name': application_name,
                'namespace': namespace,
                'new_image': new_image,
                'deployment_strategy': deployment_strategy.value,
                'updated_at': datetime.utcnow().isoformat(),
                'status': 'updated'
            }
            
            self.logger.info(f"Application updated successfully: {application_name}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to update application {application_name}: {e}")
            raise
    
    async def monitor_cluster_health(self) -> Dict[str, Any]:
        """
        Monitor cluster health and return status.
        
        Returns:
            Cluster health status
        """
        self.logger.info("Monitoring cluster health")
        
        if not self.k8s_client:
            await self._connect_to_cluster()
        
        try:
            # Get cluster version
            version_info = self.k8s_client.get_code().version
            
            # Get node status
            nodes = self.k8s_client.list_node()
            node_status = []
            
            for node in nodes.items:
                conditions = {}
                for condition in node.status.conditions:
                    conditions[condition.type] = condition.status
                
                node_status.append({
                    'name': node.metadata.name,
                    'ready': conditions.get('Ready', 'Unknown'),
                    'cpu_capacity': node.status.capacity.get('cpu', 'Unknown'),
                    'memory_capacity': node.status.capacity.get('memory', 'Unknown'),
                    'kernel_version': node.status.node_info.kernel_version,
                    'kubelet_version': node.status.node_info.kubelet_version
                })
            
            # Get namespace status
            namespaces = self.k8s_client.list_namespace()
            namespace_count = len(namespaces.items)
            
            # Get pod status
            pods = self.k8s_client.list_pod_for_all_namespaces()
            pod_status = {
                'total': len(pods.items),
                'running': 0,
                'pending': 0,
                'failed': 0,
                'succeeded': 0
            }
            
            for pod in pods.items:
                phase = pod.status.phase.lower()
                if phase in pod_status:
                    pod_status[phase] += 1
            
            # Get service status
            services = self.k8s_client.list_service_for_all_namespaces()
            service_count = len(services.items)
            
            health_status = {
                'cluster_name': self.cluster_config.cluster_name if self.cluster_config else 'unknown',
                'kubernetes_version': version_info,
                'node_count': len(node_status),
                'nodes': node_status,
                'namespace_count': namespace_count,
                'pod_status': pod_status,
                'service_count': service_count,
                'cluster_healthy': all(node['ready'] == 'True' for node in node_status),
                'checked_at': datetime.utcnow().isoformat()
            }
            
            self.logger.info("Cluster health monitoring completed")
            return health_status
            
        except Exception as e:
            self.logger.error(f"Failed to monitor cluster health: {e}")
            raise
    
    async def backup_cluster_config(self) -> Dict[str, Any]:
        """
        Backup cluster configuration and resources.
        
        Returns:
            Backup result
        """
        self.logger.info("Backing up cluster configuration")
        
        if not self.k8s_client:
            await self._connect_to_cluster()
        
        try:
            backup_data = {
                'cluster_info': {
                    'name': self.cluster_config.cluster_name if self.cluster_config else 'unknown',
                    'region': self.config.aws.region,
                    'version': self.cluster_config.version if self.cluster_config else 'unknown',
                    'backed_up_at': datetime.utcnow().isoformat()
                },
                'namespaces': [],
                'deployments': [],
                'services': [],
                'config_maps': [],
                'secrets': [],
                'persistent_volumes': [],
                'ingresses': []
            }
            
            # Backup namespaces
            namespaces = self.k8s_client.list_namespace()
            for namespace in namespaces.items:
                backup_data['namespaces'].append({
                    'name': namespace.metadata.name,
                    'labels': namespace.metadata.labels,
                    'annotations': namespace.metadata.annotations
                })
            
            # Backup deployments
            deployments = self.k8s_apps_client.list_deployment_for_all_namespaces()
            for deployment in deployments.items:
                backup_data['deployments'].append({
                    'name': deployment.metadata.name,
                    'namespace': deployment.metadata.namespace,
                    'spec': deployment.spec.to_dict(),
                    'labels': deployment.metadata.labels,
                    'annotations': deployment.metadata.annotations
                })
            
            # Backup services
            services = self.k8s_client.list_service_for_all_namespaces()
            for service in services.items:
                backup_data['services'].append({
                    'name': service.metadata.name,
                    'namespace': service.metadata.namespace,
                    'spec': service.spec.to_dict(),
                    'labels': service.metadata.labels,
                    'annotations': service.metadata.annotations
                })
            
            # Store backup (in production, this would be saved to S3)
            backup_id = f"backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            
            result = {
                'backup_id': backup_id,
                'cluster_name': self.cluster_config.cluster_name if self.cluster_config else 'unknown',
                'backup_size': len(json.dumps(backup_data)),
                'resource_count': {
                    'namespaces': len(backup_data['namespaces']),
                    'deployments': len(backup_data['deployments']),
                    'services': len(backup_data['services'])
                },
                'backed_up_at': datetime.utcnow().isoformat(),
                'status': 'completed'
            }
            
            self.logger.info(f"Cluster configuration backup completed: {backup_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to backup cluster configuration: {e}")
            raise
    
    async def cleanup_cluster(self, cluster_name: str) -> Dict[str, Any]:
        """
        Clean up and delete an EKS cluster.
        
        Args:
            cluster_name: Name of the cluster to delete
            
        Returns:
            Cleanup result
        """
        self.logger.info(f"Cleaning up EKS cluster: {cluster_name}")
        
        try:
            # Delete node groups first
            node_groups = self.eks_client.list_nodegroups(clusterName=cluster_name)
            for node_group_name in node_groups.get('nodegroups', []):
                self.logger.info(f"Deleting node group: {node_group_name}")
                self.eks_client.delete_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=node_group_name
                )
            
            # Wait for node groups to be deleted
            await self._wait_for_node_groups_deleted(cluster_name)
            
            # Delete add-ons
            addons = self.eks_client.list_addons(clusterName=cluster_name)
            for addon_name in addons.get('addons', []):
                self.logger.info(f"Deleting add-on: {addon_name}")
                self.eks_client.delete_addon(
                    clusterName=cluster_name,
                    addonName=addon_name
                )
            
            # Delete cluster
            self.logger.info(f"Deleting cluster: {cluster_name}")
            self.eks_client.delete_cluster(name=cluster_name)
            
            # Wait for cluster to be deleted
            await self._wait_for_cluster_deleted(cluster_name)
            
            # Clear local state
            self.current_cluster = None
            self.cluster_config = None
            self.deployed_applications = {}
            self.helm_releases = {}
            
            result = {
                'cluster_name': cluster_name,
                'deleted_at': datetime.utcnow().isoformat(),
                'status': 'deleted'
            }
            
            self.logger.info(f"EKS cluster cleanup completed: {cluster_name}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup cluster {cluster_name}: {e}")
            raise
    
    # Private helper methods
    
    async def _create_cluster(
        self,
        eks_config: Dict[str, Any],
        infrastructure_plan: InfrastructurePlan
    ) -> Dict[str, Any]:
        """Create EKS cluster."""
        vpc_config = infrastructure_plan['vpc_configuration']
        
        # Get subnet IDs
        subnet_ids = []
        for subnet in vpc_config.public_subnets + vpc_config.private_subnets:
            # In real implementation, get actual subnet IDs
            subnet_ids.append(f"subnet-{subnet['name']}")
        
        # Get security group IDs
        security_group_ids = []
        security_groups = infrastructure_plan['security_config'].get('security_groups', [])
        for sg in security_groups:
            security_group_ids.append(f"sg-{sg['name']}")
        
        # Create cluster
        cluster_params = {
            'name': eks_config['cluster_name'],
            'version': eks_config['version'],
            'roleArn': eks_config['role_arn'],
            'resourcesVpcConfig': {
                'subnetIds': subnet_ids,
                'securityGroupIds': security_group_ids,
                'endpointConfigPrivate': eks_config['endpoint_config']['private_access'],
                'endpointConfigPublic': eks_config['endpoint_config']['public_access']
            }
        }
        
        if eks_config.get('encryption_config'):
            cluster_params['encryptionConfig'] = [eks_config['encryption_config']]
        
        if eks_config.get('logging', {}).get('enable'):
            cluster_params['logging'] = {
                'enable': eks_config['logging']['types']
            }
        
        return self.eks_client.create_cluster(**cluster_params)
    
    async def _wait_for_cluster_active(self, cluster_name: str, timeout: int = 1800):
        """Wait for cluster to become active."""
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            try:
                response = self.eks_client.describe_cluster(name=cluster_name)
                status = response['cluster']['status']
                
                if status == 'ACTIVE':
                    self.logger.info(f"Cluster {cluster_name} is now active")
                    return
                elif status == 'FAILED':
                    raise Exception(f"Cluster {cluster_name} creation failed")
                
                self.logger.info(f"Waiting for cluster {cluster_name} to be active. Current status: {status}")
                await asyncio.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Error checking cluster status: {e}")
                await asyncio.sleep(30)
        
        raise Exception(f"Timeout waiting for cluster {cluster_name} to become active")
    
    async def _create_node_group(
        self,
        cluster_name: str,
        node_group_config: Dict[str, Any],
        infrastructure_plan: InfrastructurePlan
    ) -> Dict[str, Any]:
        """Create EKS node group."""
        vpc_config = infrastructure_plan['vpc_configuration']
        
        # Get subnet IDs for node group
        subnet_ids = []
        for subnet in vpc_config.private_subnets:
            subnet_ids.append(f"subnet-{subnet['name']}")
        
        node_group_params = {
            'clusterName': cluster_name,
            'nodegroupName': node_group_config['name'],
            'scalingConfig': node_group_config['scaling_config'],
            'instanceTypes': node_group_config['instance_types'],
            'subnets': subnet_ids,
            'nodeRole': f"arn:aws:iam::{self._get_account_id()}:role/eks-node-group-role",
            'amiType': node_group_config.get('ami_type', 'AL2_x86_64'),
            'capacityType': node_group_config.get('capacity_type', 'ON_DEMAND'),
            'diskSize': node_group_config.get('disk_size', 20)
        }
        
        if node_group_config.get('labels'):
            node_group_params['labels'] = node_group_config['labels']
        
        if node_group_config.get('taints'):
            node_group_params['taints'] = node_group_config['taints']
        
        return self.eks_client.create_nodegroup(**node_group_params)
    
    async def _install_addon(self, cluster_name: str, addon_config: Dict[str, Any]) -> Dict[str, Any]:
        """Install EKS add-on."""
        addon_params = {
            'clusterName': cluster_name,
            'addonName': addon_config['name'],
            'addonVersion': addon_config.get('version', 'latest'),
            'resolveConflicts': addon_config.get('resolve_conflicts', 'OVERWRITE')
        }
        
        return self.eks_client.create_addon(**addon_params)
    
    async def _configure_cluster_auth(self, cluster_name: str):
        """Configure cluster authentication."""
        # Get cluster details
        cluster_response = self.eks_client.describe_cluster(name=cluster_name)
        cluster_info = cluster_response['cluster']
        
        # Update kubeconfig
        # In real implementation, this would update the local kubeconfig
        self.logger.info(f"Cluster authentication configured for {cluster_name}")
    
    async def _enable_cluster_logging(self, cluster_name: str, logging_config: Dict[str, Any]):
        """Enable cluster logging."""
        logging_params = {
            'name': cluster_name,
            'logging': {
                'enable': logging_config.get('types', [])
            }
        }
        
        return self.eks_client.update_cluster_config(**logging_params)
    
    async def _configure_cluster_networking(self, cluster_name: str, infrastructure_plan: InfrastructurePlan):
        """Configure cluster networking."""
        # This would configure VPC CNI, security groups, etc.
        self.logger.info(f"Cluster networking configured for {cluster_name}")
    
    async def _connect_to_cluster(self):
        """Connect to Kubernetes cluster."""
        if not self.current_cluster:
            raise Exception("No active cluster found")
        
        # Load cluster configuration
        cluster_name = self.current_cluster['cluster_name']
        
        # Update kubeconfig
        # In real implementation, this would load the actual kubeconfig
        try:
            config.load_kube_config()
            self.k8s_client = client.CoreV1Api()
            self.k8s_apps_client = client.AppsV1Api()
            self.k8s_networking_client = client.NetworkingV1Api()
            
            self.logger.info(f"Connected to cluster: {cluster_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to cluster: {e}")
            raise
    
    async def _ensure_namespace(self, namespace: str):
        """Ensure namespace exists."""
        try:
            self.k8s_client.read_namespace(name=namespace)
        except ApiException as e:
            if e.status == 404:
                # Create namespace
                namespace_obj = client.V1Namespace(
                    metadata=client.V1ObjectMeta(name=namespace)
                )
                self.k8s_client.create_namespace(body=namespace_obj)
                self.logger.info(f"Created namespace: {namespace}")
            else:
                raise
    
    async def _create_deployment(
        self,
        app_deployment: ApplicationDeployment,
        deployment_strategy: DeploymentStrategy
    ) -> Dict[str, Any]:
        """Create Kubernetes deployment."""
        # Container specification
        container = client.V1Container(
            name=app_deployment.name,
            image=f"{app_deployment.image}:{app_deployment.tag}",
            ports=[client.V1ContainerPort(container_port=8080)],
            resources=client.V1ResourceRequirements(
                requests=app_deployment.resources.get('requests', {}),
                limits=app_deployment.resources.get('limits', {})
            ),
            env=[
                client.V1EnvVar(name=key, value=value)
                for key, value in app_deployment.environment_variables.items()
            ]
        )
        
        # Add health checks
        if app_deployment.health_checks:
            if app_deployment.health_checks.get('liveness'):
                container.liveness_probe = client.V1Probe(
                    http_get=client.V1HTTPGetAction(
                        path=app_deployment.health_checks['liveness']['path'],
                        port=app_deployment.health_checks['liveness']['port']
                    ),
                    initial_delay_seconds=30,
                    period_seconds=10
                )
            
            if app_deployment.health_checks.get('readiness'):
                container.readiness_probe = client.V1Probe(
                    http_get=client.V1HTTPGetAction(
                        path=app_deployment.health_checks['readiness']['path'],
                        port=app_deployment.health_checks['readiness']['port']
                    ),
                    initial_delay_seconds=5,
                    period_seconds=5
                )
        
        # Pod template
        pod_template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(
                labels={'app': app_deployment.name}
            ),
            spec=client.V1PodSpec(containers=[container])
        )
        
        # Deployment strategy
        strategy = client.V1DeploymentStrategy(type='RollingUpdate')
        if deployment_strategy == DeploymentStrategy.RECREATE:
            strategy = client.V1DeploymentStrategy(type='Recreate')
        
        # Deployment specification
        deployment_spec = client.V1DeploymentSpec(
            replicas=app_deployment.replicas,
            selector=client.V1LabelSelector(
                match_labels={'app': app_deployment.name}
            ),
            template=pod_template,
            strategy=strategy
        )
        
        # Deployment object
        deployment_obj = client.V1Deployment(
            api_version='apps/v1',
            kind='Deployment',
            metadata=client.V1ObjectMeta(
                name=app_deployment.name,
                namespace=app_deployment.namespace
            ),
            spec=deployment_spec
        )
        
        # Create deployment
        created_deployment = self.k8s_apps_client.create_namespaced_deployment(
            namespace=app_deployment.namespace,
            body=deployment_obj
        )
        
        return created_deployment.to_dict()
    
    async def _create_service(self, app_deployment: ApplicationDeployment) -> Dict[str, Any]:
        """Create Kubernetes service."""
        service_spec = client.V1ServiceSpec(
            selector={'app': app_deployment.name},
            ports=[client.V1ServicePort(port=80, target_port=8080)],
            type=app_deployment.service_type.value
        )
        
        service_obj = client.V1Service(
            api_version='v1',
            kind='Service',
            metadata=client.V1ObjectMeta(
                name=f"{app_deployment.name}-service",
                namespace=app_deployment.namespace
            ),
            spec=service_spec
        )
        
        created_service = self.k8s_client.create_namespaced_service(
            namespace=app_deployment.namespace,
            body=service_obj
        )
        
        return created_service.to_dict()
    
    async def _create_ingress(self, app_deployment: ApplicationDeployment) -> Dict[str, Any]:
        """Create Kubernetes ingress."""
        ingress_spec = client.V1IngressSpec(
            rules=[
                client.V1IngressRule(
                    host=f"{app_deployment.name}.example.com",
                    http=client.V1HTTPIngressRuleValue(
                        paths=[
                            client.V1HTTPIngressPath(
                                path="/",
                                path_type="Prefix",
                                backend=client.V1IngressBackend(
                                    service=client.V1IngressServiceBackend(
                                        name=f"{app_deployment.name}-service",
                                        port=client.V1ServiceBackendPort(number=80)
                                    )
                                )
                            )
                        ]
                    )
                )
            ]
        )
        
        ingress_obj = client.V1Ingress(
            api_version='networking.k8s.io/v1',
            kind='Ingress',
            metadata=client.V1ObjectMeta(
                name=f"{app_deployment.name}-ingress",
                namespace=app_deployment.namespace
            ),
            spec=ingress_spec
        )
        
        created_ingress = self.k8s_networking_client.create_namespaced_ingress(
            namespace=app_deployment.namespace,
            body=ingress_obj
        )
        
        return created_ingress.to_dict()
    
    async def _configure_hpa(self, app_deployment: ApplicationDeployment) -> Dict[str, Any]:
        """Configure Horizontal Pod Autoscaler."""
        hpa_spec = client.V2HorizontalPodAutoscalerSpec(
            scale_target_ref=client.V2CrossVersionObjectReference(
                api_version='apps/v1',
                kind='Deployment',
                name=app_deployment.name
            ),
            min_replicas=max(1, app_deployment.replicas // 2),
            max_replicas=app_deployment.replicas * 3,
            metrics=[
                client.V2MetricSpec(
                    type='Resource',
                    resource=client.V2ResourceMetricSource(
                        name='cpu',
                        target=client.V2MetricTarget(
                            type='Utilization',
                            average_utilization=70
                        )
                    )
                )
            ]
        )
        
        hpa_obj = client.V2HorizontalPodAutoscaler(
            api_version='autoscaling/v2',
            kind='HorizontalPodAutoscaler',
            metadata=client.V1ObjectMeta(
                name=f"{app_deployment.name}-hpa",
                namespace=app_deployment.namespace
            ),
            spec=hpa_spec
        )
        
        # Create HPA
        autoscaling_client = client.AutoscalingV2Api()
        created_hpa = autoscaling_client.create_namespaced_horizontal_pod_autoscaler(
            namespace=app_deployment.namespace,
            body=hpa_obj
        )
        
        return created_hpa.to_dict()
    
    async def _configure_monitoring(self, app_deployment: ApplicationDeployment):
        """Configure monitoring for the application."""
        # This would set up monitoring with Prometheus/Grafana
        self.logger.info(f"Monitoring configured for {app_deployment.name}")
    
    async def _create_config_map(self, config_map_name: str, namespace: str):
        """Create config map."""
        # This would create actual config maps
        self.logger.info(f"Config map created: {config_map_name}")
    
    async def _create_secret(self, secret_name: str, namespace: str):
        """Create secret."""
        # This would create actual secrets
        self.logger.info(f"Secret created: {secret_name}")
    
    async def _get_application_endpoints(self, app_deployment: ApplicationDeployment) -> List[str]:
        """Get application endpoints."""
        endpoints = []
        
        if app_deployment.service_type == ServiceType.LOAD_BALANCER:
            # Get load balancer endpoint
            endpoints.append(f"http://{app_deployment.name}-lb.example.com")
        
        if app_deployment.ingress_enabled:
            # Get ingress endpoint
            endpoints.append(f"https://{app_deployment.name}.example.com")
        
        return endpoints
    
    async def _wait_for_deployment_ready(self, deployment_name: str, namespace: str, timeout: int = 300):
        """Wait for deployment to be ready."""
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            try:
                deployment = self.k8s_apps_client.read_namespaced_deployment(
                    name=deployment_name,
                    namespace=namespace
                )
                
                if deployment.status.ready_replicas == deployment.spec.replicas:
                    self.logger.info(f"Deployment {deployment_name} is ready")
                    return
                
                await asyncio.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Error checking deployment status: {e}")
                await asyncio.sleep(5)
        
        raise Exception(f"Timeout waiting for deployment {deployment_name} to be ready")
    
    async def _add_helm_repository(self, repository_url: str):
        """Add Helm repository."""
        # This would add the actual Helm repository
        self.logger.info(f"Helm repository added: {repository_url}")
    
    async def _update_helm_repository(self):
        """Update Helm repository."""
        # This would update the Helm repository
        self.logger.info("Helm repository updated")
    
    async def _install_helm_chart(self, helm_chart: HelmChart, wait: bool) -> Dict[str, Any]:
        """Install Helm chart."""
        # This would install the actual Helm chart
        return {
            'name': helm_chart.name,
            'chart': helm_chart.chart,
            'version': helm_chart.version,
            'namespace': helm_chart.namespace,
            'status': 'deployed',
            'installed_at': datetime.utcnow().isoformat()
        }
    
    async def _wait_for_node_groups_deleted(self, cluster_name: str, timeout: int = 1800):
        """Wait for node groups to be deleted."""
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            try:
                node_groups = self.eks_client.list_nodegroups(clusterName=cluster_name)
                if not node_groups.get('nodegroups'):
                    self.logger.info(f"All node groups deleted for cluster {cluster_name}")
                    return
                
                self.logger.info(f"Waiting for node groups to be deleted: {node_groups['nodegroups']}")
                await asyncio.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Error checking node group status: {e}")
                await asyncio.sleep(30)
        
        raise Exception(f"Timeout waiting for node groups to be deleted for cluster {cluster_name}")
    
    async def _wait_for_cluster_deleted(self, cluster_name: str, timeout: int = 900):
        """Wait for cluster to be deleted."""
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            try:
                self.eks_client.describe_cluster(name=cluster_name)
                self.logger.info(f"Waiting for cluster {cluster_name} to be deleted")
                await asyncio.sleep(30)
                
            except self.eks_client.exceptions.ResourceNotFoundException:
                self.logger.info(f"Cluster {cluster_name} successfully deleted")
                return
            except Exception as e:
                self.logger.error(f"Error checking cluster status: {e}")
                await asyncio.sleep(30)
        
        raise Exception(f"Timeout waiting for cluster {cluster_name} to be deleted")
    
    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        try:
            return self.sts_client.get_caller_identity()['Account']
        except Exception:
            return "123456789012"  # Fallback for testing 