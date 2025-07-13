"""
Security Manager module for IAM management, security scanning, and compliance.

This module provides comprehensive security management capabilities including:
- IAM role and policy management with least-privilege principles
- Security scanning and vulnerability assessment
- Compliance checking against standards (SOC2, GDPR, etc.)
- Network security configuration
- Encryption and secrets management
- Security monitoring and alerting
"""

import json
import boto3
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from ..core.state import SecurityConfiguration, ApplicationType, DeploymentPhase
from ..core.config import AgentConfig, SecurityConfig


class SecurityLevel(Enum):
    """Security level classifications."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStandard(Enum):
    """Supported compliance standards."""
    SOC2 = "SOC2"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"
    AWS_WELL_ARCHITECTED = "AWS_Well_Architected"


@dataclass
class SecurityAssessment:
    """Security assessment results."""
    overall_score: float
    risk_level: SecurityLevel
    vulnerabilities: List[Dict[str, Any]]
    recommendations: List[str]
    compliance_status: Dict[str, bool]
    security_controls: Dict[str, Any]
    timestamp: datetime


@dataclass
class IAMRole:
    """IAM role configuration."""
    name: str
    role_type: str  # service, user, cross-account
    policies: List[str]
    trust_policy: Dict[str, Any]
    description: str
    max_session_duration: int = 3600
    tags: Dict[str, str] = None


@dataclass
class SecurityPolicy:
    """Security policy definition."""
    name: str
    policy_document: Dict[str, Any]
    description: str
    policy_type: str  # managed, inline, resource-based
    resources: List[str]
    actions: List[str]
    conditions: Dict[str, Any] = None


class SecurityManager:
    """
    Comprehensive security management for AWS infrastructure.
    
    Handles IAM roles, policies, security scanning, compliance checking,
    and security monitoring for the infrastructure deployment.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the Security Manager.
        
        Args:
            config: Agent configuration containing security settings
        """
        self.config = config
        self.security_config = config.security
        self.logger = logging.getLogger(__name__)
        
        # Initialize AWS clients
        self.iam_client = boto3.client('iam', region_name=config.aws.region)
        self.sts_client = boto3.client('sts', region_name=config.aws.region)
        self.ec2_client = boto3.client('ec2', region_name=config.aws.region)
        self.eks_client = boto3.client('eks', region_name=config.aws.region)
        self.secretsmanager_client = boto3.client('secretsmanager', region_name=config.aws.region)
        
        # Security scanning tools
        self.vulnerability_scanners = {
            'aws_inspector': self._scan_with_inspector,
            'security_groups': self._scan_security_groups,
            'iam_analyzer': self._scan_iam_policies,
            'network_analyzer': self._scan_network_configuration
        }
        
        # Compliance frameworks
        self.compliance_frameworks = {
            ComplianceStandard.SOC2: self._check_soc2_compliance,
            ComplianceStandard.GDPR: self._check_gdpr_compliance,
            ComplianceStandard.AWS_WELL_ARCHITECTED: self._check_aws_well_architected,
            ComplianceStandard.HIPAA: self._check_hipaa_compliance,
            ComplianceStandard.PCI_DSS: self._check_pci_dss_compliance
        }
        
        self.logger.info("Security Manager initialized")
    
    async def assess_security_requirements(
        self, 
        repository_analysis: Dict[str, Any],
        target_environment: str,
        application_type: ApplicationType
    ) -> SecurityConfiguration:
        """
        Assess security requirements based on repository analysis.
        
        Args:
            repository_analysis: Repository analysis results
            target_environment: Target deployment environment
            application_type: Type of application being deployed
            
        Returns:
            Security configuration with roles, policies, and controls
        """
        self.logger.info(f"Assessing security requirements for {application_type.value}")
        
        # Determine security level based on application type and environment
        security_level = self._determine_security_level(application_type, target_environment)
        
        # Generate IAM roles and policies
        iam_roles = await self._generate_iam_roles(application_type, security_level)
        security_policies = await self._generate_security_policies(application_type, security_level)
        
        # Configure network security
        network_config = await self._configure_network_security(application_type, security_level)
        
        # Set up encryption configuration
        encryption_config = await self._configure_encryption(application_type, security_level)
        
        # Configure secrets management
        secrets_config = await self._configure_secrets_management(application_type, security_level)
        
        # Determine compliance requirements
        compliance_requirements = self._determine_compliance_requirements(
            application_type, target_environment, repository_analysis
        )
        
        # Security monitoring configuration
        monitoring_config = await self._configure_security_monitoring(application_type, security_level)
        
        security_config = SecurityConfiguration(
            iam_roles=iam_roles,
            policies=security_policies,
            security_groups=network_config.get('security_groups', []),
            network_acls=network_config.get('network_acls', []),
            encryption_config=encryption_config,
            secrets_config=secrets_config,
            compliance_requirements=compliance_requirements,
            monitoring_config=monitoring_config,
            security_level=security_level.value,
            vulnerability_scan_results=None  # Will be populated during scanning
        )
        
        self.logger.info("Security requirements assessment completed")
        return security_config
    
    async def perform_security_scan(
        self, 
        infrastructure_config: Dict[str, Any],
        security_config: SecurityConfiguration
    ) -> SecurityAssessment:
        """
        Perform comprehensive security scanning of infrastructure.
        
        Args:
            infrastructure_config: Infrastructure configuration to scan
            security_config: Security configuration to validate
            
        Returns:
            Security assessment results
        """
        self.logger.info("Starting comprehensive security scan")
        
        vulnerabilities = []
        recommendations = []
        compliance_status = {}
        
        # Run all security scanners
        for scanner_name, scanner_func in self.vulnerability_scanners.items():
            try:
                self.logger.debug(f"Running {scanner_name} scanner")
                scan_results = await scanner_func(infrastructure_config, security_config)
                
                vulnerabilities.extend(scan_results.get('vulnerabilities', []))
                recommendations.extend(scan_results.get('recommendations', []))
                
            except Exception as e:
                self.logger.error(f"Scanner {scanner_name} failed: {e}")
                vulnerabilities.append({
                    'type': 'scanner_error',
                    'severity': 'medium',
                    'description': f"Scanner {scanner_name} failed: {e}",
                    'scanner': scanner_name
                })
        
        # Check compliance against required standards
        required_compliance = security_config.get('compliance_requirements', [])
        for standard_name in required_compliance:
            try:
                standard = ComplianceStandard(standard_name)
                compliance_check = self.compliance_frameworks[standard]
                
                self.logger.debug(f"Checking {standard_name} compliance")
                is_compliant = await compliance_check(infrastructure_config, security_config)
                compliance_status[standard_name] = is_compliant
                
                if not is_compliant:
                    recommendations.append(f"Address {standard_name} compliance issues")
                    
            except (ValueError, KeyError) as e:
                self.logger.warning(f"Unknown compliance standard: {standard_name}")
                compliance_status[standard_name] = False
        
        # Calculate overall security score
        security_score = self._calculate_security_score(vulnerabilities, compliance_status)
        risk_level = self._determine_risk_level(security_score, vulnerabilities)
        
        # Generate security controls recommendations
        security_controls = await self._generate_security_controls(
            vulnerabilities, compliance_status, risk_level
        )
        
        assessment = SecurityAssessment(
            overall_score=security_score,
            risk_level=risk_level,
            vulnerabilities=vulnerabilities,
            recommendations=list(set(recommendations)),  # Remove duplicates
            compliance_status=compliance_status,
            security_controls=security_controls,
            timestamp=datetime.utcnow()
        )
        
        self.logger.info(f"Security scan completed. Score: {security_score:.2f}, Risk: {risk_level.value}")
        return assessment
    
    async def create_iam_resources(self, security_config: SecurityConfiguration) -> Dict[str, Any]:
        """
        Create IAM roles and policies in AWS.
        
        Args:
            security_config: Security configuration containing IAM definitions
            
        Returns:
            Created IAM resources information
        """
        self.logger.info("Creating IAM resources")
        
        created_resources = {
            'roles': [],
            'policies': [],
            'errors': []
        }
        
        # Create IAM roles
        for role_config in security_config.get('iam_roles', []):
            try:
                role_result = await self._create_iam_role(role_config)
                created_resources['roles'].append(role_result)
                self.logger.info(f"Created IAM role: {role_config['name']}")
                
            except Exception as e:
                error_msg = f"Failed to create IAM role {role_config['name']}: {e}"
                self.logger.error(error_msg)
                created_resources['errors'].append(error_msg)
        
        # Create IAM policies
        for policy_config in security_config.get('policies', []):
            try:
                policy_result = await self._create_iam_policy(policy_config)
                created_resources['policies'].append(policy_result)
                self.logger.info(f"Created IAM policy: {policy_config['name']}")
                
            except Exception as e:
                error_msg = f"Failed to create IAM policy {policy_config['name']}: {e}"
                self.logger.error(error_msg)
                created_resources['errors'].append(error_msg)
        
        return created_resources
    
    async def validate_security_configuration(self, security_config: SecurityConfiguration) -> List[str]:
        """
        Validate security configuration for best practices.
        
        Args:
            security_config: Security configuration to validate
            
        Returns:
            List of validation errors/warnings
        """
        self.logger.info("Validating security configuration")
        
        validation_errors = []
        
        # Validate IAM roles
        roles = security_config.get('iam_roles', [])
        for role in roles:
            role_errors = await self._validate_iam_role(role)
            validation_errors.extend(role_errors)
        
        # Validate security policies
        policies = security_config.get('policies', [])
        for policy in policies:
            policy_errors = await self._validate_security_policy(policy)
            validation_errors.extend(policy_errors)
        
        # Validate network configuration
        network_errors = await self._validate_network_configuration(security_config)
        validation_errors.extend(network_errors)
        
        # Validate encryption configuration
        encryption_errors = await self._validate_encryption_configuration(security_config)
        validation_errors.extend(encryption_errors)
        
        if validation_errors:
            self.logger.warning(f"Security configuration validation found {len(validation_errors)} issues")
        else:
            self.logger.info("Security configuration validation passed")
        
        return validation_errors
    
    # Private helper methods
    
    def _determine_security_level(self, app_type: ApplicationType, environment: str) -> SecurityLevel:
        """Determine appropriate security level."""
        # Production environments always get high security
        if environment == 'prod':
            return SecurityLevel.HIGH
        
        # Critical application types get high security
        if app_type in [ApplicationType.ML_SERVICE, ApplicationType.DATA_PIPELINE]:
            return SecurityLevel.HIGH
        
        # Staging gets medium security
        if environment == 'staging':
            return SecurityLevel.MEDIUM
        
        # Development gets low security by default
        return SecurityLevel.LOW
    
    async def _generate_iam_roles(self, app_type: ApplicationType, security_level: SecurityLevel) -> List[Dict[str, Any]]:
        """Generate IAM roles based on application type and security level."""
        roles = []
        
        # EKS Cluster Service Role
        cluster_role = {
            'name': f"{self.security_config.iam_role_prefix}eks-cluster-role",
            'type': 'service',
            'policies': ['arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'],
            'trust_policy': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'eks.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            },
            'description': 'EKS cluster service role',
            'max_session_duration': 3600
        }
        roles.append(cluster_role)
        
        # EKS Node Group Role
        node_role = {
            'name': f"{self.security_config.iam_role_prefix}eks-node-group-role",
            'type': 'service',
            'policies': [
                'arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy',
                'arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
                'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly'
            ],
            'trust_policy': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'ec2.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            },
            'description': 'EKS node group role',
            'max_session_duration': 3600
        }
        roles.append(node_role)
        
        # Application-specific roles
        if app_type == ApplicationType.ML_SERVICE:
            ml_role = {
                'name': f"{self.security_config.iam_role_prefix}ml-service-role",
                'type': 'service',
                'policies': [
                    'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess',
                    'arn:aws:iam::aws:policy/AmazonSageMakerReadOnly'
                ],
                'trust_policy': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {'Service': 'sagemaker.amazonaws.com'},
                        'Action': 'sts:AssumeRole'
                    }]
                },
                'description': 'ML service execution role',
                'max_session_duration': 7200
            }
            roles.append(ml_role)
        
        elif app_type == ApplicationType.DATA_PIPELINE:
            data_role = {
                'name': f"{self.security_config.iam_role_prefix}data-pipeline-role",
                'type': 'service',
                'policies': [
                    'arn:aws:iam::aws:policy/AmazonS3FullAccess',
                    'arn:aws:iam::aws:policy/AmazonKinesisReadOnlyAccess'
                ],
                'trust_policy': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {'Service': 'lambda.amazonaws.com'},
                        'Action': 'sts:AssumeRole'
                    }]
                },
                'description': 'Data pipeline execution role',
                'max_session_duration': 3600
            }
            roles.append(data_role)
        
        # Add deployment role for CI/CD
        deployment_role = {
            'name': f"{self.security_config.iam_role_prefix}deployment-role",
            'type': 'cross-account',
            'policies': [
                'arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy'
            ],
            'trust_policy': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'AWS': f"arn:aws:iam::{self._get_account_id()}:root"},
                    'Action': 'sts:AssumeRole',
                    'Condition': {
                        'StringEquals': {
                            'sts:ExternalId': 'deployment-external-id'
                        }
                    }
                }]
            },
            'description': 'Role for CI/CD deployment',
            'max_session_duration': 1800
        }
        roles.append(deployment_role)
        
        return roles
    
    async def _generate_security_policies(self, app_type: ApplicationType, security_level: SecurityLevel) -> List[Dict[str, Any]]:
        """Generate security policies based on application requirements."""
        policies = []
        
        # Base security policy for all applications
        base_policy = {
            'name': f"{self.security_config.iam_role_prefix}base-security-policy",
            'policy_document': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': [
                            'logs:CreateLogGroup',
                            'logs:CreateLogStream',
                            'logs:PutLogEvents'
                        ],
                        'Resource': 'arn:aws:logs:*:*:*'
                    },
                    {
                        'Effect': 'Allow',
                        'Action': [
                            'cloudwatch:PutMetricData'
                        ],
                        'Resource': '*'
                    }
                ]
            },
            'description': 'Base security policy for all applications',
            'policy_type': 'managed',
            'resources': ['*'],
            'actions': ['logs:*', 'cloudwatch:PutMetricData']
        }
        policies.append(base_policy)
        
        # Application-specific policies
        if app_type == ApplicationType.ML_SERVICE:
            ml_policy = {
                'name': f"{self.security_config.iam_role_prefix}ml-service-policy",
                'policy_document': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': [
                                's3:GetObject',
                                's3:PutObject'
                            ],
                            'Resource': 'arn:aws:s3:::ml-models-bucket/*'
                        },
                        {
                            'Effect': 'Allow',
                            'Action': [
                                'sagemaker:DescribeModel',
                                'sagemaker:InvokeEndpoint'
                            ],
                            'Resource': '*'
                        }
                    ]
                },
                'description': 'ML service specific permissions',
                'policy_type': 'managed',
                'resources': ['arn:aws:s3:::ml-models-bucket/*'],
                'actions': ['s3:GetObject', 's3:PutObject', 'sagemaker:*']
            }
            policies.append(ml_policy)
        
        # Security level specific policies
        if security_level == SecurityLevel.HIGH:
            high_security_policy = {
                'name': f"{self.security_config.iam_role_prefix}high-security-policy",
                'policy_document': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Deny',
                            'Action': '*',
                            'Resource': '*',
                            'Condition': {
                                'Bool': {
                                    'aws:SecureTransport': 'false'
                                }
                            }
                        }
                    ]
                },
                'description': 'High security policy enforcing encryption in transit',
                'policy_type': 'managed',
                'resources': ['*'],
                'actions': ['*']
            }
            policies.append(high_security_policy)
        
        return policies
    
    async def _configure_network_security(self, app_type: ApplicationType, security_level: SecurityLevel) -> Dict[str, Any]:
        """Configure network security settings."""
        network_config = {
            'security_groups': [],
            'network_acls': []
        }
        
        # EKS Cluster Security Group
        cluster_sg = {
            'name': 'eks-cluster-sg',
            'description': 'Security group for EKS cluster',
            'rules': [
                {
                    'type': 'ingress',
                    'protocol': 'tcp',
                    'port': 443,
                    'source': '0.0.0.0/0',
                    'description': 'HTTPS access to EKS API'
                },
                {
                    'type': 'egress',
                    'protocol': 'all',
                    'port': 'all',
                    'destination': '0.0.0.0/0',
                    'description': 'All outbound traffic'
                }
            ]
        }
        network_config['security_groups'].append(cluster_sg)
        
        # Worker Node Security Group
        worker_sg = {
            'name': 'eks-worker-sg',
            'description': 'Security group for EKS worker nodes',
            'rules': [
                {
                    'type': 'ingress',
                    'protocol': 'tcp',
                    'port': '1025-65535',
                    'source': 'cluster-sg',
                    'description': 'Allow communication from cluster'
                },
                {
                    'type': 'ingress',
                    'protocol': 'tcp',
                    'port': 22,
                    'source': '10.0.0.0/8',
                    'description': 'SSH access from VPC'
                }
            ]
        }
        network_config['security_groups'].append(worker_sg)
        
        # Application-specific security groups
        if app_type in [ApplicationType.WEB_APP, ApplicationType.API_SERVICE]:
            app_sg = {
                'name': 'application-sg',
                'description': 'Security group for application',
                'rules': [
                    {
                        'type': 'ingress',
                        'protocol': 'tcp',
                        'port': 80,
                        'source': '0.0.0.0/0',
                        'description': 'HTTP access'
                    },
                    {
                        'type': 'ingress',
                        'protocol': 'tcp',
                        'port': 443,
                        'source': '0.0.0.0/0',
                        'description': 'HTTPS access'
                    }
                ]
            }
            network_config['security_groups'].append(app_sg)
        
        # High security configurations
        if security_level == SecurityLevel.HIGH:
            # Restrict HTTP access for high security
            for sg in network_config['security_groups']:
                sg['rules'] = [rule for rule in sg['rules'] if rule.get('port') != 80]
        
        return network_config
    
    async def _configure_encryption(self, app_type: ApplicationType, security_level: SecurityLevel) -> Dict[str, Any]:
        """Configure encryption settings."""
        encryption_config = {
            'ebs_encryption': True,
            's3_encryption': True,
            'secrets_encryption': True,
            'rds_encryption': True,
            'kms_key_rotation': True,
            'encryption_in_transit': security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]
        }
        
        # Application-specific encryption requirements
        if app_type == ApplicationType.ML_SERVICE:
            encryption_config.update({
                'model_encryption': True,
                'data_encryption': True
            })
        
        elif app_type == ApplicationType.DATA_PIPELINE:
            encryption_config.update({
                'stream_encryption': True,
                'data_lake_encryption': True
            })
        
        return encryption_config
    
    async def _configure_secrets_management(self, app_type: ApplicationType, security_level: SecurityLevel) -> Dict[str, Any]:
        """Configure secrets management."""
        secrets_config = {
            'use_aws_secrets_manager': True,
            'automatic_rotation': security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL],
            'cross_region_replication': security_level == SecurityLevel.CRITICAL,
            'secret_recovery_window': 7 if security_level == SecurityLevel.LOW else 30
        }
        
        return secrets_config
    
    async def _configure_security_monitoring(self, app_type: ApplicationType, security_level: SecurityLevel) -> Dict[str, Any]:
        """Configure security monitoring."""
        monitoring_config = {
            'cloudtrail_enabled': True,
            'config_enabled': True,
            'security_hub_enabled': security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL],
            'guardduty_enabled': security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL],
            'inspector_enabled': True,
            'access_analyzer_enabled': True
        }
        
        return monitoring_config
    
    def _determine_compliance_requirements(
        self, 
        app_type: ApplicationType, 
        environment: str, 
        repo_analysis: Dict[str, Any]
    ) -> List[str]:
        """Determine compliance requirements based on application characteristics."""
        requirements = ['AWS_Well_Architected']
        
        # Always include SOC2 for production
        if environment == 'prod':
            requirements.append('SOC2')
        
        # Web applications handling user data need GDPR
        if app_type in [ApplicationType.WEB_APP, ApplicationType.API_SERVICE]:
            requirements.append('GDPR')
        
        # Healthcare applications need HIPAA
        dependencies = repo_analysis.get('dependencies', [])
        if any('health' in dep.lower() or 'medical' in dep.lower() for dep in dependencies):
            requirements.append('HIPAA')
        
        # Payment processing needs PCI DSS
        if any('payment' in dep.lower() or 'stripe' in dep.lower() for dep in dependencies):
            requirements.append('PCI_DSS')
        
        return requirements
    
    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        try:
            return self.sts_client.get_caller_identity()['Account']
        except Exception as e:
            self.logger.error(f"Failed to get account ID: {e}")
            return "123456789012"  # Fallback for testing
    
    # Security scanning methods
    
    async def _scan_with_inspector(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> Dict[str, Any]:
        """Scan infrastructure with AWS Inspector."""
        results = {
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # This would integrate with AWS Inspector
        # For now, return mock results
        results['recommendations'].append("Enable AWS Inspector for vulnerability scanning")
        
        return results
    
    async def _scan_security_groups(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> Dict[str, Any]:
        """Scan security group configurations."""
        results = {
            'vulnerabilities': [],
            'recommendations': []
        }
        
        security_groups = security_config.get('security_groups', [])
        
        for sg in security_groups:
            for rule in sg.get('rules', []):
                # Check for overly permissive rules
                if rule.get('source') == '0.0.0.0/0' and rule.get('port') != 443:
                    results['vulnerabilities'].append({
                        'type': 'overly_permissive_sg_rule',
                        'severity': 'medium',
                        'description': f"Security group {sg['name']} allows access from anywhere on port {rule['port']}",
                        'resource': sg['name'],
                        'remediation': f"Restrict source to specific IP ranges for port {rule['port']}"
                    })
        
        return results
    
    async def _scan_iam_policies(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> Dict[str, Any]:
        """Scan IAM policies for security issues."""
        results = {
            'vulnerabilities': [],
            'recommendations': []
        }
        
        policies = security_config.get('policies', [])
        
        for policy in policies:
            policy_doc = policy.get('policy_document', {})
            statements = policy_doc.get('Statement', [])
            
            for statement in statements:
                # Check for overly broad permissions
                if statement.get('Effect') == 'Allow' and '*' in statement.get('Action', []):
                    results['vulnerabilities'].append({
                        'type': 'overly_broad_iam_permissions',
                        'severity': 'high',
                        'description': f"Policy {policy['name']} grants wildcard permissions",
                        'resource': policy['name'],
                        'remediation': "Use principle of least privilege and specify exact actions"
                    })
        
        return results
    
    async def _scan_network_configuration(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> Dict[str, Any]:
        """Scan network configuration for security issues."""
        results = {
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Check encryption in transit
        encryption_config = security_config.get('encryption_config', {})
        if not encryption_config.get('encryption_in_transit', False):
            results['vulnerabilities'].append({
                'type': 'encryption_in_transit_disabled',
                'severity': 'medium',
                'description': "Encryption in transit is not enabled",
                'resource': 'network_configuration',
                'remediation': "Enable encryption in transit for all communications"
            })
        
        return results
    
    # Compliance checking methods
    
    async def _check_soc2_compliance(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> bool:
        """Check SOC2 compliance."""
        # Basic SOC2 requirements check
        encryption_config = security_config.get('encryption_config', {})
        monitoring_config = security_config.get('monitoring_config', {})
        
        required_controls = [
            encryption_config.get('ebs_encryption', False),
            encryption_config.get('s3_encryption', False),
            monitoring_config.get('cloudtrail_enabled', False),
            monitoring_config.get('access_analyzer_enabled', False)
        ]
        
        return all(required_controls)
    
    async def _check_gdpr_compliance(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> bool:
        """Check GDPR compliance."""
        # Basic GDPR requirements
        encryption_config = security_config.get('encryption_config', {})
        secrets_config = security_config.get('secrets_config', {})
        
        required_controls = [
            encryption_config.get('ebs_encryption', False),
            encryption_config.get('encryption_in_transit', False),
            secrets_config.get('use_aws_secrets_manager', False)
        ]
        
        return all(required_controls)
    
    async def _check_aws_well_architected(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> bool:
        """Check AWS Well-Architected security pillar compliance."""
        monitoring_config = security_config.get('monitoring_config', {})
        
        required_controls = [
            monitoring_config.get('cloudtrail_enabled', False),
            monitoring_config.get('config_enabled', False),
            len(security_config.get('iam_roles', [])) > 0
        ]
        
        return all(required_controls)
    
    async def _check_hipaa_compliance(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> bool:
        """Check HIPAA compliance."""
        # Basic HIPAA requirements
        encryption_config = security_config.get('encryption_config', {})
        monitoring_config = security_config.get('monitoring_config', {})
        
        required_controls = [
            encryption_config.get('ebs_encryption', False),
            encryption_config.get('encryption_in_transit', False),
            monitoring_config.get('cloudtrail_enabled', False),
            monitoring_config.get('access_analyzer_enabled', False)
        ]
        
        return all(required_controls)
    
    async def _check_pci_dss_compliance(self, infra_config: Dict[str, Any], security_config: SecurityConfiguration) -> bool:
        """Check PCI DSS compliance."""
        # Basic PCI DSS requirements
        encryption_config = security_config.get('encryption_config', {})
        monitoring_config = security_config.get('monitoring_config', {})
        
        required_controls = [
            encryption_config.get('ebs_encryption', False),
            encryption_config.get('encryption_in_transit', False),
            monitoring_config.get('cloudtrail_enabled', False),
            monitoring_config.get('security_hub_enabled', False)
        ]
        
        return all(required_controls)
    
    # Utility methods
    
    def _calculate_security_score(self, vulnerabilities: List[Dict[str, Any]], compliance_status: Dict[str, bool]) -> float:
        """Calculate overall security score."""
        base_score = 100.0
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            if severity == 'critical':
                base_score -= 20
            elif severity == 'high':
                base_score -= 10
            elif severity == 'medium':
                base_score -= 5
            else:  # low
                base_score -= 2
        
        # Deduct points for compliance failures
        total_compliance = len(compliance_status)
        passed_compliance = sum(1 for passed in compliance_status.values() if passed)
        
        if total_compliance > 0:
            compliance_score = (passed_compliance / total_compliance) * 20
            base_score = base_score * 0.8 + compliance_score
        
        return max(0.0, min(100.0, base_score))
    
    def _determine_risk_level(self, security_score: float, vulnerabilities: List[Dict[str, Any]]) -> SecurityLevel:
        """Determine risk level based on security score and vulnerabilities."""
        critical_vulns = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high_vulns = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        
        if critical_vulns > 0 or security_score < 40:
            return SecurityLevel.CRITICAL
        elif high_vulns > 2 or security_score < 60:
            return SecurityLevel.HIGH
        elif security_score < 80:
            return SecurityLevel.MEDIUM
        else:
            return SecurityLevel.LOW
    
    async def _generate_security_controls(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        compliance_status: Dict[str, bool], 
        risk_level: SecurityLevel
    ) -> Dict[str, Any]:
        """Generate security controls based on assessment."""
        controls = {
            'required_actions': [],
            'recommended_actions': [],
            'monitoring_requirements': [],
            'compliance_actions': []
        }
        
        # Required actions for high-risk vulnerabilities
        for vuln in vulnerabilities:
            if vuln.get('severity') in ['critical', 'high']:
                controls['required_actions'].append({
                    'action': vuln.get('remediation', 'Review and fix vulnerability'),
                    'priority': 'high',
                    'resource': vuln.get('resource', 'unknown'),
                    'timeline': '24 hours' if vuln.get('severity') == 'critical' else '7 days'
                })
        
        # Compliance actions
        for standard, passed in compliance_status.items():
            if not passed:
                controls['compliance_actions'].append({
                    'action': f'Address {standard} compliance requirements',
                    'priority': 'medium',
                    'timeline': '30 days'
                })
        
        # Risk-based recommendations
        if risk_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            controls['recommended_actions'].extend([
                'Implement AWS Config rules for continuous compliance monitoring',
                'Enable AWS Security Hub for centralized security findings',
                'Set up automated incident response procedures'
            ])
        
        return controls
    
    # IAM resource creation methods
    
    async def _create_iam_role(self, role_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create IAM role in AWS."""
        try:
            response = self.iam_client.create_role(
                RoleName=role_config['name'],
                AssumeRolePolicyDocument=json.dumps(role_config['trust_policy']),
                Description=role_config.get('description', ''),
                MaxSessionDuration=role_config.get('max_session_duration', 3600)
            )
            
            # Attach policies
            for policy_arn in role_config.get('policies', []):
                self.iam_client.attach_role_policy(
                    RoleName=role_config['name'],
                    PolicyArn=policy_arn
                )
            
            return {
                'role_name': role_config['name'],
                'role_arn': response['Role']['Arn'],
                'created_at': response['Role']['CreateDate'],
                'policies_attached': role_config.get('policies', [])
            }
            
        except Exception as e:
            if 'EntityAlreadyExists' in str(e):
                self.logger.warning(f"IAM role {role_config['name']} already exists")
                return {
                    'role_name': role_config['name'],
                    'role_arn': f"arn:aws:iam::{self._get_account_id()}:role/{role_config['name']}",
                    'status': 'already_exists'
                }
            else:
                raise
    
    async def _create_iam_policy(self, policy_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create IAM policy in AWS."""
        try:
            response = self.iam_client.create_policy(
                PolicyName=policy_config['name'],
                PolicyDocument=json.dumps(policy_config['policy_document']),
                Description=policy_config.get('description', '')
            )
            
            return {
                'policy_name': policy_config['name'],
                'policy_arn': response['Policy']['Arn'],
                'created_at': response['Policy']['CreateDate'],
                'version': response['Policy']['DefaultVersionId']
            }
            
        except Exception as e:
            if 'EntityAlreadyExists' in str(e):
                self.logger.warning(f"IAM policy {policy_config['name']} already exists")
                return {
                    'policy_name': policy_config['name'],
                    'policy_arn': f"arn:aws:iam::{self._get_account_id()}:policy/{policy_config['name']}",
                    'status': 'already_exists'
                }
            else:
                raise
    
    # Validation methods
    
    async def _validate_iam_role(self, role_config: Dict[str, Any]) -> List[str]:
        """Validate IAM role configuration."""
        errors = []
        
        # Check role name
        if not role_config.get('name'):
            errors.append("IAM role name is required")
        elif len(role_config['name']) > 64:
            errors.append(f"IAM role name too long: {role_config['name']}")
        
        # Check trust policy
        if not role_config.get('trust_policy'):
            errors.append(f"Trust policy is required for role {role_config.get('name')}")
        
        # Check policies
        policies = role_config.get('policies', [])
        if not policies:
            errors.append(f"At least one policy is required for role {role_config.get('name')}")
        
        return errors
    
    async def _validate_security_policy(self, policy_config: Dict[str, Any]) -> List[str]:
        """Validate security policy configuration."""
        errors = []
        
        # Check policy name
        if not policy_config.get('name'):
            errors.append("Policy name is required")
        
        # Check policy document
        policy_doc = policy_config.get('policy_document')
        if not policy_doc:
            errors.append(f"Policy document is required for {policy_config.get('name')}")
        elif not policy_doc.get('Statement'):
            errors.append(f"Policy document must contain statements for {policy_config.get('name')}")
        
        return errors
    
    async def _validate_network_configuration(self, security_config: SecurityConfiguration) -> List[str]:
        """Validate network security configuration."""
        errors = []
        
        security_groups = security_config.get('security_groups', [])
        
        for sg in security_groups:
            if not sg.get('name'):
                errors.append("Security group name is required")
            
            rules = sg.get('rules', [])
            if not rules:
                errors.append(f"Security group {sg.get('name')} has no rules")
            
            for rule in rules:
                if rule.get('type') not in ['ingress', 'egress']:
                    errors.append(f"Invalid rule type in security group {sg.get('name')}: {rule.get('type')}")
        
        return errors
    
    async def _validate_encryption_configuration(self, security_config: SecurityConfiguration) -> List[str]:
        """Validate encryption configuration."""
        errors = []
        
        encryption_config = security_config.get('encryption_config', {})
        
        # Check required encryption settings
        required_settings = ['ebs_encryption', 's3_encryption', 'secrets_encryption']
        for setting in required_settings:
            if not encryption_config.get(setting):
                errors.append(f"Encryption setting {setting} should be enabled")
        
        return errors 