"""
Configuration management for the Agentic Infrastructure Management System.

This module handles loading and validation of agent configuration from files,
environment variables, and runtime parameters.
"""

import os
import yaml
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AWSConfig:
    """AWS-specific configuration."""
    region: str = "us-west-2"
    profile: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    assume_role_arn: Optional[str] = None
    external_id: Optional[str] = None
    
    @classmethod
    def from_environment(cls) -> "AWSConfig":
        """Load AWS configuration from environment variables."""
        return cls(
            region=os.getenv("AWS_REGION", "us-west-2"),
            profile=os.getenv("AWS_PROFILE"),
            access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            session_token=os.getenv("AWS_SESSION_TOKEN"),
            assume_role_arn=os.getenv("AWS_ASSUME_ROLE_ARN"),
            external_id=os.getenv("AWS_EXTERNAL_ID")
        )


@dataclass
class SecurityConfig:
    """Security-related configuration."""
    root_credential_usage: str = "initial_setup_only"
    iam_role_prefix: str = "agent-"
    enable_security_scanning: bool = True
    encryption_at_rest: bool = True
    encryption_in_transit: bool = True
    compliance_frameworks: List[str] = field(default_factory=lambda: ["AWS-Well-Architected"])
    secrets_manager_integration: bool = True
    security_scan_schedule: str = "daily"
    vulnerability_threshold: str = "medium"
    

@dataclass
class KubernetesConfig:
    """Kubernetes cluster configuration."""
    cluster_version: str = "1.28"
    node_instance_types: List[str] = field(default_factory=lambda: ["t3.medium", "t3.large"])
    min_nodes: int = 1
    max_nodes: int = 10
    desired_nodes: int = 2
    enable_auto_scaling: bool = True
    enable_cluster_autoscaler: bool = True
    enable_metrics_server: bool = True
    enable_pod_security_standards: bool = True
    network_plugin: str = "aws-vpc-cni"
    logging_enabled: bool = True
    monitoring_enabled: bool = True


@dataclass
class MonitoringConfig:
    """Monitoring and observability configuration."""
    enable_cloudwatch: bool = True
    enable_prometheus: bool = True
    enable_grafana: bool = True
    enable_jaeger: bool = False
    retention_days: int = 30
    alert_email: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    log_level: str = "INFO"
    metrics_collection_interval: int = 60
    custom_dashboards: List[str] = field(default_factory=list)


@dataclass
class CostConfig:
    """Cost management configuration."""
    budget_limit_monthly: Optional[float] = None
    cost_alert_threshold: float = 0.8
    enable_cost_optimization: bool = True
    spot_instance_usage: bool = True
    reserved_instance_recommendations: bool = True
    idle_resource_detection: bool = True
    cost_reporting_frequency: str = "weekly"


@dataclass
class DeploymentConfig:
    """Deployment strategy configuration."""
    default_strategy: str = "rolling"  # rolling, blue-green, canary
    timeout_minutes: int = 30
    health_check_retries: int = 3
    rollback_on_failure: bool = True
    parallel_deployments: bool = False
    deployment_environments: List[str] = field(default_factory=lambda: ["dev", "staging", "prod"])
    approval_required: Dict[str, bool] = field(default_factory=lambda: {"prod": True})


@dataclass
class AgentConfig:
    """Main agent configuration."""
    # Basic agent settings
    name: str = "Infrastructure AI Agent"
    version: str = "0.1.0"
    workspace: str = "/tmp/agent-workspace"
    log_level: str = "INFO"
    
    # AI/LLM settings
    openai_api_key: Optional[str] = None
    model_name: str = "gpt-4"
    temperature: float = 0.1
    max_tokens: int = 4000
    
    # Component configurations
    aws: AWSConfig = field(default_factory=AWSConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    kubernetes: KubernetesConfig = field(default_factory=KubernetesConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    cost: CostConfig = field(default_factory=CostConfig)
    deployment: DeploymentConfig = field(default_factory=DeploymentConfig)
    
    # Git integration
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    
    # Additional settings
    dry_run: bool = False
    debug_mode: bool = False
    backup_enabled: bool = True
    state_persistence: bool = True
    
    @classmethod
    def from_file(cls, config_path: str) -> "AgentConfig":
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            AgentConfig instance
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid YAML
        """
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        return cls.from_dict(config_data)
    
    @classmethod
    def from_dict(cls, config_data: Dict[str, Any]) -> "AgentConfig":
        """
        Create configuration from a dictionary.
        
        Args:
            config_data: Configuration dictionary
            
        Returns:
            AgentConfig instance
        """
        # Extract component configurations
        aws_config = AWSConfig(**config_data.get("aws", {}))
        security_config = SecurityConfig(**config_data.get("security", {}))
        kubernetes_config = KubernetesConfig(**config_data.get("kubernetes", {}))
        monitoring_config = MonitoringConfig(**config_data.get("monitoring", {}))
        cost_config = CostConfig(**config_data.get("cost", {}))
        deployment_config = DeploymentConfig(**config_data.get("deployment", {}))
        
        # Extract agent-level configuration
        agent_data = config_data.get("agent", {})
        
        return cls(
            name=agent_data.get("name", "Infrastructure AI Agent"),
            version=agent_data.get("version", "0.1.0"),
            workspace=agent_data.get("workspace", "/tmp/agent-workspace"),
            log_level=agent_data.get("log_level", "INFO"),
            openai_api_key=config_data.get("openai_api_key"),
            model_name=config_data.get("model_name", "gpt-4"),
            temperature=config_data.get("temperature", 0.1),
            max_tokens=config_data.get("max_tokens", 4000),
            github_token=config_data.get("github_token"),
            gitlab_token=config_data.get("gitlab_token"),
            dry_run=config_data.get("dry_run", False),
            debug_mode=config_data.get("debug_mode", False),
            backup_enabled=config_data.get("backup_enabled", True),
            state_persistence=config_data.get("state_persistence", True),
            aws=aws_config,
            security=security_config,
            kubernetes=kubernetes_config,
            monitoring=monitoring_config,
            cost=cost_config,
            deployment=deployment_config
        )
    
    @classmethod
    def from_environment(cls) -> "AgentConfig":
        """
        Load configuration from environment variables.
        
        Returns:
            AgentConfig instance with environment variable values
        """
        aws_config = AWSConfig.from_environment()
        
        return cls(
            name=os.getenv("AGENT_NAME", "Infrastructure AI Agent"),
            workspace=os.getenv("AGENT_WORKSPACE", "/tmp/agent-workspace"),
            log_level=os.getenv("AGENT_LOG_LEVEL", "INFO"),
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            model_name=os.getenv("AGENT_MODEL_NAME", "gpt-4"),
            github_token=os.getenv("GITHUB_TOKEN"),
            gitlab_token=os.getenv("GITLAB_TOKEN"),
            dry_run=os.getenv("AGENT_DRY_RUN", "false").lower() == "true",
            debug_mode=os.getenv("AGENT_DEBUG", "false").lower() == "true",
            aws=aws_config
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Configuration as dictionary
        """
        return {
            "agent": {
                "name": self.name,
                "version": self.version,
                "workspace": self.workspace,
                "log_level": self.log_level
            },
            "openai_api_key": self.openai_api_key,
            "model_name": self.model_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "github_token": self.github_token,
            "gitlab_token": self.gitlab_token,
            "dry_run": self.dry_run,
            "debug_mode": self.debug_mode,
            "backup_enabled": self.backup_enabled,
            "state_persistence": self.state_persistence,
            "aws": {
                "region": self.aws.region,
                "profile": self.aws.profile,
                "assume_role_arn": self.aws.assume_role_arn,
                "external_id": self.aws.external_id
            },
            "security": {
                "root_credential_usage": self.security.root_credential_usage,
                "iam_role_prefix": self.security.iam_role_prefix,
                "enable_security_scanning": self.security.enable_security_scanning,
                "encryption_at_rest": self.security.encryption_at_rest,
                "encryption_in_transit": self.security.encryption_in_transit,
                "compliance_frameworks": self.security.compliance_frameworks
            },
            "kubernetes": {
                "cluster_version": self.kubernetes.cluster_version,
                "node_instance_types": self.kubernetes.node_instance_types,
                "min_nodes": self.kubernetes.min_nodes,
                "max_nodes": self.kubernetes.max_nodes,
                "desired_nodes": self.kubernetes.desired_nodes,
                "enable_auto_scaling": self.kubernetes.enable_auto_scaling
            },
            "monitoring": {
                "enable_cloudwatch": self.monitoring.enable_cloudwatch,
                "enable_prometheus": self.monitoring.enable_prometheus,
                "enable_grafana": self.monitoring.enable_grafana,
                "retention_days": self.monitoring.retention_days,
                "log_level": self.monitoring.log_level
            },
            "cost": {
                "budget_limit_monthly": self.cost.budget_limit_monthly,
                "cost_alert_threshold": self.cost.cost_alert_threshold,
                "enable_cost_optimization": self.cost.enable_cost_optimization,
                "spot_instance_usage": self.cost.spot_instance_usage
            },
            "deployment": {
                "default_strategy": self.deployment.default_strategy,
                "timeout_minutes": self.deployment.timeout_minutes,
                "rollback_on_failure": self.deployment.rollback_on_failure,
                "deployment_environments": self.deployment.deployment_environments
            }
        }
    
    def save_to_file(self, config_path: str) -> None:
        """
        Save configuration to a YAML file.
        
        Args:
            config_path: Path where to save the configuration
        """
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, indent=2)
    
    def validate(self) -> List[str]:
        """
        Validate the configuration and return any errors.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Validate required fields
        if not self.aws.region:
            errors.append("AWS region is required")
        
        # Validate workspace path
        workspace_path = Path(self.workspace)
        try:
            workspace_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create workspace directory: {e}")
        
        # Validate Kubernetes configuration
        if self.kubernetes.min_nodes > self.kubernetes.max_nodes:
            errors.append("Kubernetes min_nodes cannot be greater than max_nodes")
        
        if self.kubernetes.desired_nodes < self.kubernetes.min_nodes:
            errors.append("Kubernetes desired_nodes cannot be less than min_nodes")
        
        if self.kubernetes.desired_nodes > self.kubernetes.max_nodes:
            errors.append("Kubernetes desired_nodes cannot be greater than max_nodes")
        
        # Validate cost configuration
        if self.cost.cost_alert_threshold < 0 or self.cost.cost_alert_threshold > 1:
            errors.append("Cost alert threshold must be between 0 and 1")
        
        # Validate deployment configuration
        valid_strategies = ["rolling", "blue-green", "canary"]
        if self.deployment.default_strategy not in valid_strategies:
            errors.append(f"Deployment strategy must be one of: {valid_strategies}")
        
        if self.deployment.timeout_minutes <= 0:
            errors.append("Deployment timeout must be positive")
        
        return errors


def load_config(config_path: Optional[str] = None) -> AgentConfig:
    """
    Load agent configuration from file or environment.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        AgentConfig instance
        
    Raises:
        ValueError: If configuration validation fails
    """
    if config_path:
        config = AgentConfig.from_file(config_path)
    else:
        # Try to find default config file
        default_paths = [
            "config/agent.yaml",
            "agent.yaml",
            os.path.expanduser("~/.agent/config.yaml")
        ]
        
        config_found = False
        for path in default_paths:
            if Path(path).exists():
                config = AgentConfig.from_file(path)
                config_found = True
                break
        
        if not config_found:
            # Fall back to environment variables
            config = AgentConfig.from_environment()
    
    # Validate configuration
    errors = config.validate()
    if errors:
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return config 