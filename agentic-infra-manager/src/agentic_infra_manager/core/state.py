"""
Core agent state management for LangGraph workflows.

This module defines the state structure used throughout the agent's decision-making process.
"""

from typing import TypedDict, List, Dict, Optional, Any, Literal
from datetime import datetime
from enum import Enum
import uuid


class DeploymentPhase(Enum):
    """Deployment phases for tracking progress."""
    INITIALIZATION = "initialization"
    REPOSITORY_ANALYSIS = "repository_analysis"
    INFRASTRUCTURE_PLANNING = "infrastructure_planning"
    SECURITY_ASSESSMENT = "security_assessment"
    RESOURCE_OPTIMIZATION = "resource_optimization"
    TOPOLOGY_GENERATION = "topology_generation"
    CODE_GENERATION = "code_generation"
    DEPLOYMENT = "deployment"
    MONITORING = "monitoring"
    OPTIMIZATION = "optimization"
    COMPLETED = "completed"
    FAILED = "failed"


class ApplicationType(Enum):
    """Types of applications that can be deployed."""
    WEB_APP = "web_app"
    API_SERVICE = "api_service"
    MICROSERVICE = "microservice"
    DATA_PIPELINE = "data_pipeline"
    ML_SERVICE = "ml_service"
    BATCH_JOB = "batch_job"
    STATIC_SITE = "static_site"
    DATABASE = "database"
    QUEUE_WORKER = "queue_worker"
    UNKNOWN = "unknown"


class InfrastructureRequirement(TypedDict):
    """Infrastructure requirement specification."""
    compute: Dict[str, Any]
    storage: Dict[str, Any]
    networking: Dict[str, Any]
    security: Dict[str, Any]
    monitoring: Dict[str, Any]
    estimated_cost: float
    compliance_requirements: List[str]


class RepositoryAnalysis(TypedDict):
    """Repository analysis results."""
    url: str
    name: str
    language: str
    framework: str
    dependencies: List[str]
    application_type: ApplicationType
    dockerfile_present: bool
    k8s_manifests_present: bool
    infrastructure_requirements: InfrastructureRequirement
    security_analysis: Dict[str, Any]
    complexity_score: float
    estimated_resources: Dict[str, Any]


class SecurityConfiguration(TypedDict):
    """Security configuration for infrastructure."""
    iam_roles: List[Dict[str, Any]]
    policies: List[Dict[str, Any]]
    security_groups: List[Dict[str, Any]]
    network_acls: List[Dict[str, Any]]
    encryption_config: Dict[str, Any]
    compliance_controls: List[str]
    vulnerability_scan_results: Optional[Dict[str, Any]]


class InfrastructurePlan(TypedDict):
    """Infrastructure deployment plan."""
    plan_id: str
    vpc_configuration: Dict[str, Any]
    eks_configuration: Dict[str, Any]
    compute_resources: List[Dict[str, Any]]
    storage_resources: List[Dict[str, Any]]
    networking_config: Dict[str, Any]
    security_config: SecurityConfiguration
    monitoring_config: Dict[str, Any]
    estimated_cost: Dict[str, float]
    deployment_timeline: Dict[str, datetime]
    terraform_code: Optional[str]
    cdk_code: Optional[str]
    k8s_manifests: Optional[List[str]]


class DeploymentResult(TypedDict):
    """Deployment execution results."""
    deployment_id: str
    status: Literal["pending", "in_progress", "completed", "failed", "rolled_back"]
    cluster_name: str
    cluster_arn: str
    vpc_id: str
    application_endpoints: List[str]
    monitoring_dashboards: List[str]
    cost_analysis: Dict[str, float]
    security_scan_results: Dict[str, Any]
    deployment_logs: List[str]
    rollback_plan: Optional[Dict[str, Any]]


class MonitoringData(TypedDict):
    """Infrastructure monitoring data."""
    cluster_metrics: Dict[str, Any]
    application_metrics: Dict[str, Any]
    cost_metrics: Dict[str, float]
    security_metrics: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    recommendations: List[str]
    last_updated: datetime


class AgentState(TypedDict):
    """
    Main state object for the infrastructure agent using LangGraph.
    
    This state is passed between all nodes in the LangGraph workflow and maintains
    the complete context of the agent's decision-making process.
    """
    # Session Management
    session_id: str
    agent_version: str
    created_at: datetime
    last_updated: datetime
    current_phase: DeploymentPhase
    
    # Input Data
    repository_url: Optional[str]
    target_environment: str  # dev, staging, prod
    deployment_region: str
    user_requirements: Dict[str, Any]
    
    # Analysis Results
    repository_analysis: Optional[RepositoryAnalysis]
    infrastructure_requirements: Optional[InfrastructureRequirement]
    security_assessment: Optional[SecurityConfiguration]
    
    # Planning Results
    infrastructure_plan: Optional[InfrastructurePlan]
    deployment_strategy: Optional[str]
    optimization_recommendations: List[str]
    
    # Deployment Results
    deployment_result: Optional[DeploymentResult]
    monitoring_data: Optional[MonitoringData]
    
    # Agent Decision Making
    decision_history: List[Dict[str, Any]]
    current_decisions: Dict[str, Any]
    confidence_scores: Dict[str, float]
    
    # Error Handling
    errors: List[str]
    warnings: List[str]
    rollback_required: bool
    
    # Progress Tracking
    progress_percentage: float
    completed_steps: List[str]
    pending_steps: List[str]
    
    # Resource Management
    created_resources: List[Dict[str, Any]]
    resource_dependencies: Dict[str, List[str]]
    cleanup_required: List[str]
    
    # Cost Management
    estimated_monthly_cost: float
    actual_costs: Dict[str, float]
    budget_alerts: List[str]
    
    # Compliance and Security
    compliance_status: Dict[str, bool]
    security_violations: List[str]
    audit_trail: List[Dict[str, Any]]


def create_initial_state(
    repository_url: Optional[str] = None,
    target_environment: str = "dev",
    deployment_region: str = "us-west-2",
    user_requirements: Optional[Dict[str, Any]] = None
) -> AgentState:
    """
    Create an initial agent state for a new deployment session.
    
    Args:
        repository_url: Git repository URL to analyze
        target_environment: Target deployment environment
        deployment_region: AWS region for deployment
        user_requirements: Additional user-specified requirements
        
    Returns:
        Initial AgentState instance
    """
    session_id = str(uuid.uuid4())
    now = datetime.utcnow()
    
    return AgentState(
        # Session Management
        session_id=session_id,
        agent_version="0.1.0",
        created_at=now,
        last_updated=now,
        current_phase=DeploymentPhase.INITIALIZATION,
        
        # Input Data
        repository_url=repository_url,
        target_environment=target_environment,
        deployment_region=deployment_region,
        user_requirements=user_requirements or {},
        
        # Analysis Results
        repository_analysis=None,
        infrastructure_requirements=None,
        security_assessment=None,
        
        # Planning Results
        infrastructure_plan=None,
        deployment_strategy=None,
        optimization_recommendations=[],
        
        # Deployment Results
        deployment_result=None,
        monitoring_data=None,
        
        # Agent Decision Making
        decision_history=[],
        current_decisions={},
        confidence_scores={},
        
        # Error Handling
        errors=[],
        warnings=[],
        rollback_required=False,
        
        # Progress Tracking
        progress_percentage=0.0,
        completed_steps=[],
        pending_steps=[
            "repository_analysis",
            "infrastructure_planning", 
            "security_assessment",
            "resource_optimization",
            "deployment"
        ],
        
        # Resource Management
        created_resources=[],
        resource_dependencies={},
        cleanup_required=[],
        
        # Cost Management
        estimated_monthly_cost=0.0,
        actual_costs={},
        budget_alerts=[],
        
        # Compliance and Security
        compliance_status={},
        security_violations=[],
        audit_trail=[{
            "timestamp": now,
            "action": "session_initialized",
            "details": {
                "session_id": session_id,
                "repository_url": repository_url,
                "target_environment": target_environment
            }
        }]
    )


def update_state_phase(state: AgentState, new_phase: DeploymentPhase) -> AgentState:
    """
    Update the current phase and related metadata.
    
    Args:
        state: Current agent state
        new_phase: New deployment phase
        
    Returns:
        Updated agent state
    """
    updated_state = state.copy()
    updated_state["current_phase"] = new_phase
    updated_state["last_updated"] = datetime.utcnow()
    
    # Add to audit trail
    updated_state["audit_trail"].append({
        "timestamp": datetime.utcnow(),
        "action": "phase_transition",
        "details": {
            "previous_phase": state["current_phase"],
            "new_phase": new_phase
        }
    })
    
    return updated_state


def add_error(state: AgentState, error_message: str, error_details: Optional[Dict[str, Any]] = None) -> AgentState:
    """
    Add an error to the agent state.
    
    Args:
        state: Current agent state
        error_message: Error message
        error_details: Additional error details
        
    Returns:
        Updated agent state
    """
    updated_state = state.copy()
    updated_state["errors"].append(error_message)
    updated_state["last_updated"] = datetime.utcnow()
    
    # Add to audit trail
    updated_state["audit_trail"].append({
        "timestamp": datetime.utcnow(),
        "action": "error_occurred",
        "details": {
            "error_message": error_message,
            "error_details": error_details or {}
        }
    })
    
    return updated_state


def add_warning(state: AgentState, warning_message: str) -> AgentState:
    """
    Add a warning to the agent state.
    
    Args:
        state: Current agent state
        warning_message: Warning message
        
    Returns:
        Updated agent state
    """
    updated_state = state.copy()
    updated_state["warnings"].append(warning_message)
    updated_state["last_updated"] = datetime.utcnow()
    
    return updated_state


def update_progress(state: AgentState, step_name: str, percentage_increment: float = 0.0) -> AgentState:
    """
    Update progress tracking for a completed step.
    
    Args:
        state: Current agent state
        step_name: Name of the completed step
        percentage_increment: Progress percentage to add
        
    Returns:
        Updated agent state
    """
    updated_state = state.copy()
    
    # Move from pending to completed
    if step_name in updated_state["pending_steps"]:
        updated_state["pending_steps"].remove(step_name)
    
    if step_name not in updated_state["completed_steps"]:
        updated_state["completed_steps"].append(step_name)
    
    # Update progress percentage
    updated_state["progress_percentage"] = min(
        100.0, 
        updated_state["progress_percentage"] + percentage_increment
    )
    
    updated_state["last_updated"] = datetime.utcnow()
    
    return updated_state 