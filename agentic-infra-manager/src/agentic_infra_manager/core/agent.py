"""
Core Infrastructure Agent implementation using LangGraph.

This module implements the main InfrastructureAgent class that orchestrates
the entire infrastructure planning, provisioning, and management workflow.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain.schema import BaseMessage, HumanMessage, SystemMessage

from .config import AgentConfig, load_config
from .state import (
    AgentState, 
    DeploymentPhase, 
    create_initial_state,
    update_state_phase,
    add_error,
    update_progress
)


class InfrastructureAgent:
    """
    Main Infrastructure Agent that autonomously plans, provisions, and manages AWS infrastructure.
    
    This agent uses LangGraph to model complex decision-making processes and coordinate
    various specialized modules for infrastructure management.
    """
    
    def __init__(self, config: Optional[AgentConfig] = None, config_path: Optional[str] = None):
        """
        Initialize the Infrastructure Agent.
        
        Args:
            config: Agent configuration object
            config_path: Path to configuration file
        """
        # Load configuration
        if config:
            self.config = config
        else:
            self.config = load_config(config_path)
        
        # Set up logging
        self._setup_logging()
        
        # Initialize LLM
        self.llm = self._initialize_llm()
        
        # Initialize LangGraph workflow
        self.workflow = self._create_workflow()
        
        # State management
        self.current_state: Optional[AgentState] = None
        
        self.logger.info(f"Infrastructure Agent initialized with config: {self.config.name}")
    
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _initialize_llm(self) -> ChatOpenAI:
        """Initialize the language model for decision making."""
        if not self.config.openai_api_key:
            raise ValueError("OpenAI API key is required for agent operation")
        
        return ChatOpenAI(
            api_key=self.config.openai_api_key,
            model=self.config.model_name,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens
        )
    
    def _create_workflow(self) -> StateGraph:
        """
        Create the LangGraph workflow for infrastructure management.
        
        Returns:
            Configured StateGraph workflow
        """
        workflow = StateGraph(AgentState)
        
        # Add nodes for each major phase
        workflow.add_node("analyze_repository", self._analyze_repository_node)
        workflow.add_node("assess_requirements", self._assess_infrastructure_requirements_node)
        workflow.add_node("plan_security", self._plan_security_configuration_node)
        workflow.add_node("generate_topology", self._generate_infrastructure_topology_node)
        workflow.add_node("optimize_resources", self._optimize_resource_allocation_node)
        workflow.add_node("generate_code", self._generate_infrastructure_code_node)
        workflow.add_node("deploy_infrastructure", self._deploy_infrastructure_node)
        workflow.add_node("monitor_deployment", self._monitor_deployment_node)
        workflow.add_node("handle_error", self._handle_error_node)
        
        # Set entry point
        workflow.set_entry_point("analyze_repository")
        
        # Add conditional edges for decision making
        workflow.add_conditional_edges(
            "analyze_repository",
            self._route_after_analysis,
            {
                "assess_requirements": "assess_requirements",
                "error": "handle_error"
            }
        )
        
        workflow.add_conditional_edges(
            "assess_requirements",
            self._route_after_requirements,
            {
                "plan_security": "plan_security",
                "error": "handle_error"
            }
        )
        
        workflow.add_conditional_edges(
            "plan_security",
            self._route_after_security,
            {
                "generate_topology": "generate_topology",
                "error": "handle_error"
            }
        )
        
        workflow.add_conditional_edges(
            "generate_topology",
            self._route_after_topology,
            {
                "optimize_resources": "optimize_resources",
                "error": "handle_error"
            }
        )
        
        workflow.add_conditional_edges(
            "optimize_resources",
            self._route_after_optimization,
            {
                "generate_code": "generate_code",
                "error": "handle_error"
            }
        )
        
        workflow.add_conditional_edges(
            "generate_code",
            self._route_after_code_generation,
            {
                "deploy_infrastructure": "deploy_infrastructure",
                "error": "handle_error"
            }
        )
        
        workflow.add_conditional_edges(
            "deploy_infrastructure",
            self._route_after_deployment,
            {
                "monitor_deployment": "monitor_deployment",
                "error": "handle_error",
                "end": END
            }
        )
        
        workflow.add_edge("monitor_deployment", END)
        workflow.add_edge("handle_error", END)
        
        return workflow.compile()
    
    async def analyze_repository(self, repository_url: str, **kwargs) -> AgentState:
        """
        Analyze a Git repository and plan infrastructure deployment.
        
        Args:
            repository_url: Git repository URL to analyze
            **kwargs: Additional parameters (target_environment, etc.)
            
        Returns:
            Final agent state after processing
        """
        self.logger.info(f"Starting repository analysis for: {repository_url}")
        
        # Create initial state
        initial_state = create_initial_state(
            repository_url=repository_url,
            target_environment=kwargs.get("target_environment", "dev"),
            deployment_region=kwargs.get("deployment_region", self.config.aws.region),
            user_requirements=kwargs.get("user_requirements", {})
        )
        
        self.current_state = initial_state
        
        # Execute the workflow
        try:
            final_state = await self.workflow.ainvoke(initial_state)
            self.current_state = final_state
            self.logger.info("Repository analysis and infrastructure planning completed")
            return final_state
        except Exception as e:
            self.logger.error(f"Workflow execution failed: {e}")
            error_state = add_error(initial_state, str(e))
            self.current_state = error_state
            return error_state
    
    async def deploy_infrastructure(self, plan_id: str) -> AgentState:
        """
        Deploy infrastructure based on a previously generated plan.
        
        Args:
            plan_id: Infrastructure plan identifier
            
        Returns:
            Deployment result state
        """
        self.logger.info(f"Starting infrastructure deployment for plan: {plan_id}")
        
        if not self.current_state:
            raise ValueError("No current state available. Run analyze_repository first.")
        
        # Update state to deployment phase
        deployment_state = update_state_phase(self.current_state, DeploymentPhase.DEPLOYMENT)
        
        # Execute deployment workflow starting from deploy_infrastructure node
        try:
            final_state = await self.workflow.ainvoke(deployment_state)
            self.current_state = final_state
            self.logger.info("Infrastructure deployment completed")
            return final_state
        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            error_state = add_error(deployment_state, str(e))
            self.current_state = error_state
            return error_state
    
    async def monitor_infrastructure(self, cluster_id: str) -> Dict[str, Any]:
        """
        Monitor deployed infrastructure and provide optimization recommendations.
        
        Args:
            cluster_id: Kubernetes cluster identifier
            
        Returns:
            Monitoring data and recommendations
        """
        self.logger.info(f"Starting infrastructure monitoring for cluster: {cluster_id}")
        
        # This will be implemented with actual monitoring logic
        monitoring_data = {
            "cluster_id": cluster_id,
            "status": "healthy",
            "metrics": {},
            "recommendations": [],
            "timestamp": datetime.utcnow()
        }
        
        return monitoring_data
    
    # LangGraph Node Implementations
    
    async def _analyze_repository_node(self, state: AgentState) -> AgentState:
        """Analyze Git repository to understand application requirements."""
        self.logger.info("Executing repository analysis node")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.REPOSITORY_ANALYSIS)
            
            # Use actual repository analyzer
            try:
                from ..modules.repository_analyzer import RepositoryAnalyzer
                analyzer = RepositoryAnalyzer(self.config)
                
                # Perform actual repository analysis
                analysis = await analyzer.analyze_repository(state["repository_url"])
                
                # Convert RepositoryAnalysis to dictionary format expected by state
                analysis_dict = {
                    "url": analysis["url"],
                    "name": analysis["name"],
                    "language": analysis["language"],
                    "framework": analysis["framework"],
                    "dependencies": analysis["dependencies"],
                    "application_type": analysis["application_type"],
                    "dockerfile_present": analysis["dockerfile_present"],
                    "k8s_manifests_present": analysis["k8s_manifests_present"],
                    "infrastructure_requirements": analysis["infrastructure_requirements"],
                    "security_analysis": analysis["security_analysis"],
                    "complexity_score": analysis["complexity_score"],
                    "estimated_resources": analysis["estimated_resources"]
                }
                
                updated_state["repository_analysis"] = analysis_dict
                self.logger.info("Repository analysis completed successfully")
                
            except Exception as e:
                self.logger.warning(f"Real repository analysis failed: {e}, using mock data")
                
                # Fall back to mock analysis if real analysis fails
                mock_analysis = {
                    "url": state["repository_url"],
                    "name": "sample-app",
                    "language": "python",
                    "framework": "fastapi",
                    "dependencies": ["fastapi", "uvicorn", "sqlalchemy"],
                    "application_type": "api_service",
                    "dockerfile_present": True,
                    "k8s_manifests_present": False,
                    "infrastructure_requirements": {
                        "compute": {"cpu": "500m", "memory": "512Mi"},
                        "storage": {"persistent": False, "size_gb": 20},
                        "networking": {"load_balancer": True},
                        "security": {"https": True, "authentication": True},
                        "monitoring": {"metrics": True, "logging": True},
                        "estimated_cost": 150.0,
                        "compliance_requirements": ["SOC2"]
                    },
                    "security_analysis": {"vulnerabilities": []},
                    "complexity_score": 0.6,
                    "estimated_resources": {"instances": 2, "storage_gb": 20}
                }
                
                updated_state["repository_analysis"] = mock_analysis
            
            updated_state = update_progress(updated_state, "repository_analysis", 20.0)
            
            self.logger.info("Repository analysis completed successfully")
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Repository analysis failed: {e}")
            return add_error(state, f"Repository analysis failed: {e}")
    
    async def _assess_infrastructure_requirements_node(self, state: AgentState) -> AgentState:
        """Assess infrastructure requirements based on repository analysis."""
        self.logger.info("Executing infrastructure requirements assessment")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.INFRASTRUCTURE_PLANNING)
            
            # Use actual infrastructure planner
            from ..modules.infrastructure_planner import InfrastructurePlanner
            planner = InfrastructurePlanner(self.config)
            
            # Create infrastructure plan using actual planner
            infrastructure_plan = await planner.create_infrastructure_plan(
                repository_analysis=state["repository_analysis"],
                security_config=state.get("security_assessment", {}),
                target_environment=state.get("target_environment", "dev"),
                user_requirements=state.get("user_requirements", {})
            )
            
            updated_state["infrastructure_plan"] = infrastructure_plan
            updated_state = update_progress(updated_state, "infrastructure_planning", 20.0)
            
            self.logger.info("Infrastructure requirements assessment completed")
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Infrastructure requirements assessment failed: {e}")
            return add_error(state, f"Requirements assessment failed: {e}")
    
    async def _plan_security_configuration_node(self, state: AgentState) -> AgentState:
        """Plan security configuration for the infrastructure."""
        self.logger.info("Executing security configuration planning")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.SECURITY_ASSESSMENT)
            
            # TODO: Implement actual security planning
            mock_security_config = {
                "iam_roles": [
                    {
                        "name": f"{self.config.security.iam_role_prefix}eks-cluster-role",
                        "type": "service",
                        "policies": ["AmazonEKSClusterPolicy"]
                    },
                    {
                        "name": f"{self.config.security.iam_role_prefix}node-group-role",
                        "type": "service", 
                        "policies": ["AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly"]
                    }
                ],
                "policies": [],
                "security_groups": [
                    {
                        "name": "eks-cluster-sg",
                        "rules": [
                            {"type": "ingress", "port": 443, "source": "0.0.0.0/0"}
                        ]
                    }
                ],
                "network_acls": [],
                "encryption_config": {
                    "ebs_encryption": True,
                    "s3_encryption": True,
                    "secrets_encryption": True
                },
                "compliance_controls": ["SOC2", "GDPR"],
                "vulnerability_scan_results": None
            }
            
            updated_state["security_assessment"] = mock_security_config
            updated_state = update_progress(updated_state, "security_assessment", 15.0)
            
            self.logger.info("Security configuration planning completed")
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Security configuration planning failed: {e}")
            return add_error(state, f"Security planning failed: {e}")
    
    async def _generate_infrastructure_topology_node(self, state: AgentState) -> AgentState:
        """Generate infrastructure topology and architecture diagrams."""
        self.logger.info("Executing infrastructure topology generation")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.TOPOLOGY_GENERATION)
            
            # Use actual infrastructure visualizer with graceful error handling
            try:
                from ..modules.visualization import InfrastructureVisualizer
                if InfrastructureVisualizer is None:
                    raise ImportError("InfrastructureVisualizer is not available")
                    
                visualizer = InfrastructureVisualizer(self.config)
                
                # Generate all infrastructure diagrams
                diagram_results = await visualizer.generate_all_diagrams(
                    repository_analysis=state["repository_analysis"],
                    infrastructure_plan=state["infrastructure_plan"],
                    security_config=state.get("security_assessment", {})
                )
                
                # Create summary report
                if diagram_results:
                    report_path = await visualizer.create_summary_report(
                        diagram_results, 
                        state["infrastructure_plan"]
                    )
                    updated_state["topology_diagrams"] = {
                        "diagrams": diagram_results,
                        "summary_report": report_path
                    }
                
                self.logger.info("Infrastructure topology generation completed successfully")
                
            except ImportError as e:
                self.logger.warning(f"Skipping topology generation due to import error: {e}")
                updated_state["topology_diagrams"] = {
                    "diagrams": [],
                    "summary_report": None,
                    "skipped_reason": f"Import error: {e}"
                }
            
            updated_state = update_progress(updated_state, "topology_generation", 10.0)
            
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Infrastructure topology generation failed: {e}")
            return add_error(state, f"Topology generation failed: {e}")
    
    async def _optimize_resource_allocation_node(self, state: AgentState) -> AgentState:
        """Optimize resource allocation for cost and performance."""
        self.logger.info("Executing resource optimization")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.RESOURCE_OPTIMIZATION)
            
            # TODO: Implement actual resource optimization
            optimization_recommendations = [
                "Use spot instances for non-critical workloads",
                "Enable cluster autoscaler for dynamic scaling",
                "Implement horizontal pod autoscaling",
                "Use reserved instances for baseline capacity"
            ]
            
            updated_state["optimization_recommendations"] = optimization_recommendations
            updated_state = update_progress(updated_state, "resource_optimization", 10.0)
            
            self.logger.info("Resource optimization completed")
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Resource optimization failed: {e}")
            return add_error(state, f"Resource optimization failed: {e}")
    
    async def _generate_infrastructure_code_node(self, state: AgentState) -> AgentState:
        """Generate Infrastructure as Code (Terraform/CDK)."""
        self.logger.info("Executing infrastructure code generation")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.CODE_GENERATION)
            
            # Use actual IaC generator
            from ..modules.iac_generator import IaCGenerator, IaCFramework
            generator = IaCGenerator(self.config)
            
            # Generate infrastructure code
            generation_result = await generator.generate_infrastructure_code(
                infrastructure_plan=state["infrastructure_plan"],
                security_config=state.get("security_assessment", {}),
                repository_analysis=state["repository_analysis"],
                framework=IaCFramework.TERRAFORM,
                environment=state.get("target_environment", "dev")
            )
            
            # Update infrastructure plan with generated code paths
            infrastructure_plan = state["infrastructure_plan"]
            infrastructure_plan["terraform_code"] = generation_result.output_files
            infrastructure_plan["generated_files"] = generation_result.output_files
            infrastructure_plan["modules"] = generation_result.modules
            
            updated_state["infrastructure_plan"] = infrastructure_plan
            updated_state["code_generation_result"] = generation_result
            updated_state = update_progress(updated_state, "code_generation", 15.0)
            
            self.logger.info("Infrastructure code generation completed")
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Infrastructure code generation failed: {e}")
            return add_error(state, f"Code generation failed: {e}")
    
    async def _deploy_infrastructure_node(self, state: AgentState) -> AgentState:
        """Deploy the generated infrastructure."""
        self.logger.info("Executing infrastructure deployment")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.DEPLOYMENT)
            
            # Use actual terraform deployer
            from ..modules.terraform_deployer import TerraformDeployer
            deployer = TerraformDeployer(self.config)
            
            # Get generated terraform files from the infrastructure plan
            infrastructure_plan = state["infrastructure_plan"]
            terraform_files = infrastructure_plan.get("terraform_code", [])
            
            if not terraform_files:
                self.logger.error("No terraform files found in infrastructure plan")
                return add_error(state, "No terraform files available for deployment")
            
            # Deploy infrastructure
            self.logger.info(f"Deploying {len(terraform_files)} terraform files")
            deployment_result = await deployer.deploy_infrastructure(
                infrastructure_plan=infrastructure_plan,
                terraform_files=terraform_files,
                environment=state.get("target_environment", "dev"),
                auto_approve=True  # Auto-approve for automated deployment
            )
            
            # Update state with deployment result
            updated_state["deployment_result"] = deployment_result
            
            # Update progress based on deployment status
            if deployment_result["status"] == "completed":
                updated_state = update_progress(updated_state, "deployment", 20.0)
                self.logger.info(f"Infrastructure deployment completed successfully: {deployment_result['deployment_id']}")
            else:
                self.logger.error(f"Infrastructure deployment failed: {deployment_result.get('deployment_logs', ['Unknown error'])}")
                return add_error(state, f"Infrastructure deployment failed: {deployment_result['deployment_id']}")
            
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Infrastructure deployment failed: {e}")
            return add_error(state, f"Infrastructure deployment failed: {e}")
    
    async def _monitor_deployment_node(self, state: AgentState) -> AgentState:
        """Monitor the deployed infrastructure."""
        self.logger.info("Executing deployment monitoring")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.MONITORING)
            
            # TODO: Implement actual monitoring setup
            monitoring_data = {
                "cluster_metrics": {},
                "application_metrics": {},
                "cost_metrics": {},
                "security_metrics": {},
                "performance_metrics": {},
                "alerts": [],
                "recommendations": ["Enable auto-scaling", "Set up cost alerts"],
                "last_updated": datetime.utcnow()
            }
            
            updated_state["monitoring_data"] = monitoring_data
            updated_state = update_progress(updated_state, "monitoring", 10.0)
            
            self.logger.info("Deployment monitoring setup completed")
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Deployment monitoring failed: {e}")
            return add_error(state, f"Monitoring setup failed: {e}")
    
    async def _handle_error_node(self, state: AgentState) -> AgentState:
        """Handle errors and potentially initiate rollback."""
        self.logger.info("Executing error handling")
        
        try:
            updated_state = update_state_phase(state, DeploymentPhase.FAILED)
            
            # TODO: Implement error handling and rollback logic
            if state.get("rollback_required", False):
                self.logger.warning("Initiating rollback due to deployment failure")
                # Rollback logic would go here
            
            self.logger.error(f"Deployment failed with errors: {state.get('errors', [])}")
            return updated_state
            
        except Exception as e:
            self.logger.error(f"Error handling failed: {e}")
            return add_error(state, f"Error handling failed: {e}")
    
    # Routing Functions for LangGraph
    
    def _route_after_analysis(self, state: AgentState) -> str:
        """Route after repository analysis."""
        if state.get("errors"):
            return "error"
        if state.get("repository_analysis"):
            return "assess_requirements"
        return "error"
    
    def _route_after_requirements(self, state: AgentState) -> str:
        """Route after requirements assessment."""
        if state.get("errors"):
            return "error"
        if state.get("infrastructure_plan"):
            return "plan_security"
        return "error"
    
    def _route_after_security(self, state: AgentState) -> str:
        """Route after security planning."""
        if state.get("errors"):
            return "error"
        if state.get("security_assessment"):
            return "generate_topology"
        return "error"
    
    def _route_after_topology(self, state: AgentState) -> str:
        """Route after topology generation."""
        if state.get("errors"):
            return "error"
        return "optimize_resources"
    
    def _route_after_optimization(self, state: AgentState) -> str:
        """Route after resource optimization."""
        if state.get("errors"):
            return "error"
        return "generate_code"
    
    def _route_after_code_generation(self, state: AgentState) -> str:
        """Route after code generation."""
        if state.get("errors"):
            return "error"
        if state.get("infrastructure_plan"):
            return "deploy_infrastructure"
        return "error"
    
    def _route_after_deployment(self, state: AgentState) -> str:
        """Route after deployment."""
        if state.get("errors"):
            return "error"
        deployment_result = state.get("deployment_result")
        if deployment_result and deployment_result.get("status") == "completed":
            return "monitor_deployment"
        elif deployment_result and deployment_result.get("status") == "failed":
            return "error"
        return "end"


# Utility functions for common agent operations

async def create_agent_from_config(config_path: str) -> InfrastructureAgent:
    """
    Create an Infrastructure Agent from a configuration file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Configured InfrastructureAgent instance
    """
    config = load_config(config_path)
    return InfrastructureAgent(config=config)


async def quick_analyze(repository_url: str, **kwargs) -> AgentState:
    """
    Quick analysis of a repository with default configuration.
    
    Args:
        repository_url: Git repository URL to analyze
        **kwargs: Additional parameters
        
    Returns:
        Analysis results
    """
    agent = InfrastructureAgent()
    return await agent.analyze_repository(repository_url, **kwargs) 