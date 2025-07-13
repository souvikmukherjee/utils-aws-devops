"""
Basic tests for the Infrastructure Agent.

This module contains unit tests for the core agent functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
from datetime import datetime

from agentic_infra_manager.core.agent import InfrastructureAgent
from agentic_infra_manager.core.config import AgentConfig
from agentic_infra_manager.core.state import (
    AgentState, 
    DeploymentPhase, 
    ApplicationType,
    create_initial_state
)


class TestInfrastructureAgent:
    """Test cases for the InfrastructureAgent class."""
    
    def test_agent_initialization(self):
        """Test agent initialization with configuration."""
        config = AgentConfig(
            openai_api_key="test-key",
            workspace="/tmp/test-workspace"
        )
        
        agent = InfrastructureAgent(config=config)
        
        assert agent.config == config
        assert agent.current_state is None
        assert agent.llm is not None
        assert agent.workflow is not None
    
    def test_agent_initialization_without_openai_key(self):
        """Test agent initialization fails without OpenAI API key."""
        config = AgentConfig(openai_api_key=None)
        
        with pytest.raises(ValueError, match="OpenAI API key is required"):
            InfrastructureAgent(config=config)
    
    @pytest.mark.asyncio
    async def test_analyze_repository_success(self):
        """Test successful repository analysis."""
        config = AgentConfig(
            openai_api_key="test-key",
            dry_run=True
        )
        
        agent = InfrastructureAgent(config=config)
        
        with patch.object(agent.workflow, 'ainvoke') as mock_workflow:
            # Mock successful workflow execution
            mock_result = create_initial_state()
            mock_result["current_phase"] = DeploymentPhase.COMPLETED
            mock_result["repository_analysis"] = {
                "url": "https://github.com/test/repo",
                "name": "test-repo",
                "language": "python",
                "framework": "fastapi",
                "dependencies": ["fastapi", "uvicorn"],
                "application_type": ApplicationType.API_SERVICE,
                "dockerfile_present": True,
                "k8s_manifests_present": False,
                "infrastructure_requirements": {
                    "compute": {"cpu": "500m", "memory": "512Mi"},
                    "storage": {"persistent": False, "size_gb": 5},
                    "networking": {"load_balancer": True},
                    "security": {"https": True},
                    "monitoring": {"metrics": True},
                    "estimated_cost": 100.0,
                    "compliance_requirements": ["SOC2"]
                },
                "security_analysis": {"vulnerabilities": []},
                "complexity_score": 0.6,
                "estimated_resources": {"instances": 2}
            }
            mock_workflow.return_value = mock_result
            
            result = await agent.analyze_repository("https://github.com/test/repo")
            
            assert result["current_phase"] == DeploymentPhase.COMPLETED
            assert result["repository_analysis"]["name"] == "test-repo"
            assert mock_workflow.called
    
    @pytest.mark.asyncio
    async def test_analyze_repository_failure(self):
        """Test repository analysis with failure."""
        config = AgentConfig(openai_api_key="test-key")
        agent = InfrastructureAgent(config=config)
        
        with patch.object(agent.workflow, 'ainvoke') as mock_workflow:
            # Mock workflow failure
            mock_workflow.side_effect = Exception("Analysis failed")
            
            result = await agent.analyze_repository("https://github.com/test/repo")
            
            assert len(result["errors"]) > 0
            assert "Analysis failed" in result["errors"][0]
    
    def test_workflow_creation(self):
        """Test that workflow is properly created with all nodes."""
        config = AgentConfig(openai_api_key="test-key")
        agent = InfrastructureAgent(config=config)
        
        # Check that workflow is created
        assert agent.workflow is not None
        
        # The workflow should be a compiled StateGraph
        # We can't easily inspect internal structure, but we can verify it exists
        assert hasattr(agent.workflow, 'ainvoke')


class TestAgentState:
    """Test cases for agent state management."""
    
    def test_create_initial_state(self):
        """Test creation of initial agent state."""
        state = create_initial_state(
            repository_url="https://github.com/test/repo",
            target_environment="dev",
            deployment_region="us-west-2"
        )
        
        assert state["repository_url"] == "https://github.com/test/repo"
        assert state["target_environment"] == "dev"
        assert state["deployment_region"] == "us-west-2"
        assert state["current_phase"] == DeploymentPhase.INITIALIZATION
        assert state["progress_percentage"] == 0.0
        assert len(state["errors"]) == 0
        assert len(state["audit_trail"]) == 1
    
    def test_state_audit_trail(self):
        """Test that audit trail is properly maintained."""
        state = create_initial_state()
        
        # Check initial audit entry
        assert len(state["audit_trail"]) == 1
        assert state["audit_trail"][0]["action"] == "session_initialized"
        assert "session_id" in state["audit_trail"][0]["details"]


class TestAgentConfig:
    """Test cases for agent configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = AgentConfig()
        
        assert config.name == "Infrastructure AI Agent"
        assert config.version == "0.1.0"
        assert config.aws.region == "us-west-2"
        assert config.kubernetes.cluster_version == "1.28"
        assert config.dry_run is False
    
    def test_config_validation(self):
        """Test configuration validation."""
        config = AgentConfig()
        errors = config.validate()
        
        # Should have no errors with default config
        assert len(errors) == 0
    
    def test_config_validation_with_errors(self):
        """Test configuration validation with invalid values."""
        config = AgentConfig()
        config.kubernetes.min_nodes = 10
        config.kubernetes.max_nodes = 5  # Invalid: min > max
        
        errors = config.validate()
        assert len(errors) > 0
        assert any("min_nodes cannot be greater than max_nodes" in error for error in errors)
    
    def test_config_to_dict(self):
        """Test configuration serialization to dictionary."""
        config = AgentConfig(
            name="Test Agent",
            openai_api_key="test-key"
        )
        
        config_dict = config.to_dict()
        
        assert config_dict["agent"]["name"] == "Test Agent"
        assert config_dict["openai_api_key"] == "test-key"
        assert isinstance(config_dict, dict)


@pytest.fixture
def mock_agent():
    """Fixture to create a mock agent for testing."""
    config = AgentConfig(
        openai_api_key="test-key",
        dry_run=True
    )
    return InfrastructureAgent(config=config)


def test_agent_fixture(mock_agent):
    """Test that the agent fixture works correctly."""
    assert isinstance(mock_agent, InfrastructureAgent)
    assert mock_agent.config.dry_run is True 