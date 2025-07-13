#!/usr/bin/env python3
"""
Simple test script to debug analysis issues.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from agentic_infra_manager.core.agent import InfrastructureAgent
    from agentic_infra_manager.core.config import AgentConfig
    
    async def test_analysis():
        """Test the analysis with a simple repository."""
        print("Testing analysis...")
        
        # Check OpenAI API key
        openai_key = os.getenv("OPENAI_API_KEY")
        if not openai_key:
            print("❌ Please set OPENAI_API_KEY environment variable")
            return
        
        # Create config
        config = AgentConfig(
            name="Test Agent",
            openai_api_key=openai_key,
            workspace="/tmp/test-workspace",
            dry_run=True
        )
        
        # Create agent
        agent = InfrastructureAgent(config=config)
        
        # Test analysis
        result = await agent.analyze_repository(
            repository_url="https://github.com/spring-projects/spring-petclinic",
            target_environment="dev"
        )
        
        print(f"Analysis result type: {type(result)}")
        print(f"Analysis result keys: {list(result.keys()) if hasattr(result, 'keys') else 'No keys method'}")
        
        # Check key fields
        if isinstance(result, dict):
            repo_analysis = result.get('repository_analysis')
            print(f"Repository analysis: {repo_analysis is not None}")
            if repo_analysis:
                print(f"Repository analysis keys: {list(repo_analysis.keys())}")
                
            progress = result.get('progress_percentage', 0)
            print(f"Progress: {progress}%")
            
            errors = result.get('errors', [])
            print(f"Errors: {len(errors)}")
            for error in errors:
                print(f"  - {error}")
    
    if __name__ == "__main__":
        asyncio.run(test_analysis())
        
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running this from the agentic-infra-manager directory")
    print("And that you've installed the package with: make install") 