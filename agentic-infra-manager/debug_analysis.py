#!/usr/bin/env python3
"""
Debug script for troubleshooting analysis issues.
This helps identify where the analysis is failing and what data is being returned.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from agentic_infra_manager.core.agent import InfrastructureAgent
from agentic_infra_manager.core.config import AgentConfig
from agentic_infra_manager.core.state import AgentState


async def debug_analysis(repository_url: str):
    """Debug the analysis process step by step."""
    print("🔍 Starting analysis debugging...")
    
    # Step 1: Check environment variables
    print("\n1. Checking environment variables...")
    openai_key = os.getenv("OPENAI_API_KEY")
    aws_region = os.getenv("AWS_REGION", "us-west-2")
    
    if not openai_key:
        print("❌ OPENAI_API_KEY not found in environment variables")
        print("   Please set it with: export OPENAI_API_KEY=your_key_here")
        return
    else:
        print(f"✅ OPENAI_API_KEY found (length: {len(openai_key)})")
    
    print(f"✅ AWS_REGION: {aws_region}")
    
    # Step 2: Create configuration
    print("\n2. Creating agent configuration...")
    try:
        config = AgentConfig(
            name="Debug Agent",
            openai_api_key=openai_key,
            workspace="/tmp/debug-workspace",
            dry_run=True  # Safe mode for debugging
        )
        config.aws.region = aws_region
        print("✅ Configuration created successfully")
    except Exception as e:
        print(f"❌ Configuration creation failed: {e}")
        return
    
    # Step 3: Initialize agent
    print("\n3. Initializing agent...")
    try:
        agent = InfrastructureAgent(config=config)
        print("✅ Agent initialized successfully")
    except Exception as e:
        print(f"❌ Agent initialization failed: {e}")
        return
    
    # Step 4: Test repository analysis
    print(f"\n4. Testing repository analysis for: {repository_url}")
    try:
        result = await agent.analyze_repository(
            repository_url=repository_url,
            target_environment="dev"
        )
        print("✅ Analysis completed successfully")
        
        # Step 5: Examine the result structure
        print("\n5. Examining result structure...")
        print(f"Result type: {type(result)}")
        
        if isinstance(result, dict):
            print(f"Result keys: {list(result.keys())}")
            
            # Check for expected keys
            expected_keys = [
                'repository_analysis',
                'infrastructure_requirements', 
                'progress_percentage',
                'errors',
                'warnings'
            ]
            
            for key in expected_keys:
                if key in result:
                    print(f"✅ Found key: {key}")
                    if key == 'repository_analysis' and result[key]:
                        repo_analysis = result[key]
                        print(f"   Repository analysis keys: {list(repo_analysis.keys())}")
                else:
                    print(f"❌ Missing key: {key}")
        else:
            # If it's an AgentState object
            print("Result is an AgentState object")
            if hasattr(result, 'get'):
                print(f"Available attributes: {dir(result)}")
            
            # Try to access repository_analysis
            if 'repository_analysis' in result:
                repo_analysis = result['repository_analysis']
                print(f"✅ Repository analysis found: {repo_analysis is not None}")
                if repo_analysis:
                    print(f"   Repository analysis type: {type(repo_analysis)}")
                    if isinstance(repo_analysis, dict):
                        print(f"   Keys: {list(repo_analysis.keys())}")
            else:
                print("❌ No repository_analysis in result")
        
        # Step 6: Display progress and errors
        print("\n6. Checking progress and errors...")
        progress = result.get('progress_percentage', 0)
        errors = result.get('errors', [])
        warnings = result.get('warnings', [])
        
        print(f"Progress: {progress}%")
        print(f"Errors: {len(errors)}")
        print(f"Warnings: {len(warnings)}")
        
        if errors:
            print("❌ Errors found:")
            for error in errors:
                print(f"   - {error}")
        
        if warnings:
            print("⚠️  Warnings found:")
            for warning in warnings:
                print(f"   - {warning}")
        
        # Step 7: Save debug output
        print("\n7. Saving debug output...")
        debug_output = {
            "repository_url": repository_url,
            "result_type": str(type(result)),
            "result_keys": list(result.keys()) if isinstance(result, dict) else "N/A",
            "progress": progress,
            "errors": errors,
            "warnings": warnings,
            "full_result": result if isinstance(result, dict) else str(result)
        }
        
        with open("/tmp/debug-analysis.json", "w") as f:
            json.dump(debug_output, f, indent=2, default=str)
        
        print("✅ Debug output saved to /tmp/debug-analysis.json")
        
        return result
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        print(f"Full traceback:\n{traceback.format_exc()}")
        return None


def main():
    """Main function for command-line usage."""
    if len(sys.argv) != 2:
        print("Usage: python debug_analysis.py <repository_url>")
        print("Example: python debug_analysis.py https://github.com/spring-projects/spring-petclinic")
        sys.exit(1)
    
    repository_url = sys.argv[1]
    
    # Run the debug analysis
    asyncio.run(debug_analysis(repository_url))


if __name__ == "__main__":
    main() 