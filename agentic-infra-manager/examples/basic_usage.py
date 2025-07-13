#!/usr/bin/env python3
"""
Basic usage example for the Agentic Infrastructure Management System.

This script demonstrates how to use the infrastructure agent programmatically
to analyze a repository and plan infrastructure deployment.
"""

import asyncio
import os
from pathlib import Path

from agentic_infra_manager import InfrastructureAgent, AgentConfig


async def main():
    """Main example function."""
    print("🚀 Agentic Infrastructure Manager - Basic Usage Example")
    print("=" * 60)
    
    # 1. Create configuration
    print("\n📋 Step 1: Creating agent configuration...")
    
    config = AgentConfig(
        name="Example Infrastructure Agent",
        workspace="/tmp/example-workspace",
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        github_token=os.getenv("GITHUB_TOKEN"),
        dry_run=True  # Safe mode for examples
    )
    
    # Configure AWS region
    config.aws.region = "us-west-2"
    
    print(f"✅ Agent configured: {config.name}")
    print(f"   Workspace: {config.workspace}")
    print(f"   AWS Region: {config.aws.region}")
    print(f"   Dry Run Mode: {config.dry_run}")
    
    # 2. Initialize the agent
    print("\n🤖 Step 2: Initializing the infrastructure agent...")
    
    if not config.openai_api_key:
        print("⚠️  Warning: No OpenAI API key found. Set OPENAI_API_KEY environment variable.")
        print("   For this example, we'll use a mock configuration.")
        config.openai_api_key = "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"
    
    try:
        agent = InfrastructureAgent(config=config)
        print("✅ Agent initialized successfully")
    except Exception as e:
        print(f"❌ Agent initialization failed: {e}")
        return
    
    # 3. Example repository analysis
    print("\n🔍 Step 3: Analyzing a sample repository...")
    
    # Use a public repository for demonstration
    repository_url = "https://github.com/tiangolo/fastapi"
    target_environment = "dev"
    
    print(f"   Repository: {repository_url}")
    print(f"   Target Environment: {target_environment}")
    
    try:
        # Analyze the repository
        print("   Running analysis...")
        result = await agent.analyze_repository(
            repository_url=repository_url,
            target_environment=target_environment,
            deployment_region=config.aws.region
        )
        
        print("✅ Repository analysis completed!")
        
        # 4. Display results
        print("\n📊 Step 4: Analysis Results")
        print("-" * 40)
        
        # Repository information
        repo_analysis = result.get('repository_analysis')
        if repo_analysis:
            print(f"📦 Repository: {repo_analysis['name']}")
            print(f"🔤 Language: {repo_analysis['language']}")
            print(f"🛠️  Framework: {repo_analysis['framework']}")
            print(f"📱 App Type: {repo_analysis['application_type']}")
            print(f"📚 Dependencies: {len(repo_analysis['dependencies'])} packages")
            print(f"🧮 Complexity: {repo_analysis['complexity_score']:.2f}")
        
        # Infrastructure requirements
        infra_req = result.get('infrastructure_requirements')
        if infra_req:
            print(f"\n🏗️  Infrastructure Requirements:")
            print(f"   💻 CPU: {infra_req['compute']['cpu']}")
            print(f"   🧠 Memory: {infra_req['compute']['memory']}")
            print(f"   💾 Storage: {infra_req['storage']['size_gb']} GB")
            print(f"   💰 Est. Cost: ${infra_req['estimated_cost']:.2f}/month")
        
        # Security assessment
        security = result.get('security_assessment')
        if security:
            print(f"\n🔒 Security Configuration:")
            print(f"   🛡️  IAM Roles: {len(security['iam_roles'])}")
            print(f"   📋 Policies: {len(security['policies'])}")
            print(f"   🔐 Encryption: Enabled")
        
        # Infrastructure plan
        plan = result.get('infrastructure_plan')
        if plan:
            print(f"\n📋 Infrastructure Plan:")
            print(f"   🆔 Plan ID: {plan['plan_id']}")
            print(f"   🌐 VPC CIDR: {plan['vpc_configuration'].get('cidr', 'TBD')}")
            print(f"   ⚙️  EKS Version: {plan['eks_configuration'].get('version', 'TBD')}")
            print(f"   💵 Monthly Cost: ${plan['estimated_cost'].get('monthly', 0):.2f}")
        
        # Progress and status
        progress = result.get('progress_percentage', 0)
        phase = result.get('current_phase', 'unknown')
        print(f"\n📈 Progress: {progress:.1f}% ({phase})")
        
        # Errors and warnings
        errors = result.get('errors', [])
        warnings = result.get('warnings', [])
        
        if errors:
            print(f"\n❌ Errors ({len(errors)}):")
            for error in errors[:3]:  # Show first 3 errors
                print(f"   • {error}")
        
        if warnings:
            print(f"\n⚠️  Warnings ({len(warnings)}):")
            for warning in warnings[:3]:  # Show first 3 warnings
                print(f"   • {warning}")
        
        # 5. Next steps
        print("\n🎯 Step 5: Next Steps")
        print("-" * 40)
        
        if result.get('infrastructure_plan'):
            plan_id = result['infrastructure_plan']['plan_id']
            print(f"✨ Infrastructure plan generated successfully!")
            print(f"📝 Plan ID: {plan_id}")
            print(f"\nTo deploy this infrastructure:")
            print(f"   1. Review the generated plan carefully")
            print(f"   2. Set up your AWS credentials")
            print(f"   3. Run: infra-agent deploy --plan-id {plan_id}")
            print(f"   4. Monitor deployment progress")
        else:
            print("ℹ️  Analysis completed but no deployment plan was generated.")
            print("   This might be due to errors or incomplete analysis.")
        
        print(f"\n📁 Workspace: {config.workspace}")
        print("   Check this directory for generated files and logs.")
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return
    
    print("\n🎉 Example completed successfully!")
    print("💡 Tip: Set OPENAI_API_KEY and run with real credentials for full functionality.")


def example_configuration():
    """Show different configuration options."""
    print("\n🔧 Configuration Examples")
    print("=" * 40)
    
    # Example 1: Development configuration
    print("1. Development Configuration:")
    dev_config = AgentConfig(
        name="Development Agent",
        workspace="/tmp/dev-workspace",
        dry_run=True
    )
    dev_config.aws.region = "us-east-1"
    dev_config.kubernetes.desired_nodes = 1
    dev_config.cost.budget_limit_monthly = 100.0
    
    print(f"   • Environment: Development")
    print(f"   • AWS Region: {dev_config.aws.region}")
    print(f"   • K8s Nodes: {dev_config.kubernetes.desired_nodes}")
    print(f"   • Monthly Budget: ${dev_config.cost.budget_limit_monthly}")
    
    # Example 2: Production configuration
    print("\n2. Production Configuration:")
    prod_config = AgentConfig(
        name="Production Agent",
        dry_run=False
    )
    prod_config.aws.region = "us-west-2"
    prod_config.kubernetes.desired_nodes = 3
    prod_config.kubernetes.enable_auto_scaling = True
    prod_config.security.compliance_frameworks = ["SOC2", "GDPR", "HIPAA"]
    prod_config.deployment.approval_required["prod"] = True
    
    print(f"   • Environment: Production")
    print(f"   • AWS Region: {prod_config.aws.region}")
    print(f"   • K8s Nodes: {prod_config.kubernetes.desired_nodes}")
    print(f"   • Auto-scaling: {prod_config.kubernetes.enable_auto_scaling}")
    print(f"   • Compliance: {', '.join(prod_config.security.compliance_frameworks)}")


async def example_monitoring():
    """Example of infrastructure monitoring."""
    print("\n📊 Monitoring Example")
    print("=" * 40)
    
    config = AgentConfig(
        openai_api_key="mock-key",
        dry_run=True
    )
    
    agent = InfrastructureAgent(config=config)
    
    # Simulate monitoring
    cluster_id = "example-cluster"
    
    print(f"🔍 Monitoring cluster: {cluster_id}")
    
    monitoring_data = await agent.monitor_infrastructure(cluster_id)
    
    print(f"✅ Cluster Status: {monitoring_data['status']}")
    print(f"📅 Last Updated: {monitoring_data['timestamp']}")
    print(f"💡 Recommendations: {len(monitoring_data['recommendations'])}")
    
    for i, rec in enumerate(monitoring_data['recommendations'], 1):
        print(f"   {i}. {rec}")


if __name__ == "__main__":
    """Run the example."""
    print("🤖 Starting Agentic Infrastructure Manager Example")
    
    # Run the main example
    asyncio.run(main())
    
    # Show configuration examples
    example_configuration()
    
    # Show monitoring example
    asyncio.run(example_monitoring())
    
    print("\n✨ All examples completed!")
    print("For more information, visit: https://github.com/your-org/agentic-infra-manager") 