"""
Command-line interface for the Agentic Infrastructure Management System.

This module provides a comprehensive CLI for interacting with the infrastructure agent,
including repository analysis, infrastructure deployment, and monitoring operations.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import logging

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.json import JSON

from .core.agent import InfrastructureAgent
from .core.config import AgentConfig, load_config
from .core.state import DeploymentPhase, ApplicationType


console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


@click.group()
@click.option('--config', '-c', help='Path to configuration file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def main(ctx: click.Context, config: Optional[str], verbose: bool) -> None:
    """
    Agentic AI Infrastructure Management System
    
    An intelligent agent that autonomously plans, provisions, and manages AWS infrastructure
    with specialized focus on Kubernetes cluster deployment and application lifecycle management.
    """
    setup_logging(verbose)
    
    # Store configuration path in context
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config
    ctx.obj['verbose'] = verbose


@main.command()
@click.option('--config-path', default='config/agent.yaml', help='Path where to save configuration')
@click.option('--interactive', '-i', is_flag=True, help='Interactive configuration setup')
def init(config_path: str, interactive: bool) -> None:
    """Initialize the agent with a new configuration."""
    console.print("[bold green]Initializing Agentic Infrastructure Manager[/bold green]")
    
    config_file = Path(config_path)
    
    if config_file.exists():
        if not click.confirm(f"Configuration file {config_path} already exists. Overwrite?"):
            console.print("[yellow]Initialization cancelled.[/yellow]")
            return
    
    if interactive:
        config = create_interactive_config()
    else:
        config = AgentConfig()
    
    # Create directory if it doesn't exist
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Save configuration
    config.save_to_file(config_path)
    
    console.print(f"[green]Configuration saved to {config_path}[/green]")
    console.print("\n[bold]Next steps:[/bold]")
    console.print("1. Set your AWS credentials and OpenAI API key")
    console.print("2. Run: infra-agent analyze <repository-url>")
    console.print("3. Review the generated infrastructure plan")
    console.print("4. Deploy with: infra-agent deploy --plan-id <plan-id>")


def create_interactive_config() -> AgentConfig:
    """Create configuration through interactive prompts."""
    console.print("[bold green]Interactive Configuration Setup[/bold green]")
    
    # Basic agent settings
    name = click.prompt("Agent name", default="Infrastructure AI Agent")
    workspace = click.prompt("Workspace directory", default="/tmp/agent-workspace")
    
    # AWS configuration
    aws_region = click.prompt("AWS region", default="us-west-2")
    aws_profile = click.prompt("AWS profile (optional)", default="", show_default=False)
    
    # OpenAI configuration
    openai_key = click.prompt("OpenAI API key", hide_input=True, default="", show_default=False)
    model_name = click.prompt("OpenAI model", default="gpt-4")
    
    # GitHub token
    github_token = click.prompt("GitHub token (optional)", hide_input=True, default="", show_default=False)
    
    # Create configuration
    config = AgentConfig(
        name=name,
        workspace=workspace,
        openai_api_key=openai_key or None,
        model_name=model_name,
        github_token=github_token or None
    )
    
    config.aws.region = aws_region
    config.aws.profile = aws_profile or None
    
    return config


@main.command()
@click.argument('repository_url')
@click.option('--target-env', default='dev', help='Target environment (dev/staging/prod)')
@click.option('--region', help='AWS region (overrides config)')
@click.option('--output', '-o', help='Output file for analysis results')
@click.option('--dry-run', is_flag=True, help='Perform analysis without deployment planning')
@click.pass_context
def analyze(ctx: click.Context, repository_url: str, target_env: str, region: Optional[str], 
            output: Optional[str], dry_run: bool) -> None:
    """Analyze a Git repository and plan infrastructure deployment."""
    
    try:
        # Load configuration
        config_path = ctx.obj.get('config_path')
        config = load_config(config_path)
        
        if region:
            config.aws.region = region
        
        if dry_run:
            config.dry_run = True
        
        # Initialize agent
        agent = InfrastructureAgent(config=config)
        
        console.print(f"[bold green]Analyzing repository:[/bold green] {repository_url}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing repository...", total=None)
            
            # Run analysis
            result = asyncio.run(agent.analyze_repository(
                repository_url=repository_url,
                target_environment=target_env,
                deployment_region=config.aws.region
            ))
            
            progress.update(task, description="Analysis complete!")
        
        # Display results
        display_analysis_results(result)
        
        # Save results if requested
        if output:
            save_analysis_results(result, output)
            console.print(f"[green]Results saved to {output}[/green]")
        
        # Display next steps
        if not dry_run and result.get('infrastructure_plan'):
            plan_id = result['infrastructure_plan']['plan_id']
            console.print(f"\n[bold]Next step:[/bold] infra-agent deploy --plan-id {plan_id}")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)


@main.command()
@click.option('--plan-id', required=True, help='Infrastructure plan ID to deploy')
@click.option('--approve', is_flag=True, help='Skip deployment confirmation')
@click.option('--timeout', default=30, help='Deployment timeout in minutes')
@click.pass_context
def deploy(ctx: click.Context, plan_id: str, approve: bool, timeout: int) -> None:
    """Deploy infrastructure based on a generated plan."""
    
    try:
        # Load configuration
        config_path = ctx.obj.get('config_path')
        config = load_config(config_path)
        
        # Initialize agent
        agent = InfrastructureAgent(config=config)
        
        if not agent.current_state:
            console.print("[red]Error: No current state found. Run 'analyze' first.[/red]")
            sys.exit(1)
        
        # Display deployment plan
        plan = agent.current_state.get('infrastructure_plan')
        if not plan or plan['plan_id'] != plan_id:
            console.print(f"[red]Error: Plan {plan_id} not found.[/red]")
            sys.exit(1)
        
        display_deployment_plan(plan)
        
        # Confirm deployment
        if not approve:
            if not click.confirm("Proceed with deployment?"):
                console.print("[yellow]Deployment cancelled.[/yellow]")
                return
        
        console.print(f"[bold green]Deploying infrastructure plan:[/bold green] {plan_id}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Deploying infrastructure...", total=None)
            
            # Run deployment
            result = asyncio.run(agent.deploy_infrastructure(plan_id))
            
            progress.update(task, description="Deployment complete!")
        
        # Display results
        display_deployment_results(result)
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)


@main.command()
@click.option('--cluster', required=True, help='Cluster name to monitor')
@click.option('--watch', is_flag=True, help='Continuously monitor (Ctrl+C to stop)')
@click.option('--interval', default=30, help='Monitoring interval in seconds')
@click.pass_context
def monitor(ctx: click.Context, cluster: str, watch: bool, interval: int) -> None:
    """Monitor deployed infrastructure and show metrics."""
    
    try:
        # Load configuration
        config_path = ctx.obj.get('config_path')
        config = load_config(config_path)
        
        # Initialize agent
        agent = InfrastructureAgent(config=config)
        
        console.print(f"[bold green]Monitoring cluster:[/bold green] {cluster}")
        
        if watch:
            # Continuous monitoring
            try:
                while True:
                    monitoring_data = asyncio.run(agent.monitor_infrastructure(cluster))
                    display_monitoring_data(monitoring_data)
                    
                    console.print(f"[dim]Next update in {interval} seconds... (Ctrl+C to stop)[/dim]")
                    asyncio.run(asyncio.sleep(interval))
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Monitoring stopped.[/yellow]")
        else:
            # One-time monitoring
            monitoring_data = asyncio.run(agent.monitor_infrastructure(cluster))
            display_monitoring_data(monitoring_data)
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)


@main.command()
@click.option('--cluster', required=True, help='Cluster name to optimize')
@click.option('--recommendations-only', is_flag=True, help='Show recommendations without applying')
@click.pass_context
def optimize(ctx: click.Context, cluster: str, recommendations_only: bool) -> None:
    """Optimize existing infrastructure for cost and performance."""
    
    try:
        # Load configuration
        config_path = ctx.obj.get('config_path')
        config = load_config(config_path)
        
        # Initialize agent
        agent = InfrastructureAgent(config=config)
        
        console.print(f"[bold green]Optimizing cluster:[/bold green] {cluster}")
        
        # Get monitoring data first
        monitoring_data = asyncio.run(agent.monitor_infrastructure(cluster))
        
        # TODO: Implement optimization logic
        recommendations = [
            "Enable cluster autoscaler for better resource utilization",
            "Use spot instances for development workloads",
            "Implement horizontal pod autoscaling",
            "Configure resource requests and limits",
            "Enable vertical pod autoscaling for right-sizing"
        ]
        
        display_optimization_recommendations(recommendations)
        
        if not recommendations_only:
            if click.confirm("Apply optimization recommendations?"):
                console.print("[yellow]Optimization application not yet implemented.[/yellow]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)


@main.command()
@click.option('--format', 'output_format', type=click.Choice(['yaml', 'json']), default='yaml')
def config(output_format: str) -> None:
    """Show current configuration."""
    
    try:
        config = load_config()
        
        if output_format == 'json':
            console.print(JSON.from_data(config.to_dict()))
        else:
            console.print(yaml.dump(config.to_dict(), default_flow_style=False))
    
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)


@main.command()
def version() -> None:
    """Show version information."""
    from . import __version__
    console.print(f"Agentic Infrastructure Manager v{__version__}")


# Display Functions

def display_analysis_results(result: Dict[str, Any]) -> None:
    """Display repository analysis results."""
    console.print("\n[bold]📊 Repository Analysis Results[/bold]")
    
    # Repository info
    repo_analysis = result.get('repository_analysis')
    if repo_analysis:
        table = Table(title="Repository Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Name", repo_analysis['name'])
        table.add_row("Language", repo_analysis['language'])
        table.add_row("Framework", repo_analysis['framework'])
        table.add_row("Application Type", repo_analysis['application_type'])
        table.add_row("Dependencies", str(len(repo_analysis['dependencies'])))
        table.add_row("Complexity Score", f"{repo_analysis['complexity_score']:.2f}")
        
        console.print(table)
    
    # Infrastructure requirements
    infra_req = result.get('infrastructure_requirements')
    if infra_req:
        console.print("\n[bold]🏗️ Infrastructure Requirements[/bold]")
        
        requirements_panel = Panel.fit(
            f"CPU: {infra_req['compute']['cpu']}\n"
            f"Memory: {infra_req['compute']['memory']}\n"
            f"Storage: {infra_req['storage']['size_gb']} GB\n"
            f"Estimated Cost: ${infra_req['estimated_cost']:.2f}/month",
            title="Resource Requirements"
        )
        console.print(requirements_panel)
    
    # Progress
    progress = result.get('progress_percentage', 0)
    console.print(f"\n[bold]Progress:[/bold] {progress:.1f}% complete")
    
    # Errors and warnings
    errors = result.get('errors', [])
    warnings = result.get('warnings', [])
    
    if errors:
        console.print(f"\n[red]❌ Errors ({len(errors)}):[/red]")
        for error in errors:
            console.print(f"  • {error}")
    
    if warnings:
        console.print(f"\n[yellow]⚠️ Warnings ({len(warnings)}):[/yellow]")
        for warning in warnings:
            console.print(f"  • {warning}")


def display_deployment_plan(plan: Dict[str, Any]) -> None:
    """Display infrastructure deployment plan."""
    console.print("\n[bold]🚀 Deployment Plan[/bold]")
    
    plan_panel = Panel.fit(
        f"Plan ID: {plan['plan_id']}\n"
        f"Estimated Cost: ${plan['estimated_cost']['monthly']:.2f}/month\n"
        f"Estimated Duration: {plan['deployment_timeline']['estimated_duration']}",
        title="Deployment Overview"
    )
    console.print(plan_panel)


def display_deployment_results(result: Dict[str, Any]) -> None:
    """Display deployment results."""
    console.print("\n[bold]✅ Deployment Results[/bold]")
    
    deployment = result.get('deployment_result')
    if deployment:
        table = Table(title="Deployment Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Status", deployment['status'])
        table.add_row("Cluster Name", deployment['cluster_name'])
        table.add_row("VPC ID", deployment['vpc_id'])
        
        if deployment['application_endpoints']:
            table.add_row("Endpoints", '\n'.join(deployment['application_endpoints']))
        
        console.print(table)


def display_monitoring_data(data: Dict[str, Any]) -> None:
    """Display monitoring data."""
    console.print("\n[bold]📈 Monitoring Data[/bold]")
    
    monitoring_panel = Panel.fit(
        f"Cluster: {data['cluster_id']}\n"
        f"Status: {data['status']}\n"
        f"Last Updated: {data['timestamp']}\n"
        f"Recommendations: {len(data['recommendations'])}",
        title="Infrastructure Status"
    )
    console.print(monitoring_panel)
    
    if data['recommendations']:
        console.print("\n[bold]💡 Recommendations:[/bold]")
        for rec in data['recommendations']:
            console.print(f"  • {rec}")


def display_optimization_recommendations(recommendations: list) -> None:
    """Display optimization recommendations."""
    console.print("\n[bold]🎯 Optimization Recommendations[/bold]")
    
    for i, rec in enumerate(recommendations, 1):
        console.print(f"  {i}. {rec}")


def save_analysis_results(result: Dict[str, Any], output_path: str) -> None:
    """Save analysis results to file."""
    output_file = Path(output_path)
    
    # Convert datetime objects to strings for JSON serialization
    serializable_result = json.loads(json.dumps(result, default=str))
    
    if output_file.suffix.lower() == '.json':
        with open(output_file, 'w') as f:
            json.dump(serializable_result, f, indent=2)
    else:
        with open(output_file, 'w') as f:
            yaml.dump(serializable_result, f, default_flow_style=False)


if __name__ == '__main__':
    main() 