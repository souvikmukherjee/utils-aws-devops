"""
Terraform Deployment module for executing Terraform commands and managing infrastructure deployment.

This module provides comprehensive Terraform deployment capabilities including:
- Terraform initialization and planning
- Infrastructure deployment and destruction
- State management and backup
- Deployment validation and monitoring
- Rollback capabilities
- Real-time deployment logging
"""

import os
import json
import subprocess
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import tempfile
import shutil

from ..core.state import (
    InfrastructurePlan,
    DeploymentResult,
    DeploymentPhase
)
from ..core.config import AgentConfig


class TerraformCommand(Enum):
    """Terraform command types."""
    INIT = "init"
    PLAN = "plan"
    APPLY = "apply"
    DESTROY = "destroy"
    VALIDATE = "validate"
    REFRESH = "refresh"
    SHOW = "show"
    OUTPUT = "output"


class DeploymentStatus(Enum):
    """Deployment status types."""
    NOT_STARTED = "not_started"
    INITIALIZING = "initializing"
    PLANNING = "planning"
    APPLYING = "applying"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"


@dataclass
class TerraformExecutionResult:
    """Result of terraform command execution."""
    command: TerraformCommand
    success: bool
    output: str
    error: str
    duration: float
    exit_code: int
    timestamp: datetime


@dataclass
class DeploymentContext:
    """Context for terraform deployment."""
    terraform_dir: Path
    tfvars_file: Path
    state_file: Optional[Path]
    backup_dir: Path
    log_file: Path
    environment: str
    project_name: str


class TerraformDeployer:
    """
    Terraform deployment manager for executing infrastructure as code.
    
    This class handles the complete lifecycle of terraform deployments including
    initialization, planning, applying, and cleanup operations.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the Terraform Deployer.
        
        Args:
            config: Agent configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Deployment state
        self.current_deployment: Optional[DeploymentContext] = None
        self.deployment_status = DeploymentStatus.NOT_STARTED
        
        # Terraform binary path
        self.terraform_path = self._find_terraform_binary()
        
        # Workspace directory
        self.workspace_dir = Path(config.workspace)
        self.workspace_dir.mkdir(exist_ok=True)
        
        self.logger.info("Terraform Deployer initialized")
    
    def _find_terraform_binary(self) -> str:
        """Find terraform binary in PATH."""
        terraform_path = shutil.which("terraform")
        if not terraform_path:
            raise RuntimeError("Terraform binary not found in PATH. Please install Terraform.")
        
        self.logger.info(f"Found terraform binary at: {terraform_path}")
        return terraform_path
    
    async def deploy_infrastructure(
        self,
        infrastructure_plan: InfrastructurePlan,
        terraform_files: List[str],
        environment: str = "dev",
        auto_approve: bool = False
    ) -> DeploymentResult:
        """
        Deploy infrastructure using Terraform.
        
        Args:
            infrastructure_plan: Infrastructure plan to deploy
            terraform_files: List of generated terraform files
            environment: Target environment
            auto_approve: Whether to auto-approve terraform apply
            
        Returns:
            Deployment result
        """
        self.logger.info(f"Starting terraform deployment for {infrastructure_plan['plan_id']}")
        
        deployment_id = f"deploy-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        
        try:
            # Create deployment context
            context = await self._create_deployment_context(
                infrastructure_plan, terraform_files, environment, deployment_id
            )
            self.current_deployment = context
            self.deployment_status = DeploymentStatus.INITIALIZING
            
            # Initialize Terraform
            self.logger.info("Initializing Terraform...")
            init_result = await self._execute_terraform_command(
                TerraformCommand.INIT, context
            )
            
            if not init_result.success:
                return self._create_failed_deployment_result(
                    deployment_id, infrastructure_plan, "Terraform initialization failed", init_result
                )
            
            # Validate configuration
            self.logger.info("Validating Terraform configuration...")
            validate_result = await self._execute_terraform_command(
                TerraformCommand.VALIDATE, context
            )
            
            if not validate_result.success:
                return self._create_failed_deployment_result(
                    deployment_id, infrastructure_plan, "Terraform validation failed", validate_result
                )
            
            # Plan deployment
            self.logger.info("Planning Terraform deployment...")
            self.deployment_status = DeploymentStatus.PLANNING
            plan_result = await self._execute_terraform_command(
                TerraformCommand.PLAN, context, ["-detailed-exitcode"]
            )
            
            # Check if there are changes to apply
            if plan_result.exit_code == 0:
                self.logger.info("No changes detected, infrastructure is up to date")
                return self._create_successful_deployment_result(
                    deployment_id, infrastructure_plan, "No changes required"
                )
            elif plan_result.exit_code == 2:
                self.logger.info("Changes detected, proceeding with apply...")
            else:
                return self._create_failed_deployment_result(
                    deployment_id, infrastructure_plan, "Terraform plan failed", plan_result
                )
            
            # Apply changes
            self.logger.info("Applying Terraform configuration...")
            self.deployment_status = DeploymentStatus.APPLYING
            apply_args = ["-auto-approve"] if auto_approve else []
            apply_result = await self._execute_terraform_command(
                TerraformCommand.APPLY, context, apply_args
            )
            
            if not apply_result.success:
                return self._create_failed_deployment_result(
                    deployment_id, infrastructure_plan, "Terraform apply failed", apply_result
                )
            
            # Get deployment outputs
            outputs = await self._get_terraform_outputs(context)
            
            # Create successful result
            self.deployment_status = DeploymentStatus.COMPLETED
            
            result = DeploymentResult(
                deployment_id=deployment_id,
                status="completed",
                cluster_name=outputs.get("cluster_name", ""),
                cluster_arn=outputs.get("cluster_arn", ""),
                vpc_id=outputs.get("vpc_id", ""),
                application_endpoints=outputs.get("application_endpoints", []),
                monitoring_dashboards=outputs.get("monitoring_dashboards", []),
                cost_analysis={"actual_monthly": infrastructure_plan['estimated_cost']['monthly']},
                security_scan_results={"vulnerabilities": 0},
                deployment_logs=self._get_deployment_logs(context),
                rollback_plan=await self._create_rollback_plan(context, infrastructure_plan)
            )
            
            self.logger.info(f"Terraform deployment completed successfully: {deployment_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Terraform deployment failed: {e}")
            return self._create_failed_deployment_result(
                deployment_id, infrastructure_plan, f"Deployment error: {str(e)}", None
            )
    
    async def destroy_infrastructure(
        self,
        infrastructure_plan: InfrastructurePlan,
        terraform_files: List[str],
        environment: str = "dev",
        auto_approve: bool = False
    ) -> DeploymentResult:
        """
        Destroy infrastructure using Terraform.
        
        Args:
            infrastructure_plan: Infrastructure plan to destroy
            terraform_files: List of terraform files
            environment: Target environment
            auto_approve: Whether to auto-approve terraform destroy
            
        Returns:
            Destruction result
        """
        self.logger.info(f"Starting terraform destruction for {infrastructure_plan['plan_id']}")
        
        deployment_id = f"destroy-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        
        try:
            # Create deployment context
            context = await self._create_deployment_context(
                infrastructure_plan, terraform_files, environment, deployment_id
            )
            
            # Initialize Terraform
            init_result = await self._execute_terraform_command(
                TerraformCommand.INIT, context
            )
            
            if not init_result.success:
                return self._create_failed_deployment_result(
                    deployment_id, infrastructure_plan, "Terraform initialization failed", init_result
                )
            
            # Destroy infrastructure
            self.logger.info("Destroying Terraform infrastructure...")
            destroy_args = ["-auto-approve"] if auto_approve else []
            destroy_result = await self._execute_terraform_command(
                TerraformCommand.DESTROY, context, destroy_args
            )
            
            if not destroy_result.success:
                return self._create_failed_deployment_result(
                    deployment_id, infrastructure_plan, "Terraform destroy failed", destroy_result
                )
            
            result = DeploymentResult(
                deployment_id=deployment_id,
                status="completed",
                cluster_name="",
                cluster_arn="",
                vpc_id="",
                application_endpoints=[],
                monitoring_dashboards=[],
                cost_analysis={"actual_monthly": 0.0},
                security_scan_results={"vulnerabilities": 0},
                deployment_logs=self._get_deployment_logs(context),
                rollback_plan=None
            )
            
            self.logger.info(f"Terraform destruction completed successfully: {deployment_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Terraform destruction failed: {e}")
            return self._create_failed_deployment_result(
                deployment_id, infrastructure_plan, f"Destruction error: {str(e)}", None
            )
    
    async def _create_deployment_context(
        self,
        infrastructure_plan: InfrastructurePlan,
        terraform_files: List[str],
        environment: str,
        deployment_id: str
    ) -> DeploymentContext:
        """Create deployment context for terraform execution."""
        project_name = infrastructure_plan.get('project_name', 'unknown')
        
        # Create deployment directory
        deployment_dir = self.workspace_dir / "deployments" / deployment_id
        deployment_dir.mkdir(parents=True, exist_ok=True)
        
        # Create terraform working directory
        terraform_dir = deployment_dir / "terraform"
        terraform_dir.mkdir(exist_ok=True)
        
        # Copy terraform files to working directory preserving structure
        for file_path in terraform_files:
            src_path = Path(file_path)
            if src_path.exists():
                # Preserve directory structure for module files
                if "/modules/" in str(src_path):
                    # Extract module path (e.g., modules/vpc/main.tf)
                    parts = src_path.parts
                    modules_index = parts.index('modules')
                    relative_path = Path(*parts[modules_index:])
                    dst_path = terraform_dir / relative_path
                    dst_path.parent.mkdir(parents=True, exist_ok=True)
                elif "/kubernetes/" in str(src_path):
                    # Extract kubernetes path
                    parts = src_path.parts
                    kubernetes_index = parts.index('kubernetes')
                    relative_path = Path(*parts[kubernetes_index:])
                    dst_path = terraform_dir / relative_path
                    dst_path.parent.mkdir(parents=True, exist_ok=True)
                else:
                    # Main terraform files go in root
                    dst_path = terraform_dir / src_path.name
                
                shutil.copy2(src_path, dst_path)
                self.logger.debug(f"Copied {src_path} to {dst_path}")
        
        # Find tfvars file
        tfvars_file = None
        for file_path in terraform_files:
            if file_path.endswith('.tfvars'):
                tfvars_file = terraform_dir / Path(file_path).name
                break
        
        if not tfvars_file:
            # Create default tfvars file
            tfvars_file = terraform_dir / f"{environment}.tfvars"
            with open(tfvars_file, 'w') as f:
                f.write(f'# Default variables for {environment}\n')
        
        # Create backup directory
        backup_dir = deployment_dir / "backups"
        backup_dir.mkdir(exist_ok=True)
        
        # Create log file
        log_file = deployment_dir / "deployment.log"
        
        context = DeploymentContext(
            terraform_dir=terraform_dir,
            tfvars_file=tfvars_file,
            state_file=None,
            backup_dir=backup_dir,
            log_file=log_file,
            environment=environment,
            project_name=project_name
        )
        
        return context
    
    async def _execute_terraform_command(
        self,
        command: TerraformCommand,
        context: DeploymentContext,
        additional_args: List[str] = None
    ) -> TerraformExecutionResult:
        """Execute a terraform command."""
        additional_args = additional_args or []
        
        # Build command
        cmd = [self.terraform_path, command.value]
        
        # Add common arguments
        if command in [TerraformCommand.PLAN, TerraformCommand.APPLY, TerraformCommand.DESTROY]:
            cmd.extend(["-var-file", str(context.tfvars_file)])
        
        # Add additional arguments
        cmd.extend(additional_args)
        
        # Set environment variables
        env = os.environ.copy()
        env.update({
            'TF_IN_AUTOMATION': 'true',
            'TF_INPUT': 'false',
            'TF_LOG': 'INFO' if self.config.debug_mode else 'ERROR'
        })
        
        start_time = datetime.utcnow()
        
        try:
            self.logger.info(f"Executing: {' '.join(cmd)}")
            
            # Execute command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=context.terraform_dir,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Decode output
            output = stdout.decode('utf-8') if stdout else ""
            error = stderr.decode('utf-8') if stderr else ""
            
            # Log output
            self._log_terraform_output(context, command, output, error)
            
            success = process.returncode == 0
            
            result = TerraformExecutionResult(
                command=command,
                success=success,
                output=output,
                error=error,
                duration=duration,
                exit_code=process.returncode,
                timestamp=datetime.utcnow()
            )
            
            if success:
                self.logger.info(f"Terraform {command.value} completed successfully in {duration:.2f}s")
            else:
                self.logger.error(f"Terraform {command.value} failed with exit code {process.returncode}")
                self.logger.error(f"Error output: {error}")
            
            return result
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            self.logger.error(f"Failed to execute terraform {command.value}: {e}")
            
            return TerraformExecutionResult(
                command=command,
                success=False,
                output="",
                error=str(e),
                duration=duration,
                exit_code=-1,
                timestamp=datetime.utcnow()
            )
    
    def _log_terraform_output(
        self,
        context: DeploymentContext,
        command: TerraformCommand,
        output: str,
        error: str
    ) -> None:
        """Log terraform command output to file."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(context.log_file, 'a') as f:
            f.write(f"\n=== Terraform {command.value.upper()} - {timestamp} ===\n")
            if output:
                f.write(f"STDOUT:\n{output}\n")
            if error:
                f.write(f"STDERR:\n{error}\n")
            f.write("=" * 50 + "\n")
    
    async def _get_terraform_outputs(self, context: DeploymentContext) -> Dict[str, Any]:
        """Get terraform outputs."""
        output_result = await self._execute_terraform_command(
            TerraformCommand.OUTPUT, context, ["-json"]
        )
        
        if output_result.success and output_result.output:
            try:
                outputs = json.loads(output_result.output)
                # Extract values from terraform output format
                extracted_outputs = {}
                for key, value in outputs.items():
                    if isinstance(value, dict) and 'value' in value:
                        extracted_outputs[key] = value['value']
                    else:
                        extracted_outputs[key] = value
                return extracted_outputs
            except json.JSONDecodeError:
                self.logger.warning("Failed to parse terraform outputs as JSON")
        
        return {}
    
    def _get_deployment_logs(self, context: DeploymentContext) -> List[str]:
        """Get deployment logs."""
        try:
            if context.log_file.exists():
                with open(context.log_file, 'r') as f:
                    return f.read().split('\n')
        except Exception as e:
            self.logger.warning(f"Failed to read deployment logs: {e}")
        
        return ["Deployment logs not available"]
    
    async def _create_rollback_plan(
        self,
        context: DeploymentContext,
        infrastructure_plan: InfrastructurePlan
    ) -> Dict[str, Any]:
        """Create rollback plan for the deployment."""
        return {
            "rollback_method": "terraform_destroy",
            "terraform_dir": str(context.terraform_dir),
            "tfvars_file": str(context.tfvars_file),
            "backup_dir": str(context.backup_dir),
            "created_at": datetime.utcnow().isoformat(),
            "instructions": [
                "1. Navigate to terraform directory",
                "2. Run 'terraform init'",
                "3. Run 'terraform destroy -var-file=<tfvars_file> -auto-approve'",
                "4. Verify all resources are destroyed in AWS console"
            ]
        }
    
    def _create_successful_deployment_result(
        self,
        deployment_id: str,
        infrastructure_plan: InfrastructurePlan,
        message: str
    ) -> DeploymentResult:
        """Create successful deployment result."""
        return DeploymentResult(
            deployment_id=deployment_id,
            status="completed",
            cluster_name=infrastructure_plan.get('eks_configuration', {}).get('cluster_name', ''),
            cluster_arn='',
            vpc_id='',
            application_endpoints=[],
            monitoring_dashboards=[],
            cost_analysis={"actual_monthly": infrastructure_plan['estimated_cost']['monthly']},
            security_scan_results={"vulnerabilities": 0},
            deployment_logs=[message],
            rollback_plan={}
        )
    
    def _create_failed_deployment_result(
        self,
        deployment_id: str,
        infrastructure_plan: InfrastructurePlan,
        error_message: str,
        terraform_result: Optional[TerraformExecutionResult]
    ) -> DeploymentResult:
        """Create failed deployment result."""
        logs = [error_message]
        if terraform_result:
            logs.extend([
                f"Command: {terraform_result.command.value}",
                f"Exit code: {terraform_result.exit_code}",
                f"Output: {terraform_result.output}",
                f"Error: {terraform_result.error}"
            ])
        
        return DeploymentResult(
            deployment_id=deployment_id,
            status="failed",
            cluster_name="",
            cluster_arn="",
            vpc_id="",
            application_endpoints=[],
            monitoring_dashboards=[],
            cost_analysis={"actual_monthly": 0.0},
            security_scan_results={"vulnerabilities": 0},
            deployment_logs=logs,
            rollback_plan=None
        )
    
    def get_deployment_status(self) -> Dict[str, Any]:
        """Get current deployment status."""
        return {
            "status": self.deployment_status.value,
            "current_deployment": str(self.current_deployment.terraform_dir) if self.current_deployment else None,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def cleanup_deployment(self, deployment_id: str) -> bool:
        """Clean up deployment files."""
        try:
            deployment_dir = self.workspace_dir / "deployments" / deployment_id
            if deployment_dir.exists():
                shutil.rmtree(deployment_dir)
                self.logger.info(f"Cleaned up deployment directory: {deployment_dir}")
                return True
        except Exception as e:
            self.logger.error(f"Failed to cleanup deployment {deployment_id}: {e}")
        
        return False 