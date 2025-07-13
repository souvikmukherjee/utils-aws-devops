"""
Repository Analyzer module for analyzing Git repositories and extracting infrastructure requirements.

This module provides functionality to:
- Clone and analyze Git repositories
- Detect application framework and language
- Extract dependencies and configuration
- Assess infrastructure requirements
- Perform security analysis
"""

import os
import json
import yaml
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import tempfile
import shutil

import git
from github import Github
import docker
from kubernetes import config as k8s_config
import requests

from ..core.state import RepositoryAnalysis, ApplicationType, InfrastructureRequirement
from ..core.config import AgentConfig


class RepositoryAnalyzer:
    """
    Analyzes Git repositories to understand application requirements and infrastructure needs.
    
    This class can analyze various types of applications and extract the information needed
    to plan appropriate AWS infrastructure deployment.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the Repository Analyzer.
        
        Args:
            config: Agent configuration containing GitHub tokens and settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize GitHub client if token is available
        self.github_client = None
        if config.github_token:
            self.github_client = Github(config.github_token)
        
        # Docker client for Dockerfile analysis
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            self.logger.warning(f"Docker client not available: {e}")
            self.docker_client = None
    
    async def analyze_repository(self, repository_url: str, target_branch: str = "main") -> RepositoryAnalysis:
        """
        Analyze a Git repository and extract infrastructure requirements.
        
        Args:
            repository_url: URL of the Git repository
            target_branch: Git branch to analyze (default: main)
            
        Returns:
            Repository analysis results
            
        Raises:
            ValueError: If repository URL is invalid or inaccessible
        """
        self.logger.info(f"Starting analysis of repository: {repository_url}")
        
        # Create temporary directory for cloning
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "repo"
            
            try:
                # Clone repository
                repo = await self._clone_repository(repository_url, repo_path, target_branch)
                
                # Extract basic repository information
                repo_info = await self._extract_repo_info(repository_url, repo)
                
                # Analyze code structure
                code_analysis = await self._analyze_code_structure(repo_path)
                
                # Detect application type and framework
                app_type, framework = await self._detect_application_type(repo_path, code_analysis)
                
                # Analyze dependencies
                dependencies = await self._analyze_dependencies(repo_path, code_analysis)
                
                # Check for existing infrastructure files
                infra_files = await self._check_infrastructure_files(repo_path)
                
                # Assess infrastructure requirements
                infra_requirements = await self._assess_infrastructure_requirements(
                    app_type, framework, dependencies, code_analysis
                )
                
                # Perform security analysis
                security_analysis = await self._perform_security_analysis(repo_path, dependencies)
                
                # Calculate complexity score
                complexity_score = await self._calculate_complexity_score(code_analysis, dependencies)
                
                # Estimate resource requirements
                estimated_resources = await self._estimate_resources(
                    app_type, framework, complexity_score, infra_requirements
                )
                
                # Compile analysis results
                analysis = RepositoryAnalysis(
                    url=repository_url,
                    name=repo_info["name"],
                    language=code_analysis["primary_language"],
                    framework=framework,
                    dependencies=dependencies,
                    application_type=app_type,
                    dockerfile_present=infra_files["dockerfile"],
                    k8s_manifests_present=infra_files["kubernetes"],
                    infrastructure_requirements=infra_requirements,
                    security_analysis=security_analysis,
                    complexity_score=complexity_score,
                    estimated_resources=estimated_resources
                )
                
                self.logger.info(f"Repository analysis completed for: {repository_url}")
                return analysis
                
            except Exception as e:
                self.logger.error(f"Repository analysis failed: {e}")
                raise ValueError(f"Failed to analyze repository: {e}")
    
    async def _clone_repository(self, repository_url: str, repo_path: Path, branch: str) -> git.Repo:
        """Clone Git repository to local path."""
        self.logger.debug(f"Cloning repository {repository_url} to {repo_path}")
        
        try:
            repo = git.Repo.clone_from(repository_url, repo_path, branch=branch, depth=1)
            return repo
        except git.exc.GitCommandError as e:
            # Try with default branch if specified branch doesn't exist
            if branch != "main":
                try:
                    repo = git.Repo.clone_from(repository_url, repo_path, depth=1)
                    return repo
                except git.exc.GitCommandError:
                    pass
            raise ValueError(f"Failed to clone repository: {e}")
    
    async def _extract_repo_info(self, repository_url: str, repo: git.Repo) -> Dict[str, Any]:
        """Extract basic repository information."""
        repo_name = repository_url.rstrip('/').split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        
        info = {
            "name": repo_name,
            "url": repository_url,
            "default_branch": repo.active_branch.name if repo.active_branch else "main",
            "commit_count": len(list(repo.iter_commits())),
            "last_commit": repo.head.commit.hexsha[:8] if repo.head.commit else None
        }
        
        # Try to get additional info from GitHub API if available
        if self.github_client and "github.com" in repository_url:
            try:
                repo_path = repository_url.replace("https://github.com/", "").replace(".git", "")
                gh_repo = self.github_client.get_repo(repo_path)
                info.update({
                    "description": gh_repo.description,
                    "stars": gh_repo.stargazers_count,
                    "forks": gh_repo.forks_count,
                    "language": gh_repo.language,
                    "topics": gh_repo.get_topics()
                })
            except Exception as e:
                self.logger.debug(f"Could not fetch GitHub metadata: {e}")
        
        return info
    
    async def _analyze_code_structure(self, repo_path: Path) -> Dict[str, Any]:
        """Analyze the code structure and file organization."""
        structure = {
            "total_files": 0,
            "total_lines": 0,
            "file_types": {},
            "languages": {},
            "directories": [],
            "primary_language": "unknown",
            "config_files": [],
            "test_files": [],
            "documentation_files": []
        }
        
        # Common file extensions and their languages
        language_extensions = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rs': 'rust',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.kt': 'kotlin',
            '.swift': 'swift',
            '.scala': 'scala',
            '.r': 'r',
            '.sh': 'shell',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.json': 'json',
            '.xml': 'xml',
            '.html': 'html',
            '.css': 'css',
            '.scss': 'scss',
            '.sql': 'sql'
        }
        
        # Walk through all files
        for file_path in repo_path.rglob('*'):
            if file_path.is_file() and not file_path.name.startswith('.'):
                structure["total_files"] += 1
                
                # Count file types
                extension = file_path.suffix.lower()
                structure["file_types"][extension] = structure["file_types"].get(extension, 0) + 1
                
                # Map to languages
                if extension in language_extensions:
                    lang = language_extensions[extension]
                    structure["languages"][lang] = structure["languages"].get(lang, 0) + 1
                
                # Count lines for code files
                if extension in ['.py', '.js', '.ts', '.java', '.go', '.rs', '.cpp', '.c', '.cs']:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = len(f.readlines())
                            structure["total_lines"] += lines
                    except Exception:
                        pass
                
                # Categorize special files
                filename = file_path.name.lower()
                if any(config in filename for config in ['config', '.env', 'settings', 'properties']):
                    structure["config_files"].append(str(file_path.relative_to(repo_path)))
                elif any(test in filename for test in ['test', 'spec']):
                    structure["test_files"].append(str(file_path.relative_to(repo_path)))
                elif any(doc in filename for doc in ['readme', 'doc', '.md']):
                    structure["documentation_files"].append(str(file_path.relative_to(repo_path)))
        
        # Determine primary language
        if structure["languages"]:
            structure["primary_language"] = max(structure["languages"], key=structure["languages"].get)
        
        # Get directory structure
        structure["directories"] = [
            str(d.relative_to(repo_path)) 
            for d in repo_path.rglob('*') 
            if d.is_dir() and not d.name.startswith('.')
        ]
        
        return structure
    
    async def _detect_application_type(self, repo_path: Path, code_analysis: Dict[str, Any]) -> Tuple[ApplicationType, str]:
        """Detect the application type and framework."""
        primary_language = code_analysis["primary_language"]
        framework = "unknown"
        app_type = ApplicationType.UNKNOWN
        
        # Check for specific framework files and patterns
        framework_indicators = {
            # Python frameworks
            'fastapi': ['main.py', 'app.py', 'requirements.txt'],
            'flask': ['app.py', 'wsgi.py', 'requirements.txt'],
            'django': ['manage.py', 'settings.py', 'wsgi.py'],
            'streamlit': ['streamlit_app.py', 'requirements.txt'],
            
            # JavaScript/TypeScript frameworks
            'express': ['package.json', 'app.js', 'server.js'],
            'nextjs': ['next.config.js', 'package.json'],
            'react': ['package.json', 'src/App.js', 'src/App.tsx'],
            'vue': ['package.json', 'vue.config.js'],
            'angular': ['angular.json', 'package.json'],
            'nestjs': ['nest-cli.json', 'package.json'],
            
            # Java frameworks
            'spring': ['pom.xml', 'src/main/java', 'application.properties'],
            'springboot': ['pom.xml', 'src/main/java', 'application.yml'],
            
            # Go frameworks
            'gin': ['go.mod', 'main.go'],
            'echo': ['go.mod', 'main.go'],
            
            # Other
            'docker': ['Dockerfile'],
            'kubernetes': ['deployment.yaml', 'service.yaml']
        }
        
        # Check for framework files
        detected_frameworks = []
        for fw, indicators in framework_indicators.items():
            if all((repo_path / indicator).exists() for indicator in indicators[:2]):  # Check first 2 indicators
                detected_frameworks.append(fw)
        
        # Analyze package files for more specific detection
        if (repo_path / 'package.json').exists():
            try:
                with open(repo_path / 'package.json', 'r') as f:
                    package_data = json.load(f)
                    dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
                    
                    if 'fastapi' in dependencies or 'uvicorn' in dependencies:
                        framework = 'fastapi'
                        app_type = ApplicationType.API_SERVICE
                    elif 'express' in dependencies:
                        framework = 'express'
                        app_type = ApplicationType.API_SERVICE
                    elif 'next' in dependencies:
                        framework = 'nextjs'
                        app_type = ApplicationType.WEB_APP
                    elif 'react' in dependencies:
                        framework = 'react'
                        app_type = ApplicationType.WEB_APP
                    elif '@nestjs/core' in dependencies:
                        framework = 'nestjs'
                        app_type = ApplicationType.API_SERVICE
            except Exception as e:
                self.logger.debug(f"Error parsing package.json: {e}")
        
        elif (repo_path / 'requirements.txt').exists():
            try:
                with open(repo_path / 'requirements.txt', 'r') as f:
                    requirements = f.read().lower()
                    
                    if 'fastapi' in requirements:
                        framework = 'fastapi'
                        app_type = ApplicationType.API_SERVICE
                    elif 'flask' in requirements:
                        framework = 'flask'
                        app_type = ApplicationType.WEB_APP
                    elif 'django' in requirements:
                        framework = 'django'
                        app_type = ApplicationType.WEB_APP
                    elif 'streamlit' in requirements:
                        framework = 'streamlit'
                        app_type = ApplicationType.WEB_APP
                    elif any(ml_lib in requirements for ml_lib in ['tensorflow', 'pytorch', 'scikit-learn']):
                        framework = 'ml-python'
                        app_type = ApplicationType.ML_SERVICE
            except Exception as e:
                self.logger.debug(f"Error parsing requirements.txt: {e}")
        
        elif (repo_path / 'pom.xml').exists():
            try:
                with open(repo_path / 'pom.xml', 'r') as f:
                    pom_content = f.read()
                    
                    if 'spring-boot' in pom_content:
                        framework = 'springboot'
                        app_type = ApplicationType.API_SERVICE
                    elif 'spring' in pom_content:
                        framework = 'spring'
                        app_type = ApplicationType.WEB_APP
            except Exception as e:
                self.logger.debug(f"Error parsing pom.xml: {e}")
        
        # Determine application type based on directory structure if not detected
        if app_type == ApplicationType.UNKNOWN:
            directories = code_analysis.get("directories", [])
            
            if any('api' in d for d in directories):
                app_type = ApplicationType.API_SERVICE
            elif any('web' in d or 'frontend' in d for d in directories):
                app_type = ApplicationType.WEB_APP
            elif any('worker' in d or 'job' in d for d in directories):
                app_type = ApplicationType.BATCH_JOB
            elif any('data' in d or 'etl' in d for d in directories):
                app_type = ApplicationType.DATA_PIPELINE
            elif primary_language in ['python', 'r'] and any('model' in d or 'ml' in d for d in directories):
                app_type = ApplicationType.ML_SERVICE
            else:
                # Default based on primary language
                if primary_language == 'python':
                    app_type = ApplicationType.API_SERVICE
                elif primary_language in ['javascript', 'typescript']:
                    app_type = ApplicationType.WEB_APP
                elif primary_language == 'java':
                    app_type = ApplicationType.API_SERVICE
                else:
                    app_type = ApplicationType.MICROSERVICE
        
        # Set framework if still unknown
        if framework == "unknown":
            if detected_frameworks:
                framework = detected_frameworks[0]
            else:
                framework = primary_language
        
        return app_type, framework
    
    async def _analyze_dependencies(self, repo_path: Path, code_analysis: Dict[str, Any]) -> List[str]:
        """Analyze project dependencies."""
        dependencies = []
        
        # Python dependencies
        if (repo_path / 'requirements.txt').exists():
            try:
                with open(repo_path / 'requirements.txt', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract package name (before version specifiers)
                            dep = line.split('==')[0].split('>=')[0].split('<=')[0].split('>')[0].split('<')[0]
                            dependencies.append(dep.strip())
            except Exception as e:
                self.logger.debug(f"Error parsing requirements.txt: {e}")
        
        # Node.js dependencies
        if (repo_path / 'package.json').exists():
            try:
                with open(repo_path / 'package.json', 'r') as f:
                    package_data = json.load(f)
                    deps = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
                    dependencies.extend(deps.keys())
            except Exception as e:
                self.logger.debug(f"Error parsing package.json: {e}")
        
        # Java dependencies (Maven)
        if (repo_path / 'pom.xml').exists():
            # Simple XML parsing for Maven dependencies
            try:
                with open(repo_path / 'pom.xml', 'r') as f:
                    content = f.read()
                    # Basic regex-like extraction (simplified)
                    import re
                    artifacts = re.findall(r'<artifactId>(.*?)</artifactId>', content)
                    dependencies.extend(artifacts)
            except Exception as e:
                self.logger.debug(f"Error parsing pom.xml: {e}")
        
        # Go dependencies
        if (repo_path / 'go.mod').exists():
            try:
                with open(repo_path / 'go.mod', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('require '):
                            # Extract module name
                            parts = line.replace('require ', '').split()
                            if parts:
                                dependencies.append(parts[0])
            except Exception as e:
                self.logger.debug(f"Error parsing go.mod: {e}")
        
        return dependencies
    
    async def _check_infrastructure_files(self, repo_path: Path) -> Dict[str, bool]:
        """Check for existing infrastructure and deployment files."""
        checks = {
            "dockerfile": False,
            "docker_compose": False,
            "kubernetes": False,
            "terraform": False,
            "helm": False,
            "cloudformation": False,
            "github_actions": False,
            "gitlab_ci": False
        }
        
        # Check for specific files
        file_checks = {
            "dockerfile": ['Dockerfile', 'dockerfile'],
            "docker_compose": ['docker-compose.yml', 'docker-compose.yaml'],
            "kubernetes": ['deployment.yaml', 'service.yaml', 'ingress.yaml'],
            "terraform": ['main.tf', '*.tf'],
            "helm": ['Chart.yaml', 'values.yaml'],
            "cloudformation": ['template.yaml', 'template.json'],
            "github_actions": ['.github/workflows'],
            "gitlab_ci": ['.gitlab-ci.yml']
        }
        
        for check_type, files_to_check in file_checks.items():
            for file_pattern in files_to_check:
                if '*' in file_pattern:
                    # Use glob for patterns
                    if list(repo_path.glob(file_pattern)):
                        checks[check_type] = True
                        break
                else:
                    if (repo_path / file_pattern).exists():
                        checks[check_type] = True
                        break
        
        return checks
    
    async def _assess_infrastructure_requirements(
        self, 
        app_type: ApplicationType, 
        framework: str, 
        dependencies: List[str], 
        code_analysis: Dict[str, Any]
    ) -> InfrastructureRequirement:
        """Assess infrastructure requirements based on application analysis."""
        
        # Base requirements templates
        base_requirements = {
            ApplicationType.WEB_APP: {
                "compute": {"cpu": "500m", "memory": "512Mi", "instances": 2},
                "storage": {"persistent": True, "size_gb": 10},
                "networking": {"load_balancer": True, "cdn": True},
                "estimated_cost": 150.0
            },
            ApplicationType.API_SERVICE: {
                "compute": {"cpu": "250m", "memory": "256Mi", "instances": 2},
                "storage": {"persistent": False, "size_gb": 5},
                "networking": {"load_balancer": True, "cdn": False},
                "estimated_cost": 100.0
            },
            ApplicationType.MICROSERVICE: {
                "compute": {"cpu": "200m", "memory": "256Mi", "instances": 3},
                "storage": {"persistent": False, "size_gb": 5},
                "networking": {"service_mesh": True, "load_balancer": True},
                "estimated_cost": 120.0
            },
            ApplicationType.DATA_PIPELINE: {
                "compute": {"cpu": "1000m", "memory": "2Gi", "instances": 1},
                "storage": {"persistent": True, "size_gb": 100},
                "networking": {"load_balancer": False, "private": True},
                "estimated_cost": 300.0
            },
            ApplicationType.ML_SERVICE: {
                "compute": {"cpu": "2000m", "memory": "4Gi", "instances": 1, "gpu": True},
                "storage": {"persistent": True, "size_gb": 50},
                "networking": {"load_balancer": True, "cdn": False},
                "estimated_cost": 500.0
            },
            ApplicationType.BATCH_JOB: {
                "compute": {"cpu": "500m", "memory": "1Gi", "instances": 1},
                "storage": {"persistent": True, "size_gb": 20},
                "networking": {"load_balancer": False, "private": True},
                "estimated_cost": 80.0
            }
        }
        
        # Get base requirements for application type
        base_req = base_requirements.get(app_type, base_requirements[ApplicationType.API_SERVICE])
        
        # Adjust based on framework and dependencies
        compute_multiplier = 1.0
        storage_multiplier = 1.0
        cost_multiplier = 1.0
        
        # Framework-specific adjustments
        framework_adjustments = {
            'django': {'compute': 1.3, 'storage': 1.2, 'cost': 1.2},
            'spring': {'compute': 1.4, 'storage': 1.1, 'cost': 1.3},
            'springboot': {'compute': 1.2, 'storage': 1.1, 'cost': 1.1},
            'nextjs': {'compute': 1.1, 'storage': 1.0, 'cost': 1.1},
            'react': {'compute': 0.8, 'storage': 0.9, 'cost': 0.9},
            'fastapi': {'compute': 0.9, 'storage': 0.8, 'cost': 0.9}
        }
        
        if framework in framework_adjustments:
            adj = framework_adjustments[framework]
            compute_multiplier *= adj['compute']
            storage_multiplier *= adj['storage'] 
            cost_multiplier *= adj['cost']
        
        # Dependency-based adjustments
        heavy_dependencies = ['tensorflow', 'pytorch', 'pandas', 'numpy', 'opencv']
        database_dependencies = ['postgresql', 'mysql', 'mongodb', 'redis']
        
        if any(dep in dependencies for dep in heavy_dependencies):
            compute_multiplier *= 1.5
            cost_multiplier *= 1.3
        
        if any(dep in dependencies for dep in database_dependencies):
            storage_multiplier *= 1.5
            cost_multiplier *= 1.2
        
        # Code complexity adjustments
        total_lines = code_analysis.get("total_lines", 0)
        if total_lines > 10000:
            compute_multiplier *= 1.2
            cost_multiplier *= 1.1
        elif total_lines > 50000:
            compute_multiplier *= 1.5
            cost_multiplier *= 1.3
        
        # Apply multipliers to base requirements
        adjusted_compute = base_req["compute"].copy()
        adjusted_compute["cpu"] = f"{int(float(adjusted_compute['cpu'].replace('m', '')) * compute_multiplier)}m"
        adjusted_compute["memory"] = f"{int(float(adjusted_compute['memory'].replace('Mi', '').replace('Gi', '')) * compute_multiplier * (1024 if 'Gi' in adjusted_compute['memory'] else 1))}Mi"
        
        adjusted_storage = base_req["storage"].copy()
        adjusted_storage["size_gb"] = int(adjusted_storage["size_gb"] * storage_multiplier)
        
        # Security requirements based on application type
        security_req = {
            "encryption_at_rest": True,
            "encryption_in_transit": True,
            "authentication_required": app_type in [ApplicationType.WEB_APP, ApplicationType.API_SERVICE],
            "authorization_required": True,
            "network_policies": True,
            "secrets_management": len(dependencies) > 5
        }
        
        # Monitoring requirements
        monitoring_req = {
            "metrics_collection": True,
            "log_aggregation": True,
            "health_checks": True,
            "alerting": True,
            "distributed_tracing": app_type == ApplicationType.MICROSERVICE
        }
        
        # Compliance requirements based on data handling
        compliance_requirements = ["AWS-Well-Architected"]
        if app_type in [ApplicationType.WEB_APP, ApplicationType.API_SERVICE]:
            compliance_requirements.extend(["SOC2", "GDPR"])
        
        return InfrastructureRequirement(
            compute=adjusted_compute,
            storage=adjusted_storage,
            networking=base_req["networking"],
            security=security_req,
            monitoring=monitoring_req,
            estimated_cost=base_req["estimated_cost"] * cost_multiplier,
            compliance_requirements=compliance_requirements
        )
    
    async def _perform_security_analysis(self, repo_path: Path, dependencies: List[str]) -> Dict[str, Any]:
        """Perform basic security analysis of the repository."""
        security_analysis = {
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": [],
            "security_score": 0.8  # Default score
        }
        
        # Check for common security issues
        security_issues = []
        
        # Check for exposed secrets (basic patterns)
        secret_patterns = [
            'password', 'secret', 'key', 'token', 'api_key',
            'aws_access_key', 'aws_secret', 'database_url'
        ]
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.java', '.go']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        for pattern in secret_patterns:
                            if f'{pattern}=' in content or f'"{pattern}"' in content:
                                security_issues.append(f"Potential secret exposure in {file_path.name}")
                                break
                except Exception:
                    pass
        
        # Check for security-related dependencies
        security_deps = [dep for dep in dependencies if 'security' in dep.lower() or 'auth' in dep.lower()]
        
        # Generate recommendations
        recommendations = []
        if not security_deps:
            recommendations.append("Consider adding authentication and authorization libraries")
        
        if security_issues:
            recommendations.append("Review potential secret exposures and use environment variables")
            security_analysis["security_score"] -= 0.2
        
        recommendations.extend([
            "Implement proper input validation",
            "Use HTTPS for all communications",
            "Implement rate limiting",
            "Regular security updates for dependencies"
        ])
        
        security_analysis.update({
            "security_issues": security_issues,
            "recommendations": recommendations,
            "security_dependencies": security_deps
        })
        
        return security_analysis
    
    async def _calculate_complexity_score(self, code_analysis: Dict[str, Any], dependencies: List[str]) -> float:
        """Calculate a complexity score for the application."""
        score = 0.0
        
        # Base score from lines of code
        total_lines = code_analysis.get("total_lines", 0)
        if total_lines < 1000:
            score += 0.1
        elif total_lines < 5000:
            score += 0.3
        elif total_lines < 20000:
            score += 0.5
        elif total_lines < 50000:
            score += 0.7
        else:
            score += 0.9
        
        # Score from number of dependencies
        dep_count = len(dependencies)
        if dep_count < 5:
            score += 0.1
        elif dep_count < 15:
            score += 0.2
        elif dep_count < 30:
            score += 0.4
        else:
            score += 0.6
        
        # Score from file diversity
        file_types = len(code_analysis.get("file_types", {}))
        score += min(0.3, file_types * 0.02)
        
        # Score from directory structure
        dir_count = len(code_analysis.get("directories", []))
        score += min(0.2, dir_count * 0.01)
        
        return min(1.0, score)  # Cap at 1.0
    
    async def _estimate_resources(
        self, 
        app_type: ApplicationType, 
        framework: str, 
        complexity_score: float,
        infra_requirements: InfrastructureRequirement
    ) -> Dict[str, Any]:
        """Estimate detailed resource requirements."""
        
        # Base instance recommendations
        base_instances = {
            ApplicationType.WEB_APP: {"min": 2, "max": 10, "desired": 3},
            ApplicationType.API_SERVICE: {"min": 2, "max": 8, "desired": 2},
            ApplicationType.MICROSERVICE: {"min": 1, "max": 5, "desired": 2},
            ApplicationType.DATA_PIPELINE: {"min": 1, "max": 3, "desired": 1},
            ApplicationType.ML_SERVICE: {"min": 1, "max": 4, "desired": 1},
            ApplicationType.BATCH_JOB: {"min": 0, "max": 5, "desired": 1}
        }
        
        instances = base_instances.get(app_type, base_instances[ApplicationType.API_SERVICE])
        
        # Adjust based on complexity
        if complexity_score > 0.7:
            instances["desired"] = min(instances["max"], instances["desired"] + 1)
            instances["max"] += 2
        
        # Instance type recommendations
        instance_types = ["t3.micro", "t3.small", "t3.medium"]
        if complexity_score > 0.6:
            instance_types = ["t3.medium", "t3.large", "t3.xlarge"]
        if app_type == ApplicationType.ML_SERVICE:
            instance_types = ["m5.large", "m5.xlarge", "p3.2xlarge"]
        
        return {
            "instances": instances,
            "instance_types": instance_types,
            "storage_gb": infra_requirements["storage"]["size_gb"],
            "cpu_requests": infra_requirements["compute"]["cpu"],
            "memory_requests": infra_requirements["compute"]["memory"],
            "estimated_monthly_cost": infra_requirements["estimated_cost"],
            "auto_scaling_enabled": True,
            "load_balancer_required": infra_requirements["networking"].get("load_balancer", False)
        } 