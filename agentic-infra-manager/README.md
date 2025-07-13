# Agentic AI Infrastructure Management System

An intelligent agent that autonomously plans, provisions, and manages AWS infrastructure with specialized focus on Kubernetes cluster deployment and application lifecycle management.

## 🚀 Overview

This system operates as an intelligent infrastructure companion that:
- Analyzes application requirements from Git repositories
- Plans optimal AWS infrastructure using Well-Architected Framework principles
- Generates Infrastructure as Code (Terraform/CDK)
- Provisions and manages Kubernetes clusters
- Deploys applications with proper monitoring and security
- Continuously optimizes performance and costs

## 🔧 Core Capabilities

### Infrastructure Planning & Architecture
- ✅ AWS Well-Architected Framework compliance
- ✅ High availability multi-AZ deployments
- ✅ EKS cluster management with security configurations
- ✅ VPC design with proper network segmentation

### LangGraph Integration
- ✅ Topology visualization and planning workflows
- ✅ Decision-making process modeling
- ✅ Impact analysis for infrastructure changes
- ✅ Automated compliance checking

### Security & IAM Management
- ✅ Root credential usage only for initial setup
- ✅ Role-based access control with least-privilege
- ✅ Automated security scanning and compliance
- ✅ Secrets management integration

### Application Deployment Intelligence
- ✅ Git repository analysis and dependency mapping
- ✅ Infrastructure requirements assessment
- ✅ Deployment strategy planning (blue/green, canary, rolling)
- ✅ Auto-scaling and resource optimization

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Agentic AI Infrastructure Manager         │
├─────────────────────────────────────────────────────────────┤
│  Core Agent (LangGraph)                                     │
│  ├── Repository Analyzer                                    │
│  ├── Infrastructure Planner                                 │
│  ├── Security Manager                                       │
│  ├── Deployment Orchestrator                                │
│  └── Optimization Engine                                    │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure Layer                                       │
│  ├── AWS SDK Integration                                    │
│  ├── Terraform/CDK Generator                                │
│  ├── Kubernetes Manager                                     │
│  └── Monitoring & Observability                             │
├─────────────────────────────────────────────────────────────┤
│  Security Layer                                             │
│  ├── IAM Role Management                                    │
│  ├── Policy Generation                                      │
│  ├── Compliance Scanning                                    │
│  └── Secrets Management                                     │
└─────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

Before you begin, ensure you have:
- **MacBook** with macOS 10.15+ (Catalina or later)
- **Terminal** access (built-in Terminal app)
- **Internet connection** for downloading dependencies
- **AWS Account** with administrative access
- **OpenAI API Key** (for AI-powered planning)

## 🛠️ Complete Setup Guide for New Users

### Step 1: Install System Dependencies

#### Install Homebrew (Package Manager)
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add Homebrew to your PATH
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zshrc
source ~/.zshrc
```

#### Install Python 3.11+
```bash
# Install Python using Homebrew
brew install python@3.11

# Verify installation
python3 --version
# Should show Python 3.11.x or higher
```

#### Install Git (if not already installed)
```bash
# Install Git
brew install git

# Verify installation
git --version
```

#### Install AWS CLI
```bash
# Install AWS CLI
brew install awscli

# Verify installation
aws --version
```

### Step 2: AWS Account Setup

#### Create AWS Account
1. Go to [AWS Console](https://aws.amazon.com/)
2. Click "Create an AWS Account"
3. Follow the registration process
4. **Important**: You'll need a credit card for verification

#### Create IAM User for the Agent
```bash
# Login to AWS Console
# Navigate to IAM > Users > Create User
# User name: agentic-infra-manager
# Attach policies: AdministratorAccess (for initial setup)
# Create access keys and download CSV file
```

#### Configure AWS CLI
```bash
# Configure AWS credentials
aws configure

# When prompted, enter:
# AWS Access Key ID: [Your access key from CSV]
# AWS Secret Access Key: [Your secret key from CSV]
# Default region name: us-west-2
# Default output format: json

# Test your configuration
aws sts get-caller-identity
```

### Step 3: Get OpenAI API Key

#### Sign up for OpenAI
1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Sign up for an account
3. Navigate to API Keys section
4. Create new API key
5. **Important**: Save this key securely - you won't see it again

### Step 4: Download and Install the Agent

#### Clone the Repository
```bash
# Navigate to your desired directory
cd ~/Documents

# Clone the repository
git clone https://github.com/your-org/agentic-infra-manager.git
cd agentic-infra-manager
```

#### Create Python Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# You should see (venv) in your terminal prompt
```

#### Install the Agent
```bash
# Install dependencies and the agent
make install

# Install additional dependencies for full repository analysis
pip install GitPython PyGithub docker

# Verify installation
infra-agent --help
```

### Step 5: Configure Environment Variables

#### Create Environment File
```bash
# Create .env file with your credentials
cat > .env << 'EOF'
# AWS Configuration
AWS_REGION=us-west-2
AWS_PROFILE=default

# OpenAI API Key (REQUIRED)
OPENAI_API_KEY=your_openai_api_key_here

# GitHub Token (Optional - for private repositories)
# GITHUB_TOKEN=your_github_token_here

# Agent Configuration
AGENT_LOG_LEVEL=INFO
AGENT_WORKSPACE=/tmp/agent-workspace

# Optional: LangSmith for debugging
# LANGCHAIN_TRACING_V2=true
# LANGCHAIN_API_KEY=your_langsmith_api_key_here
# LANGCHAIN_PROJECT=agentic-infra-manager
EOF
```

#### Update Environment Variables
```bash
# Edit the .env file with your actual keys
nano .env

# Replace 'your_openai_api_key_here' with your actual OpenAI API key
# Save and exit (Ctrl+X, then Y, then Enter)

# Load environment variables
source .env
```

### Step 6: Initialize the Agent

#### Interactive Setup
```bash
# Initialize with interactive configuration
infra-agent init --interactive

# Follow the prompts:
# - Agent name: Infrastructure AI Agent
# - Workspace directory: /tmp/agent-workspace
# - AWS region: us-west-2
# - OpenAI API key: [will be loaded from environment]
```

#### Verify Setup
```bash
# Check configuration
infra-agent config

# Check version
infra-agent version
```

## 🚀 Usage Examples

### Primary Workflow: Complete Infrastructure Analysis

The `analyze` command performs the **complete infrastructure workflow** in a single command:

1. **Repository Analysis** - Clones and analyzes the codebase
2. **Infrastructure Planning** - Generates optimal AWS infrastructure plans
3. **Security Assessment** - Creates security configurations and compliance checks
4. **Resource Optimization** - Optimizes resource allocation and costs
5. **Code Generation** - Generates Terraform and Kubernetes manifests
6. **Deployment Planning** - Creates complete deployment plans with timelines

#### Basic Analysis (Complete Workflow)
```bash
# Activate virtual environment (if not already active)
source venv/bin/activate

# Load environment variables
source .env

# Analyze a public repository - DOES EVERYTHING!
infra-agent analyze https://github.com/spring-projects/spring-petclinic

# Analyze for production environment with high availability
infra-agent analyze https://github.com/spring-projects/spring-petclinic --target-env prod

# Save complete analysis and infrastructure plan
infra-agent analyze https://github.com/spring-projects/spring-petclinic --output complete-plan.json
```

#### What You Get From Analysis
The analysis command provides:
- ✅ **Complete Infrastructure Plan** with unique plan-id
- ✅ **Security Configurations** (IAM roles, policies, security groups)
- ✅ **Generated Terraform Code** for AWS infrastructure
- ✅ **Kubernetes Manifests** for application deployment
- ✅ **Cost Estimates** for monthly infrastructure costs
- ✅ **Deployment Timeline** and resource dependencies
- ✅ **VPC Configuration** with proper network segmentation
- ✅ **EKS Cluster Setup** with optimized node groups

#### Advanced Analysis Options
```bash
# Analyze with verbose logging for debugging
infra-agent --verbose analyze https://github.com/spring-projects/spring-petclinic

# Analyze with custom AWS region
infra-agent analyze https://github.com/spring-projects/spring-petclinic --region eu-west-1

# Dry-run analysis (simulation only)
infra-agent analyze https://github.com/spring-projects/spring-petclinic --dry-run
```

### Additional Commands

#### Check System Status
```bash
# Check agent configuration
infra-agent config

# Check version
infra-agent version

# Get help for any command
infra-agent --help
infra-agent analyze --help
```

#### Initialize Configuration
```bash
# Set up initial configuration
infra-agent init

# Interactive configuration setup
infra-agent init --interactive
```

### Real-World Usage Examples

#### Different Target Environments
```bash
# Development environment - smaller resources, single AZ
infra-agent analyze https://github.com/your-org/your-app --target-env dev --output dev-plan.json

# Staging environment - medium resources, testing configurations  
infra-agent analyze https://github.com/your-org/your-app --target-env staging --output staging-plan.json

# Production environment - high availability, auto-scaling, multi-AZ
infra-agent analyze https://github.com/your-org/your-app --target-env prod --output prod-plan.json
```

#### Different Application Types
```bash
# Analyze a Python/FastAPI microservice
infra-agent analyze https://github.com/tiangolo/fastapi --target-env prod

# Analyze a React frontend application
infra-agent analyze https://github.com/facebook/create-react-app --target-env prod

# Analyze a Spring Boot Java application
infra-agent analyze https://github.com/spring-projects/spring-boot --target-env prod

# Analyze a Node.js/Express API
infra-agent analyze https://github.com/expressjs/express --target-env prod
```

#### Custom Configurations
```bash
# Use different AWS region
infra-agent analyze https://github.com/your-org/your-app --region eu-west-1 --target-env prod

# Enable verbose logging for debugging
infra-agent --verbose analyze https://github.com/your-org/your-app --target-env dev

# Combine options for comprehensive analysis
infra-agent --verbose analyze https://github.com/your-org/your-app --target-env prod --region us-east-1 --output detailed-plan.json
```

### Complete Step-by-Step Workflow

#### Example: Deploying Spring PetClinic to AWS

```bash
# 1. Navigate to project directory and activate environment
cd ~/Documents/agentic-infra-manager
source venv/bin/activate
source .env

# 2. Run complete infrastructure analysis (this does everything!)
infra-agent analyze https://github.com/spring-projects/spring-petclinic --target-env prod --output petclinic-production.json

# 3. Review the complete infrastructure plan
echo "📋 Infrastructure Plan Generated:"
cat petclinic-production.json | grep -A 5 "plan_id"

echo "💰 Cost Estimate:"
cat petclinic-production.json | grep -A 3 "estimated_monthly_cost"

echo "🏗️ VPC Configuration:" 
cat petclinic-production.json | grep -A 10 "vpc_configuration"

echo "⚙️ EKS Configuration:"
cat petclinic-production.json | grep -A 10 "eks_configuration"

# 4. Extract deployment details
echo "🚀 Deployment Details:"
cat petclinic-production.json | grep -A 5 "deployment_result"

# 5. The infrastructure plan is now ready for deployment!
echo "✅ Complete infrastructure plan generated and ready for AWS deployment"
echo "📁 All Terraform code and Kubernetes manifests are included in the plan"
echo "🔒 Security configurations and IAM roles are configured"
echo "📊 Monitoring and alerting are set up"
```

#### What You Have After Analysis
After running the analysis command, you get a **complete, production-ready infrastructure package**:

1. **📋 Infrastructure Plan** (`plan_id`) - Ready for deployment
2. **🏗️ AWS Resources** - VPC, EKS, Security Groups, IAM Roles
3. **🔧 Terraform Code** - Infrastructure as Code for AWS
4. **☸️ Kubernetes Manifests** - Application deployment configs
5. **🔒 Security Setup** - IAM policies, security groups, encryption
6. **📊 Monitoring** - CloudWatch, Prometheus, Grafana configurations
7. **💰 Cost Analysis** - Detailed monthly cost breakdown
8. **📈 Scaling Plan** - Auto-scaling and resource optimization

## 📁 Generated Files and Artifacts

The system generates several important files:

### Configuration Files
- `config/agent.yaml` - Agent configuration
- `.env` - Environment variables

### Analysis Results
- `analysis.json` - Repository analysis results
- `config/plans/` - Infrastructure plans directory

### Generated Code
- `generated/terraform/` - Terraform infrastructure code
- `generated/kubernetes/` - Kubernetes manifests
- `generated/helm/` - Helm charts

### Documentation
- `generated/diagrams/` - Architecture diagrams (PNG/SVG)
- `generated/docs/` - Auto-generated documentation
- `generated/reports/` - Cost analysis and security reports

### Logs
- `/tmp/agent-workspace/logs/` - Agent logs
- `/tmp/agent-workspace/plans/` - Deployment plans
- `/tmp/agent-workspace/state/` - Agent state files

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Missing Dependencies Error
If you see warnings like "No module named 'git'" or "No module named 'github'", install the missing dependencies:

```bash
# Install all required dependencies for full functionality
pip install GitPython PyGithub docker

# If you get more specific errors, install individually:
pip install GitPython  # For Git repository operations
pip install PyGithub   # For GitHub API integration  
pip install docker     # For Docker analysis
```

#### AWS Credentials Not Found
```bash
# Check if AWS is configured
aws sts get-caller-identity

# If error, configure AWS credentials
aws configure

# Test with a simple AWS command
aws ec2 describe-regions --region us-west-2
```

#### OpenAI API Key Issues
```bash
# Check if environment variable is set and has correct length
echo "OPENAI_API_KEY length: $(echo $OPENAI_API_KEY | wc -c)"
# Should show a number > 50

# If empty or incorrect, update .env file
nano .env
# Add: OPENAI_API_KEY=your_actual_key_here

# Reload environment variables
source .env
```

#### "No current state found" Error
This error occurs when trying to use commands that expect a previous analysis:

```bash
# ❌ Wrong: Running deploy without analysis
infra-agent deploy --plan-id some-plan-id

# ✅ Correct: Always run analysis first (which includes everything)
infra-agent analyze https://github.com/your-org/your-app --target-env prod --output plan.json
```

**Note**: The `analyze` command performs the complete workflow, so you don't need separate deploy commands.

#### Virtual Environment Issues
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# You should see (venv) in your prompt

# If activation fails, recreate the virtual environment
python3 -m venv venv
source venv/bin/activate

# Reinstall everything
make install
pip install GitPython PyGithub docker
```

#### Analysis Taking Too Long
The analysis includes AI processing and repository cloning, which can take time:

```bash
# Use verbose mode to see progress
infra-agent --verbose analyze https://github.com/your-repo --target-env dev

# For faster testing, use a smaller repository
infra-agent analyze https://github.com/spring-projects/spring-petclinic --target-env dev
```

### Debugging Commands

```bash
# Run with verbose logging
infra-agent --verbose analyze https://github.com/your-repo

# Check agent logs
tail -f /tmp/agent-workspace/logs/agent.log

# Validate configuration
infra-agent config

# Test AWS connectivity
aws ec2 describe-regions --region us-west-2
```

### Getting Help

```bash
# General help
infra-agent --help

# Command-specific help
infra-agent analyze --help
infra-agent deploy --help
infra-agent monitor --help
infra-agent optimize --help
```

## 💡 Tips for Success

### Before You Start
1. **Test AWS Access**: Run `aws sts get-caller-identity` to verify credentials
2. **Check OpenAI Credits**: Ensure you have sufficient OpenAI API credits
3. **Understand Costs**: Review AWS pricing for services you'll use
4. **Start Small**: Begin with development environment and simple applications

### Best Practices
1. **Use Version Control**: Commit generated Terraform code to Git
2. **Review Plans**: Always review infrastructure plans before deployment
3. **Monitor Costs**: Set up AWS billing alerts
4. **Security First**: Review security configurations before production use
5. **Backup State**: Keep Terraform state files backed up

### Resource Management
```bash
# Clean up resources when done
infra-agent cleanup --cluster your-cluster-name

# Or manually through AWS Console
# Navigate to CloudFormation and delete stacks
```

## 🧪 Testing Your Setup

### Quick System Test
```bash
# Test the installation
infra-agent version

# Test AWS connectivity
aws sts get-caller-identity

# Test OpenAI API key length
echo "OPENAI_API_KEY length: $(echo $OPENAI_API_KEY | wc -c)"
# Should show a number > 50

# Test all dependencies
python -c "import git, github, docker; print('✅ All dependencies installed')"
```

### Full Functionality Test
```bash
# Test complete workflow with a real repository
infra-agent analyze https://github.com/spring-projects/spring-petclinic --target-env dev --output test-results.json

# Verify the analysis results
echo "📋 Analysis Results:"
cat test-results.json | grep -E "(plan_id|progress_percentage|estimated_monthly_cost)" | head -5

# Check for any errors
cat test-results.json | grep -A 3 '"errors"'
```

### Expected Output
When the analysis runs successfully, you should see:
- ✅ **Progress spinner** showing "Analyzing repository..."
- ✅ **Repository Information table** with Name, Language, Framework, etc.
- ✅ **Infrastructure Requirements panel** with CPU, Memory, Storage estimates
- ✅ **Progress: 100.0% complete**
- ✅ **Plan ID generated** (e.g., "plan-abc123")
- ✅ **Results saved** message

If you see warnings about missing modules (git, github, docker), install them as described in the Troubleshooting section.

### Test with Your Own Repository
```bash
# Test with your own public repository
infra-agent analyze https://github.com/your-username/your-repo --target-env dev --output my-test.json

# Test with different environments
infra-agent analyze https://github.com/your-username/your-repo --target-env prod --output prod-test.json
```

## 📊 LangGraph Workflow

The agent uses LangGraph to model complex decision-making processes:

```python
workflow = StateGraph(AgentState)
workflow.add_node("analyze_repo", analyze_repository_node)
workflow.add_node("assess_requirements", assess_infrastructure_requirements)
workflow.add_node("plan_security", plan_security_configuration)
workflow.add_node("generate_topology", generate_infrastructure_topology)
workflow.add_node("optimize_resources", optimize_resource_allocation)
workflow.add_node("deploy_infrastructure", deploy_infrastructure_node)

# Add conditional edges for decision making
workflow.add_conditional_edges(
    "analyze_repo",
    route_based_on_app_type,
    {
        "web_app": "assess_requirements",
        "microservice": "assess_requirements",
        "data_pipeline": "assess_requirements"
    }
)
```

## 🔒 Security Model

### Phase 1: Initial Setup (Root Credentials)
- Create foundational IAM roles and policies
- Establish cross-account access patterns
- Set up logging and monitoring foundations

### Phase 2: Operations (Assumed Roles)
- All infrastructure operations use assumed roles
- Least-privilege access patterns
- Automated security scanning

### Phase 3: Continuous Compliance
- Regular security assessments
- Policy drift detection
- Automated remediation

## 📈 Monitoring & Optimization

The agent continuously monitors:
- Resource utilization and costs
- Security compliance status
- Application performance metrics
- Infrastructure drift detection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 🎯 Key Points to Remember

### How the System Actually Works
1. **Single Command Does Everything**: The `analyze` command performs the complete infrastructure workflow
2. **No Separate Deployment**: You don't need to run separate `deploy` commands - analysis includes deployment planning
3. **Complete Results**: Each analysis provides a full infrastructure plan ready for AWS deployment
4. **JSON Output Contains Everything**: The output file has all Terraform code, Kubernetes manifests, and configurations

### What You Get From One `analyze` Command
- ✅ Repository analysis (language, framework, dependencies)
- ✅ Infrastructure planning (VPC, EKS, security groups)
- ✅ Security assessment (IAM roles, policies, compliance)
- ✅ Resource optimization (CPU, memory, storage sizing)
- ✅ Code generation (Terraform + Kubernetes manifests)
- ✅ Cost estimation (monthly AWS costs)
- ✅ Deployment plan (timeline and dependencies)

### Best Practices
1. **Always start with analysis**: `infra-agent analyze <repo-url> --target-env <env>`
2. **Save results to file**: Use `--output results.json` to capture everything
3. **Test with dev first**: Start with `--target-env dev` before trying production
4. **Use verbose logging**: Add `--verbose` when debugging issues
5. **Review the JSON output**: It contains your complete infrastructure plan

### Common Workflow
```bash
# 1. Analyze repository and generate complete infrastructure plan
infra-agent analyze https://github.com/your-org/your-app --target-env prod --output infrastructure-plan.json

# 2. Review the generated plan
cat infrastructure-plan.json | grep -E "(plan_id|estimated_monthly_cost|vpc_configuration)"

# 3. Extract Terraform code and Kubernetes manifests from the plan
# 4. Deploy to AWS using the generated code
```

That's it! Your infrastructure is planned, generated, and ready for deployment. 🚀

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details. 