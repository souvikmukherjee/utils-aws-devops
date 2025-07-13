# AWS DevOps Utilities & Agentic Infrastructure Management

A comprehensive collection of AWS DevOps utilities featuring an intelligent AI-powered infrastructure management system that autonomously plans, provisions, and manages cloud infrastructure.

## 🚀 Overview

This repository contains advanced AWS DevOps tools and utilities, with the flagship being the **Agentic AI Infrastructure Management System** - an intelligent agent that can analyze your applications, plan optimal AWS infrastructure, and automatically deploy it using Infrastructure as Code.

### Key Features

- 🤖 **AI-Powered Infrastructure Planning** - Analyzes Git repositories and generates optimal AWS infrastructure designs
- 🏗️ **Automated Infrastructure Deployment** - Generates and deploys Terraform code to provision real AWS resources
- ⚡ **Kubernetes Integration** - Creates and manages EKS clusters with complete application deployment manifests
- 🔐 **Security-First Architecture** - Implements AWS Well-Architected Framework principles with automated security scanning
- 📊 **Cost Optimization** - Continuously monitors and optimizes infrastructure costs
- 🔄 **Multi-Environment Support** - Handles dev, staging, and production environments seamlessly

## 📁 Repository Structure

```
utils-aws-devops/
├── README.md                          # This file - main repository overview
├── agentic-infra-manager/             # Main AI infrastructure management system
│   ├── README.md                      # Detailed documentation and setup guide
│   ├── src/                           # Source code for the AI agent
│   │   └── agentic_infra_manager/
│   │       ├── core/                  # Core agent logic and LangGraph workflows
│   │       ├── modules/               # Infrastructure modules (Terraform, K8s, etc.)
│   │       └── utils/                 # Utility functions and helpers
│   ├── tests/                         # Test suites
│   ├── examples/                      # Usage examples
│   └── TERRAFORM_BACKEND_FIX.md      # Recent S3 backend error fix documentation
└── docs/                              # Additional documentation (future)
```

## 🌟 What's Working - Latest Status

### ✅ Fully Functional Components

1. **Repository Analysis** - Analyzes Git repositories to understand application requirements
2. **Infrastructure Planning** - Creates optimal AWS infrastructure plans using AI
3. **Security Configuration** - Generates IAM roles, policies, and security groups
4. **Terraform Code Generation** - Produces complete, modular Terraform code (16+ files)
5. **Kubernetes Manifest Generation** - Creates deployment, service, and ingress configurations
6. **Infrastructure Deployment** - Automatically deploys to AWS using Terraform
7. **Multi-Environment Support** - Handles dev, staging, and production environments

### 🔧 Recent Fixes & Improvements

- **S3 Backend Error Fix** - Resolved terraform deployment failures due to missing S3 buckets
- **Local State Support** - Development environments now use local state by default
- **Improved Error Handling** - Better error messages and recovery mechanisms
- **Enhanced Security** - Strengthened IAM policies and security configurations

## 🚀 Quick Start

### Prerequisites

- AWS Account with administrative access
- OpenAI API Key (for AI-powered planning)
- Terraform installed (`brew install terraform` on macOS)
- Python 3.9+ with pip

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd utils-aws-devops
   ```

2. **Navigate to the main system**:
   ```bash
   cd agentic-infra-manager
   ```

3. **Set up Python environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -e .
   ```

4. **Configure environment variables**:
   ```bash
   export OPENAI_API_KEY="your-openai-api-key"
   export AWS_REGION="us-west-2"  # or your preferred region
   ```

5. **Run your first analysis**:
   ```bash
   python examples/basic_usage.py
   ```

## 📖 Detailed Documentation

For comprehensive documentation including:
- Complete setup instructions
- API reference
- Architecture details
- Usage examples
- Troubleshooting guide

Please refer to the detailed README in the `agentic-infra-manager/` directory:
- [📖 Complete Documentation](agentic-infra-manager/README.md)

## 🎯 Use Cases

### 1. Automated Infrastructure Provisioning
```bash
# Analyze a Spring Boot application and deploy to AWS
python -c "
from agentic_infra_manager.core.agent import quick_analyze
import asyncio

result = asyncio.run(quick_analyze(
    'https://github.com/spring-projects/spring-petclinic',
    target_environment='dev'
))
print(f'Infrastructure provisioned: {result[\"deployment_result\"]}')
"
```

### 2. Multi-Environment Deployment
- **Dev Environment**: Uses local Terraform state, simplified configurations
- **Staging Environment**: Uses S3 backend (optional), enhanced monitoring
- **Production Environment**: Full S3 backend, comprehensive security, auto-scaling

### 3. Application Migration
- Analyze existing applications
- Generate migration plans
- Provision new infrastructure
- Deploy with zero-downtime strategies

## 🔒 Security & Compliance

- **AWS Well-Architected Framework** compliance
- **Least-privilege IAM policies**
- **Automated security scanning**
- **Secrets management integration**
- **Network segmentation and security groups**
- **Encryption at rest and in transit**

## 🛠️ Technology Stack

- **AI/ML**: OpenAI GPT-4, LangGraph for workflow orchestration
- **Infrastructure as Code**: Terraform, AWS CDK
- **Container Orchestration**: Amazon EKS, Kubernetes
- **Languages**: Python 3.9+, HCL (Terraform), YAML
- **AWS Services**: EKS, VPC, RDS, S3, IAM, CloudWatch, and more

## 📊 Success Metrics

Recent test results demonstrate:
- ✅ **100% Workflow Completion** - All agent phases execute successfully
- ✅ **16+ Terraform Files Generated** - Complete modular infrastructure code
- ✅ **5+ Kubernetes Manifests** - Ready-to-deploy application configurations
- ✅ **Real AWS Infrastructure** - Successfully provisions actual AWS resources
- ✅ **Zero S3 Backend Errors** - Resolved terraform deployment issues

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support & Issues

- **Documentation**: [agentic-infra-manager/README.md](agentic-infra-manager/README.md)
- **Recent Fixes**: [TERRAFORM_BACKEND_FIX.md](agentic-infra-manager/TERRAFORM_BACKEND_FIX.md)
- **Issues**: Create an issue in this repository
- **Discussions**: Use the repository discussions for questions and ideas

## 🎉 Getting Started

Ready to transform your infrastructure management? Start with the detailed setup guide in the `agentic-infra-manager/` directory and experience the power of AI-driven infrastructure automation!

---

*Built with ❤️ for the AWS DevOps community*