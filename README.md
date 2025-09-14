# Recur137 - Advanced Smart Contract Security Scanner

## 🚀 Project Overview

**Recur137** is an M.Tech level cybersecurity-focused smart contract security analysis platform that provides comprehensive vulnerability detection, risk assessment, and compliance checking for Solidity smart contracts. This enterprise-grade tool combines multiple security analysis engines with advanced cybersecurity principles and industry-standard compliance frameworks.

## 🎯 Key Features

### 🔒 Advanced Security Analysis
- **Multi-Engine Analysis**: Integration with Slither, Mythril, and custom pattern-based vulnerability detection
- **Comprehensive Vulnerability Detection**: 20+ vulnerability types including reentrancy, access control, timestamp dependency, and more
- **CVSS Scoring**: Common Vulnerability Scoring System (CVSS) integration for standardized risk assessment
- **CWE Mapping**: Common Weakness Enumeration (CWE) identification for industry-standard vulnerability classification

### 📊 Cybersecurity Metrics & Analytics
- **Risk Scoring**: 0-100 risk assessment with severity classification (Low, Medium, High, Critical)
- **Code Quality Analysis**: Cyclomatic complexity, maintainability index, and gas optimization scoring
- **Security Metrics Dashboard**: Real-time analytics and trend analysis
- **Compliance Scoring**: Framework-based compliance assessment

### 🏛️ Compliance Framework Support
- **OWASP Top 10 (2021)**: Web application security standard compliance
- **NIST Cybersecurity Framework 2.0**: Government security standard compliance
- **ISO 27001**: Information security management system compliance
- **Custom Framework Support**: Extensible compliance framework architecture

### 🔍 Advanced Detection Capabilities
- **Pattern-Based Analysis**: Custom regex patterns for vulnerability detection
- **Static Code Analysis**: Comprehensive source code examination
- **Gas Optimization**: Smart contract efficiency analysis
- **Access Control Validation**: Authorization mechanism verification

### 📈 Professional Reporting
- **Executive Summary**: High-level risk assessment and recommendations
- **Technical Details**: Line-by-line vulnerability analysis with code snippets
- **Remediation Guidance**: Actionable security improvement recommendations
- **Compliance Reports**: Framework-specific compliance status
- **Audit Trail**: Complete analysis history and security event logging

## 🛠️ Technical Architecture

### Backend Framework
- **Django 3.2.25**: Robust web framework with security features
- **SQLite Database**: Lightweight, file-based database for development
- **RESTful API**: JSON-based API endpoints for integration
- **Asynchronous Processing**: Multi-threaded analysis for performance

### Security Analysis Engines
- **Slither**: Professional Solidity static analysis tool
- **Mythril**: Symbolic execution-based security analysis
- **Custom Analyzer**: Advanced pattern matching and vulnerability detection
- **Compliance Engine**: Framework-based compliance assessment

### Data Models
- **ScanSession**: Complete scan metadata and results
- **Vulnerability**: Detailed vulnerability information with CWE/CVSS mapping
- **SecurityMetric**: Comprehensive security and quality metrics
- **ComplianceCheck**: Framework compliance validation results
- **AuditTrail**: Complete security event logging

## 🚀 Installation & Setup

### Prerequisites
- Python 3.7+
- Django 3.2+
- Solidity compiler (solc)
- Slither analyzer
- Mythril analyzer

### Installation Steps

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd Recur137
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Security Tools**
   ```bash
   # Install Slither
   pip install slither-analyzer
   
   # Install Mythril
   pip install mythril
   
   # Install Solidity compiler
   pip install py-solc-x
   ```

5. **Database Setup**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create Superuser**
   ```bash
   python manage.py createsuperuser
   ```

7. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

## 📱 Usage Guide

### 1. Upload Smart Contract
- Navigate to the main upload interface
- Drag & drop or select a Solidity (.sol) file
- Choose analysis options (Slither, Mythril, Custom Analysis, Compliance Check)

### 2. Security Analysis
- The system automatically runs multiple analysis engines
- Real-time progress tracking and status updates
- Comprehensive vulnerability detection and classification

### 3. Review Results
- **Risk Assessment**: Overall security risk score and severity level
- **Vulnerability Details**: Line-by-line analysis with code snippets
- **Compliance Status**: Framework-specific compliance validation
- **Security Metrics**: Code quality and optimization scores

### 4. Generate Reports
- Professional PDF reports for stakeholders
- Technical details for development teams
- Compliance reports for auditors
- Executive summaries for management

## 🔐 Security Features

### Vulnerability Detection
- **Reentrancy Attacks**: Detection of external call patterns before state updates
- **Access Control**: Identification of public functions without proper authorization
- **Timestamp Dependency**: Detection of block.timestamp usage for critical decisions
- **Integer Overflow**: Arithmetic operation vulnerability detection
- **Unchecked Calls**: External call return value validation
- **Gas Limit Issues**: Unbounded loop and gas optimization problems

### Risk Assessment
- **CVSS Integration**: Industry-standard vulnerability scoring
- **Severity Classification**: Critical, High, Medium, Low risk levels
- **Confidence Levels**: High, Medium, Low detection confidence
- **Impact Analysis**: Business and technical impact assessment

### Compliance Validation
- **OWASP Top 10**: Web application security standard compliance
- **NIST Framework**: Government cybersecurity standard validation
- **Custom Frameworks**: Extensible compliance framework support
- **Evidence Collection**: Compliance validation evidence and documentation

## 📊 Dashboard & Analytics

### Security Metrics Dashboard
- **Vulnerability Distribution**: Count by severity level
- **Risk Score Trends**: Historical risk assessment tracking
- **Compliance Status**: Framework compliance percentages
- **Code Quality Metrics**: Complexity and maintainability scores

### Scan History & Analytics
- **Complete Scan History**: All analysis sessions with metadata
- **Performance Metrics**: Scan duration and success rates
- **Trend Analysis**: Security improvement over time
- **Export Capabilities**: Data export for external analysis

## 🔧 API Endpoints

### RESTful API
- `POST /upload/`: Contract upload and analysis initiation
- `GET /history/`: Scan history and analytics
- `GET /detail/<session_id>/`: Detailed scan results
- `GET /api/status/<session_id>/`: Real-time scan status

### Integration Capabilities
- **CI/CD Integration**: Automated security scanning in development pipelines
- **Webhook Support**: Real-time notifications for scan completion
- **External Tools**: Integration with development and security tools
- **Custom Workflows**: Extensible analysis and reporting workflows

## 🎓 M.Tech Level Features

### Advanced Cybersecurity Principles
- **Threat Modeling**: Systematic security threat identification
- **Risk Assessment**: Quantitative and qualitative risk analysis
- **Compliance Management**: Industry-standard framework compliance
- **Audit Trail**: Complete security event logging and tracking

### Professional Analysis Capabilities
- **Multi-Engine Analysis**: Comprehensive security tool integration
- **Pattern Recognition**: Advanced vulnerability pattern detection
- **Code Quality Assessment**: Professional code review capabilities
- **Performance Optimization**: Gas efficiency and optimization analysis

### Enterprise Features
- **User Management**: Role-based access control
- **Audit Logging**: Complete system activity tracking
- **Report Generation**: Professional security assessment reports
- **Data Export**: Compliance and audit data export

## 🚀 Future Enhancements

### Planned Features
- **Machine Learning**: AI-powered vulnerability detection
- **Integration APIs**: Third-party security tool integration
- **Advanced Reporting**: Custom report templates and formats
- **Performance Optimization**: Enhanced analysis speed and efficiency

### Research Areas
- **Zero-Day Detection**: Advanced vulnerability discovery techniques
- **Behavioral Analysis**: Smart contract behavior pattern analysis
- **Threat Intelligence**: Real-time threat information integration
- **Compliance Automation**: Automated compliance validation workflows

## 🤝 Contributing

### Development Guidelines
- Follow Django coding standards
- Implement comprehensive testing
- Document all new features
- Maintain security best practices

### Testing
- Unit tests for all models and views
- Integration tests for analysis workflows
- Security testing for vulnerability detection
- Performance testing for large contracts

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support & Contact

- **Project Maintainer**: [Your Name]
- **Email**: [your.email@domain.com]
- **GitHub**: [GitHub Profile]
- **Documentation**: [Documentation Link]

## 🙏 Acknowledgments

- **Slither Team**: Professional Solidity analysis tool
- **Mythril Team**: Symbolic execution security analysis
- **OWASP**: Web application security standards
- **NIST**: Cybersecurity framework standards
- **Django Community**: Web framework and ecosystem

---

**Recur137** - Advancing Smart Contract Security Through Advanced Cybersecurity Analysis

*Built with ❤️ for the blockchain security community*
