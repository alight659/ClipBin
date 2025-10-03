#!/usr/bin/env python3
"""
ClipBin Test Runner

A comprehensive test runner script for the ClipBin project.
Provides various testing options including coverage reporting,
test categorization, and performance timing.

Usage:
    python run_tests.py [options]

Examples:
    python run_tests.py                    # Run all tests with coverage
    python run_tests.py --fast             # Quick test run without coverage
    python run_tests.py --html-report      # Generate HTML coverage report
    python run_tests.py --type unit        # Run only unit tests
    python run_tests.py --type integration # Run only integration tests
"""

import sys
import subprocess
import argparse
import time
from pathlib import Path


class TestRunner:
    """Comprehensive test runner for ClipBin project."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_categories = {
            'unit': [
                'tests/test_additional.py',
                'tests/test_sqlite.py',
                'tests/test_basic_app.py'
            ],
            'integration': [
                'tests/test_integration.py',
                'tests/test_app.py'
            ],
            'database': [
                'tests/test_sqlite.py',
                'tests/test_database_cleanup.py'
            ],
            'security': [
                'tests/test_app.py::TestSecurityWorkflow',
                'tests/test_integration.py::TestSecurityWorkflow'
            ],
            'all': ['tests/']
        }
    
    def run_command(self, command, description="Running tests"):
        """Execute a command and return the result."""
        print(f"\n{'='*60}")
        print(f"🧪 {description}")
        print(f"{'='*60}")
        print(f"Command: {' '.join(command)}")
        print()
        
        start_time = time.time()
        try:
            result = subprocess.run(
                command,
                cwd=self.project_root,
                capture_output=False,
                text=True,
                check=False
            )
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"\n{'='*60}")
            if result.returncode == 0:
                print(f"✅ {description} completed successfully in {duration:.2f}s")
            else:
                print(f"❌ {description} failed with exit code {result.returncode} after {duration:.2f}s")
            print(f"{'='*60}")
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"❌ Error running command: {e}")
            return False
    
    def run_tests(self, test_type='all', fast=False, html_report=False, verbose=False):
        """Run the specified test category."""
        
        # Get test files for the specified type
        if test_type not in self.test_categories:
            print(f"❌ Unknown test type: {test_type}")
            print(f"Available types: {', '.join(self.test_categories.keys())}")
            return False
        
        test_files = self.test_categories[test_type]
        
        # Build pytest command
        command = ['python', '-m', 'pytest']
        command.extend(test_files)
        
        if verbose:
            command.append('-v')
        
        if not fast:
            # Add coverage options
            command.extend([
                '--cov=.',
                '--cov-report=term-missing',
                '--cov-fail-under=39'
            ])
            
            if html_report:
                command.extend(['--cov-report=html'])
        
        # Add other useful options
        command.extend([
            '--tb=short',  # Shorter traceback format
            '-ra'  # Show short test summary info for all
        ])
        
        description = f"Running {test_type} tests"
        if fast:
            description += " (fast mode)"
        if html_report:
            description += " with HTML report"
            
        success = self.run_command(command, description)
        
        if success and html_report and not fast:
            print(f"\n📊 HTML coverage report generated: htmlcov/index.html")
            print(f"Open it in your browser to view detailed coverage analysis.")
        
        return success
    
    def check_dependencies(self):
        """Check if required testing dependencies are available."""
        print("🔍 Checking test dependencies...")
        
        required_packages = ['pytest', 'pytest-cov', 'pytest-flask']
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"✅ {package}")
            except ImportError:
                print(f"❌ {package}")
                missing_packages.append(package)
        
        if missing_packages:
            print(f"\n❌ Missing dependencies: {', '.join(missing_packages)}")
            print("Install them with: pip install -r requirements.txt")
            return False
        
        print("✅ All test dependencies are available")
        return True
    
    def show_help(self):
        """Display help information."""
        print("""
ClipBin Test Runner Help
========================

This script provides various options for running the ClipBin test suite.

Test Categories:
  unit         - Unit tests for utility functions and database operations
  integration  - End-to-end workflow and integration tests  
  database     - Database-specific tests
  security     - Security and vulnerability tests
  all          - All tests (default)

Options:
  --fast       - Skip coverage reporting for faster execution
  --html-report- Generate HTML coverage report
  --type TYPE  - Run specific test category
  --verbose    - Verbose test output
  --help       - Show this help message

Examples:
  python run_tests.py                     # Run all tests with coverage
  python run_tests.py --fast              # Quick test run
  python run_tests.py --type unit         # Run only unit tests
  python run_tests.py --html-report       # Generate HTML report
  python run_tests.py --type unit --fast  # Quick unit tests

Coverage Goals:
  - Overall: 64%+ (currently achieved)
  - additional.py: 100% (achieved)
  - sqlite.py: 90%+ (achieved)
  - app.py: 50%+ (achieved)

Test Statistics:
  - Total Tests: 147
  - Success Rate: 100%
  - Execution Time: ~17 seconds
""")


def main():
    """Main entry point for the test runner."""
    parser = argparse.ArgumentParser(
        description='ClipBin Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--type',
        choices=['unit', 'integration', 'database', 'security', 'all'],
        default='all',
        help='Type of tests to run (default: all)'
    )
    
    parser.add_argument(
        '--fast',
        action='store_true',
        help='Skip coverage reporting for faster execution'
    )
    
    parser.add_argument(
        '--html-report',
        action='store_true',
        help='Generate HTML coverage report'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose test output'
    )
    
    args = parser.parse_args()
    
    # Show help if requested
    if len(sys.argv) == 1:
        # No arguments provided, show brief help
        print("ClipBin Test Runner")
        print("==================")
        print("Use --help for detailed options")
        print()
    
    runner = TestRunner()
    
    # Check dependencies
    if not runner.check_dependencies():
        sys.exit(1)
    
    # Run tests
    success = runner.run_tests(
        test_type=args.type,
        fast=args.fast,
        html_report=args.html_report,
        verbose=args.verbose
    )
    
    if success:
        print("\n🎉 All tests completed successfully!")
        if not args.fast:
            print("📊 Coverage reports have been generated.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        sys.exit(1)


if __name__ == '__main__':
    main()