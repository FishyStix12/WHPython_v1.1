#!/bin/bash

# Function to display error messages and exit
function display_error {
    echo "Error: $1"
    exit 1
}

# Check if git is installed
which git >/dev/null 2>&1 || display_error "Git is not installed. Please install Git and run the script again."

# Check if Python 3 and pip are installed
which python3 >/dev/null 2>&1 || display_error "Python 3 is not installed. Please install Python 3 and run the script again."
which pip3 >/dev/null 2>&1 || display_error "pip is not installed. Please install pip and run the script again."

# Check if Volatility is already installed
if [ -d "volatility" ]; then
    echo "Volatility already installed."
    exit 0
fi

# Install necessary dependencies
echo "Installing necessary dependencies..."
sudo apt-get update >/dev/null 2>&1
sudo apt-get install -y build-essential libssl-dev libffi-dev python3-dev python3-pip >/dev/null 2>&1 || display_error "Failed to install dependencies."

# Clone Volatility repository
echo "Cloning Volatility repository..."
git clone https://github.com/volatilityfoundation/volatility.git >/dev/null 2>&1 || display_error "Failed to clone Volatility repository."

# Navigate to Volatility directory
cd volatility || display_error "Volatility directory not found."

# Install Volatility requirements
echo "Installing Volatility requirements..."
pip3 install -r requirements.txt >/dev/null 2>&1 || display_error "Failed to install Volatility requirements."

# Display completion message
echo "Volatility configuration complete. You can now use the Volatility framework."
