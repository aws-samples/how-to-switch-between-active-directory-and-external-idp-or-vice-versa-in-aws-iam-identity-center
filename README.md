# How to switch between Active Directory and External IdP (or vice versa) in AWS IAM Identity Center with automation

This repository contains a python script used to interact with AWS Identity Center. Script goal is to document current principals in the Identity Store, Document existing permission set > AWS Account > principal assignments, and automate issuing assignment requests for permission set to AWS Account + principal.

## Requirements

* AWS CLI - Installed and Configured with a valid profile [Install the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
* [Python 3 installed](https://www.python.org/downloads/)

## Setup

```bash
git clone https://github.com/aws-samples/how-to-switch-between-active-directory-and-external-idp-or-vice-versa-in-aws-iam-identity-center.git
cd how-to-switch-between-active-directory-and-external-idp-or-vice-versa-in-aws-iam-identity-center
```

## Usage

Running python main.py -h displays all the different options available in the script. Note that it requires Python3.11 and later.

```bash
usage: main.py [-h] [-v] [-l] [-p] [-s] [-c] [-o OUTPUT] [-i INPUT] [-d DEBUG] [--profile PROFILE]

options:
-h, --help            show this help message and exit
-v, --verbose         Verbose output
-l, --list            Returns all permission set to account assignment information.
-p, --principals      Returns all user and group principals found in AWS IAM Identity Center.
-s, --set             Assign permission sets to AWS accounts and groups/users. Use -c to stay in a loop checking request results instead of exiting immediately.
-c, --check           Requires -s to work. Loops checking the assignment request status every few seconds.
-o OUTPUT, --output OUTPUT
Output file for -l --list, -p --principals.
-i INPUT, --input INPUT
Input file for -s --set.
-d DEBUG, --debug DEBUG
Debug log file, always utilize the highest verbosity possible for the log messages.
--profile PROFILE     AWS Session profile name (when using named profiles instead of default).
```

## License

This solution is licensed under the MIT-0 License. See the LICENSE file.
