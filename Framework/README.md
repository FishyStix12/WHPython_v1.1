# Trojan Framework <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/239280f9-d78f-4e2d-aace-6fb0b4e59177) <br />

**Important Note: For this Trojan to work install the appropriate libraries using the commands below, or head to pypi.org/project/github3.py' to automate the process:** <br />
  pip install github3.py <br />
  pip install base64 <br />
  pip install importlib <br />
  pip install json <br />
  pip install random <br />
  pip install sys <br />
  pip install threading <br />
  pip install time <br />
  pip install datetime <br />

**Please Note: Any of these python scripts can be used as the Trojan's Modules.** <br />

**Important Note to use github_trojan.py, Please get the necassary token input by doing the following settings:** <br />
1. Click on user Profile on left hand side. <br />
2. Click on developer settings. <br />
3. Click on Personal Access Tokens. <br />
4. Click on the classic Token. <br />
5. Click Generate New Token. <br />
6. Click on the Generate Classic New Token Option. <br />
7. Finish Generating Token with appropriate settings. <br />
8. Finally, copy the token, and paste it into a text file. <br />

**Important Note: To create the basic structure for this repo enter the following on the Linux Command Line or use the provided configuration Bash file:** <br />
  $ mkdir \<trojan_name\> <br />
  $ cd \<trojan_name\> <br />
  $ git init <br />
  $ mkdir modules <br />
  $ mkdir config <br />
  $ mkdir data <br />
  $ touch .gitignore <br />
  $ git add . <br />
  $ git commit -m "Adds repo structure for trojan" <br />
  $ git remote add origin https://github.com/<yourusername\>/<torjan_github_repository\>.git <br />
  $ git push origin master <br />

**The Following List gives a short description of all the scripts in this group:** <br />
**1. Set up/ 2. Update/ 3. Pull Data: (Run scripts 2 and 3 in the home directory of your Trojan!)** <br />
1. trojan_linux_framewrk_conf.sh - This script is used to create the initial structure for the repo. The config directory holds unique configuration files for each trojan, so each Trojan can contain a seperate configuration file. The modules directory contains any modular code that the trojan should pick up and then execute. The data directory is where the trojan will check any collected data. <br />
2. push_trojan_updates.sh - This script automates the process to push new features into the active Trojan on Github. To ensure this script works please place it in the <trojan_name> directory. You will need your Github username and password to push the Trojan update. <br />
3. data_pull.sh - This script pulls the results of the running Trojan Modules. <br />

**Configuration:** <br />
1. modul3s.json - is just a simple list of modules that the remote trojan should run. <br />
2. github_trojan.py - This script  implements a Trojan horse program that can be used for remote execution of tasks on a target machine. It uses GitHub as a repository for storing configuration files and modules. The program continuously checks for updates in the repository, retrieves new modules or configurations, and executes them. This allows for dynamic and remote control of the Trojan's behavior. To use the code, you would need to set up a GitHub repository with the necessary configuration files and modules. You would also need to generate a personal access token for GitHub API access. An example of using the code would be to create a repository with a configuration file specifying which modules to run and their parameters. The Trojan would then fetch this configuration, run the specified modules, and store the results back in the repository.  !!Belongs in the config module of the Trojan Framework!! <br />

**Example Layout of the JSON script below: (1 underscore + space = 1 tab)**
[ <br />
_ { <br />
_ _ "module" : "script1" <br />
_ }, <br />
_ { <br />
_ _ "module" : "script2" <br />
_ } <br />
] <br />
Important Note: Please run the push_trojan_updates.sh file in the config module to push changes into the active trojan! <br />
