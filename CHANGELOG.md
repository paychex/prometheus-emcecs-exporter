# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2018-05-17
Initial release - [Mark DeNeve](https://github.com/xphyr)

## [1.1.0] - 2018-09-24
Changes to authentication system to cut down on login/logouts that occur - [Mark DeNeve](https://github.com/xphyr)

## [1.2.0] - 2019-07-13
Updates to project layout, and enhancement to http client usage to cut down on memory usage.
Also changed to use go modules by default and have removed all vendored dependencies
Node info is now gathered over port 9021 to enable SSL. If your ECS arrays are behind a firewall be sure to update your rules to allow port 9021 instead of 9020
Loging has been updated to only use Logrus and time format has been updated to be human readable.
[Mark DeNeve](https://github.com/xphyr)
