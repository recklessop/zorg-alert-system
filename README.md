# zorg-alert-system

The Zorg Alert System is for use with the Zerto Cloud Manager. This repository contains the code used to build the Docker image. Deployment should be via Docker or Docker Compose.

## Legal Disclaimer

This script is an example script and is not supported under any Zerto support program or service. The author and Zerto further disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.

In no event shall Zerto, its authors or anyone else involved in the creation, production or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or the inability to use the sample scripts or documentation, even if the author or Zerto has been advised of the possibility of such damages. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.

## Disclaimer

This code is still under development! Please use carefully and if you encounter any issues or have an idea, please submit an [issue](https://github.com/recklessop/zorg-alert-system/issues). Along the same lines, should you be proficient in Python, please feel free to submit any [Pull Requests](https://github.com/recklessop/zorg-alert-system/pulls) with enhancements and bug fixes.

## Express Setup

Download the docker-compose.yml file  to a directory on your docker host, then execute:

```python
docker-compose up -d
```

The application will be available at http://"Your Docker Host IP":8088

## Recent Updates

All recent updates can now be tracked via the [Change Log](https://github.com/ZertoPublic/recklessop/zorg-alert-system/CHANGELOG.md).

## TODO

* Build Tests
* Complete Automated Build Process
