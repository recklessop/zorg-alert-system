# zorg-alert-system

The Zorg Alert System is for use with the Zerto Cloud Manager. This repository contains the code used to build the Docker image. Deployment should be via Docker or Docker Compose.

## Express Setup

Download the docker-compose.yml file  to a directory on your docker host, then execute:

```python
docker-compose up -d
```

The application will be available at http://"<Your Docker Host IP>":8088
