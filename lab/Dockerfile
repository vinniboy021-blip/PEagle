FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

WORKDIR /lab

# Ferramentas auxiliares para os testes
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl jq net-tools procps 2>/dev/null && rm -rf /var/lib/apt/lists/*

# Contexto de build e a raiz /root/winpeas (definido no docker-compose)
COPY lab/mocks/       /lab/mocks/
COPY lab/tests/       /lab/tests/
COPY lab/run_tests.sh /lab/run_tests.sh
COPY PEagle.ps1 /lab/PEagle.ps1

RUN chmod +x /lab/run_tests.sh

ENTRYPOINT ["/lab/run_tests.sh"]
