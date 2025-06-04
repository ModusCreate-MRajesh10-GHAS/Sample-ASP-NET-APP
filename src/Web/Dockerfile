# RUN ALL CONTAINERS FROM ROOT (folder with .sln file):
# docker-compose build
# docker-compose up
#
# RUN JUST THIS CONTAINER FROM ROOT (folder with .sln file):
# docker build --pull -t web -f src/Web/Dockerfile .
#
# RUN COMMAND
#  docker run --name eshopweb --rm -it -p 5106:5106 web
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

COPY *.sln .
COPY . .
WORKDIR /app/src/Web
RUN dotnet restore

RUN dotnet publish -c Release -o out

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/src/Web/out ./

# Vulnerability: Hardcoded secrets in Docker environment variables
# These should never be hardcoded in Dockerfiles
ENV DATABASE_PASSWORD="SuperSecretDBPassword123!"
ENV API_KEY="sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890"
ENV JWT_SECRET="MyJWTSecretKeyForProductionUse2024!"
ENV AZURE_STORAGE_KEY="Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
ENV STRIPE_SECRET_KEY="sk_live_1234567890abcdefghijklmnopqrstuvwxyz1234567890"
ENV SENDGRID_API_KEY="SG.1234567890abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz1234567890"

# Optional: Set this here if not setting it from docker-compose.yml
# ENV ASPNETCORE_ENVIRONMENT Development

ENTRYPOINT ["dotnet", "Web.dll"]
