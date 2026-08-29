FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/Auth.Core/Auth.Core.csproj src/Auth.Core/
COPY src/Auth.Infrastructure/Auth.Infrastructure.csproj src/Auth.Infrastructure/
COPY src/Auth.Api/Auth.Api.csproj src/Auth.Api/
COPY nuget.config ./
COPY local-feed/ local-feed/
RUN dotnet restore src/Auth.Api/Auth.Api.csproj
COPY . .
RUN dotnet publish src/Auth.Api/Auth.Api.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 5001
ENV ASPNETCORE_URLS=http://+:5001
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
USER app
HEALTHCHECK CMD curl -f http://localhost:5001/health || exit 1
ENTRYPOINT ["dotnet", "Auth.Api.dll"]
