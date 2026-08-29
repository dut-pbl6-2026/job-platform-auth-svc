FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
# Copy shared first (needs sibling path)
COPY ../job-platform-shared/src/SharedKernel/SharedKernel.csproj ../job-platform-shared/src/SharedKernel/
COPY src/Auth.Core/Auth.Core.csproj src/Auth.Core/
COPY src/Auth.Infrastructure/Auth.Infrastructure.csproj src/Auth.Infrastructure/
COPY src/Auth.Api/Auth.Api.csproj src/Auth.Api/
# Restore with shared present locally (fallback if shared not copied, build will use already copied)
COPY ../job-platform-shared/src/SharedKernel/ ../job-platform-shared/src/SharedKernel/
RUN dotnet restore src/Auth.Api/Auth.Api.csproj
COPY . .
RUN dotnet publish src/Auth.Api/Auth.Api.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 5001
ENV ASPNETCORE_URLS=http://+:5001
ENTRYPOINT ["dotnet", "Auth.Api.dll"]
