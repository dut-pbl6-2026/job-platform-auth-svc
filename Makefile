.PHONY: build test format ef-check run pack-shared verify

build:
	dotnet build AuthService.sln --warnaserror

test:
	dotnet test AuthService.sln

format:
	dotnet format --verify-no-changes AuthService.sln

ef-check:
	dotnet ef migrations has-pending-model-changes --project src/Auth.Infrastructure --startup-project src/Auth.Api

run:
	dotnet run --project src/Auth.Api

pack-shared:
	dotnet pack ../job-platform-shared/src/SharedKernel/SharedKernel.csproj -c Release -o ../job-platform-shared/artifacts && cp ../job-platform-shared/artifacts/*.nupkg local-feed/

verify: build test
	@echo "verify ok"
