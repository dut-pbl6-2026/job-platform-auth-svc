namespace Auth.Core.Interfaces;

public interface ICompanyValidationClient
{
    Task<bool> ExistsAsync(Guid companyId, CancellationToken ct = default);
}
