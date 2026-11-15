using Auth.Core.Interfaces;

namespace Auth.Tests.Fixtures;

/// <summary>
/// In-memory stand-in for job-svc's company endpoints. It holds verified Companies by domain and the names
/// and tax codes already taken, records every create, and can fail calls on demand.
/// </summary>
public sealed class FakeCompanyDirectory : ICompanyDirectoryClient
{
    public sealed record CreatedCompany(Guid Id, string Name, string? TaxCode, Guid CreatedBy, string EmailDomain);

    private readonly object _gate = new();
    private readonly Dictionary<string, Guid> _verifiedByDomain = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _takenNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _takenTaxCodes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>When true, every call fails as job-svc unavailable.</summary>
    public bool Unavailable { get; set; }

    /// <summary>Fails this many create calls (company or join request) before the next one succeeds.</summary>
    public int UnavailableCreatesRemaining { get; set; }

    /// <summary>Runs inside the availability lookup, before it answers. Lets a test interleave a second request.</summary>
    public Func<Task>? BeforeAvailability { get; set; }

    /// <summary>Runs inside the company create, before its uniqueness check. Lets a test take a name after the lookup.</summary>
    public Func<Task>? BeforeCreate { get; set; }

    public int DomainLookups { get; private set; }
    public int AvailabilityLookups { get; private set; }
    public List<CreatedCompany> CompaniesCreated { get; } = new();
    public List<(Guid UserId, Guid CompanyId)> JoinRequests { get; } = new();

    public void AddVerifiedCompany(string domain, string name)
    {
        lock (_gate)
        {
            _verifiedByDomain[domain] = Guid.NewGuid();
            _takenNames.Add(name);
        }
    }

    public void TakeName(string name)
    {
        lock (_gate) _takenNames.Add(name);
    }

    public void TakeTaxCode(string taxCode)
    {
        lock (_gate) _takenTaxCodes.Add(taxCode);
    }

    public void Reset()
    {
        lock (_gate)
        {
            _verifiedByDomain.Clear();
            _takenNames.Clear();
            _takenTaxCodes.Clear();
            CompaniesCreated.Clear();
            JoinRequests.Clear();
            DomainLookups = 0;
            AvailabilityLookups = 0;
        }
        Unavailable = false;
        UnavailableCreatesRemaining = 0;
        BeforeAvailability = null;
        BeforeCreate = null;
    }

    public Task<Guid?> FindVerifiedCompanyIdAsync(string emailDomain, CancellationToken ct = default)
    {
        ThrowIfUnavailable();
        lock (_gate)
        {
            DomainLookups++;
            return Task.FromResult<Guid?>(_verifiedByDomain.TryGetValue(emailDomain, out var id) ? id : null);
        }
    }

    public async Task<bool> IsAvailableAsync(string companyName, string? taxCode, CancellationToken ct = default)
    {
        ThrowIfUnavailable();
        lock (_gate) AvailabilityLookups++;
        if (BeforeAvailability is { } hook)
            await hook();
        lock (_gate)
        {
            return !_takenNames.Contains(companyName) && (taxCode is null || !_takenTaxCodes.Contains(taxCode));
        }
    }

    public async Task<Guid> CreateCompanyAsync(string companyName, string? taxCode, Guid createdBy, string emailDomain, CancellationToken ct = default)
    {
        ConsumeCreateFailure();
        if (BeforeCreate is { } hook)
            await hook();
        lock (_gate)
        {
            if (_takenNames.Contains(companyName) || (taxCode is not null && _takenTaxCodes.Contains(taxCode)))
                throw new CompanyAlreadyExistsException();
            var id = Guid.NewGuid();
            _takenNames.Add(companyName);
            if (taxCode is not null)
                _takenTaxCodes.Add(taxCode);
            _verifiedByDomain[emailDomain] = id;
            CompaniesCreated.Add(new CreatedCompany(id, companyName, taxCode, createdBy, emailDomain));
            return id;
        }
    }

    public Task CreateJoinRequestAsync(Guid userId, Guid companyId, CancellationToken ct = default)
    {
        ConsumeCreateFailure();
        lock (_gate) JoinRequests.Add((userId, companyId));
        return Task.CompletedTask;
    }

    private void ThrowIfUnavailable()
    {
        if (Unavailable)
            throw new CompanyDirectoryUnavailableException("simulated job-svc outage");
    }

    private void ConsumeCreateFailure()
    {
        ThrowIfUnavailable();
        bool fail;
        lock (_gate)
        {
            fail = UnavailableCreatesRemaining > 0;
            if (fail) UnavailableCreatesRemaining--;
        }
        if (fail)
            throw new CompanyDirectoryUnavailableException("simulated job-svc create failure");
    }
}
